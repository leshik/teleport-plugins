package main

import (
	"context"
	"io/ioutil"
	"os"
	"os/user"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/gravitational/teleport-plugins/access/integration"
	"github.com/gravitational/teleport-plugins/lib"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/auth/testauthority"
	"github.com/gravitational/teleport/lib/backend"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/trace"

	. "gopkg.in/check.v1"
)

const (
	Host   = "localhost"
	HostID = "00000000-0000-0000-0000-000000000000"
	Site   = "local-site"

	EscalationPolicyID = "escalation_policy-1"
)

type PagerdutySuite struct {
	ctx           context.Context
	cancel        context.CancelFunc
	appConfig     Config
	app           *App
	userName      string
	raceNumber    int
	me            *user.User
	fakePagerduty *FakePagerduty
	pdService     Service
	pdUser        User
	teleport      *integration.TeleInstance
	tmpFiles      []*os.File
}

var _ = Suite(&PagerdutySuite{})

func TestPagerduty(t *testing.T) { TestingT(t) }

func (s *PagerdutySuite) SetUpSuite(c *C) {
	var err error
	log.SetLevel(log.DebugLevel)
	priv, pub, err := testauthority.New().GenerateKeyPair("")
	c.Assert(err, IsNil)
	t := integration.NewInstance(integration.InstanceConfig{ClusterName: Site, HostID: HostID, NodeName: Host, Priv: priv, Pub: pub})

	s.raceNumber = runtime.GOMAXPROCS(0)
	s.me, err = user.Current()
	c.Assert(err, IsNil)
	userRole, err := types.NewRole("foo", types.RoleSpecV3{
		Allow: types.RoleConditions{
			Logins:  []string{s.me.Username}, // cannot be empty
			Request: &services.AccessRequestConditions{Roles: []string{"admin"}},
		},
	})
	c.Assert(err, IsNil)
	t.AddUserWithRole(s.me.Username, userRole)
	t.AddUserWithRole(s.me.Username+"@example.com", userRole) // For testing auto-approve

	accessPluginRole, err := types.NewRole("access-plugin", types.RoleSpecV3{
		Allow: types.RoleConditions{
			Logins: []string{"access-plugin"}, // cannot be empty
			Rules: []types.Rule{
				types.NewRule("access_request", []string{"list", "read", "update"}),
			},
		},
	})
	c.Assert(err, IsNil)
	t.AddUserWithRole("plugin", accessPluginRole)

	err = t.Create(nil, nil)
	c.Assert(err, IsNil)
	if err := t.Start(); err != nil {
		c.Fatalf("Unexpected response from Start: %v", err)
	}
	s.teleport = t
}

func (s *PagerdutySuite) SetUpTest(c *C) {
	s.ctx, s.cancel = context.WithTimeout(context.Background(), 5*time.Second)
	s.fakePagerduty = NewFakePagerduty(s.raceNumber)
	s.pdService = s.fakePagerduty.StoreService(Service{
		Name: "Test service",
		EscalationPolicy: Reference{
			ID: EscalationPolicyID,
		},
	})
	s.pdUser = s.fakePagerduty.StoreUser(User{
		Name:  "Test User",
		Email: s.me.Username + "@example.com",
	})

	auth := s.teleport.Process.GetAuthServer()
	certAuthorities, err := auth.GetCertAuthorities(services.HostCA, false)
	c.Assert(err, IsNil)
	pluginKey := s.teleport.Secrets.Users["plugin"].Key

	keyFile := s.newTmpFile(c, "auth.*.key")
	_, err = keyFile.Write(pluginKey.Priv)
	c.Assert(err, IsNil)
	keyFile.Close()

	certFile := s.newTmpFile(c, "auth.*.crt")
	_, err = certFile.Write(pluginKey.TLSCert)
	c.Assert(err, IsNil)
	certFile.Close()

	casFile := s.newTmpFile(c, "auth.*.cas")
	for _, ca := range certAuthorities {
		for _, keyPair := range ca.GetTLSKeyPairs() {
			_, err = casFile.Write(keyPair.Cert)
			c.Assert(err, IsNil)
		}
	}
	casFile.Close()

	authAddr, err := s.teleport.Process.AuthSSHAddr()
	c.Assert(err, IsNil)

	var conf Config
	conf.Teleport.AuthServer = authAddr.Addr
	conf.Teleport.ClientCrt = certFile.Name()
	conf.Teleport.ClientKey = keyFile.Name()
	conf.Teleport.RootCAs = casFile.Name()
	conf.Pagerduty.APIEndpoint = s.fakePagerduty.URL()
	conf.Pagerduty.UserEmail = "bot@example.com"
	conf.Pagerduty.ServiceID = s.pdService.ID

	s.appConfig = conf
	s.userName = s.me.Username
}

func (s *PagerdutySuite) TearDownTest(c *C) {
	s.shutdownApp(c)
	s.fakePagerduty.Close()
	s.cancel()
	for _, tmp := range s.tmpFiles {
		err := os.Remove(tmp.Name())
		c.Assert(err, IsNil)
	}
	s.tmpFiles = []*os.File{}
}

func (s *PagerdutySuite) newTmpFile(c *C, pattern string) (file *os.File) {
	file, err := ioutil.TempFile("", pattern)
	c.Assert(err, IsNil)
	s.tmpFiles = append(s.tmpFiles, file)
	return
}

func (s *PagerdutySuite) startApp(c *C) {
	var err error

	s.app, err = NewApp(s.appConfig)
	c.Assert(err, IsNil)

	go func() {
		if err := s.app.Run(s.ctx); err != nil {
			panic(err)
		}
	}()
	ok, err := s.app.WaitReady(s.ctx)
	c.Assert(err, IsNil)
	c.Assert(ok, Equals, true)
}

func (s *PagerdutySuite) shutdownApp(c *C) {
	err := s.app.Shutdown(s.ctx)
	c.Assert(err, IsNil)
	c.Assert(s.app.Err(), IsNil)
}

func (s *PagerdutySuite) newAccessRequest(c *C) services.AccessRequest {
	req, err := services.NewAccessRequest(s.userName, "admin")
	c.Assert(err, IsNil)
	return req
}

func (s *PagerdutySuite) createAccessRequest(c *C) services.AccessRequest {
	req := s.newAccessRequest(c)
	err := s.teleport.CreateAccessRequest(s.ctx, req)
	c.Assert(err, IsNil)
	return req
}

func (s *PagerdutySuite) createExpiredAccessRequest(c *C) services.AccessRequest {
	req := s.newAccessRequest(c)
	err := s.teleport.CreateExpiredAccessRequest(s.ctx, req)
	c.Assert(err, IsNil)
	return req
}

func (s *PagerdutySuite) checkPluginData(c *C, reqID string) PluginData {
	rawData, err := s.teleport.PollAccessRequestPluginData(s.ctx, "pagerduty", reqID)
	c.Assert(err, IsNil)
	return DecodePluginData(rawData)
}

func (s *PagerdutySuite) TestIncidentCreation(c *C) {
	s.startApp(c)
	req := s.createAccessRequest(c)
	pluginData := s.checkPluginData(c, req.GetName())

	incident, err := s.fakePagerduty.CheckNewIncident(s.ctx)
	c.Assert(err, IsNil, Commentf("no new incidents stored"))

	c.Assert(pluginData.ID, Equals, incident.ID)
	c.Assert(incident.IncidentKey, Equals, pdIncidentKeyPrefix+"/"+req.GetName())
}

func (s *PagerdutySuite) TestAutoApprovalWhenOnCall(c *C) {
	s.fakePagerduty.StoreOnCall(OnCall{
		EscalationPolicy: s.pdService.EscalationPolicy,
		User:             Reference{ID: s.pdUser.ID, Type: "user_reference"},
	})

	s.appConfig.Pagerduty.AutoApprove = true
	s.userName = s.pdUser.Email // Current user name matches pagerduty user email
	s.startApp(c)
	watcher, err := s.teleport.Process.GetAuthServer().NewWatcher(s.ctx, services.Watch{
		Kinds: []services.WatchKind{
			{
				Kind: types.KindAccessRequest,
			},
		},
	})
	c.Assert(err, IsNil)
	defer watcher.Close()

	ev := <-watcher.Events()
	c.Assert(ev.Type, Equals, backend.OpInit)

	request := s.createAccessRequest(c)

	ev = <-watcher.Events()
	c.Assert(ev.Type, Equals, backend.OpPut)
	c.Assert(ev.Resource.GetName(), Equals, request.GetName())

	ev = <-watcher.Events()
	c.Assert(ev.Type, Equals, backend.OpPut)
	c.Assert(ev.Resource.GetName(), Equals, request.GetName())
	request, ok := ev.Resource.(services.AccessRequest)
	c.Assert(ok, Equals, true)
	c.Assert(request.GetState(), Equals, types.RequestState_APPROVED)
}

func (s *PagerdutySuite) TestAutoApprovalWhenNotOnCall(c *C) {
	// Store another user in pagerduty and put him on-call
	pdUser2 := s.fakePagerduty.StoreUser(User{
		Name:  "Test User",
		Email: s.me.Username + "2@example.com",
	})
	s.fakePagerduty.StoreOnCall(OnCall{
		EscalationPolicy: s.pdService.EscalationPolicy,
		User:             Reference{ID: pdUser2.ID, Type: "user_reference"},
	})

	s.appConfig.Pagerduty.AutoApprove = true
	s.userName = s.pdUser.Email // Current user name matches pagerduty user email
	s.startApp(c)
	request := s.createAccessRequest(c)
	s.checkPluginData(c, request.GetName())

	time.Sleep(250 * time.Millisecond)
	request, err := s.teleport.GetAccessRequest(s.ctx, request.GetName())
	c.Assert(err, IsNil)
	c.Assert(request.GetState(), Equals, types.RequestState_PENDING) // still pending
}

func (s *PagerdutySuite) TestExpiration(c *C) {
	s.startApp(c)
	s.createExpiredAccessRequest(c)

	incident, err := s.fakePagerduty.CheckNewIncident(s.ctx)
	c.Assert(err, IsNil, Commentf("no new incidents stored"))
	c.Assert(incident.Status, Equals, "triggered")
	incidentID := incident.ID

	incident, err = s.fakePagerduty.CheckIncidentUpdate(s.ctx)
	c.Assert(err, IsNil, Commentf("no incidents updated"))
	c.Assert(incident.ID, Equals, incidentID)
	c.Assert(incident.Status, Equals, "resolved")

	note, err := s.fakePagerduty.CheckNewIncidentNote(s.ctx)
	c.Assert(err, IsNil, Commentf("no new notes stored"))
	c.Assert(note.Content, Equals, "Access request has been expired")
}

func (s *PagerdutySuite) TestRace(c *C) {
	return
	prevLogLevel := log.GetLevel()
	log.SetLevel(log.InfoLevel) // Turn off noisy debug logging
	defer log.SetLevel(prevLogLevel)

	s.cancel() // Cancel the default timeout
	s.ctx, s.cancel = context.WithTimeout(context.Background(), 10*time.Second)
	s.startApp(c)

	var (
		raceErr     error
		raceErrOnce sync.Once
		requests    sync.Map
	)
	setRaceErr := func(err error) error {
		raceErrOnce.Do(func() {
			raceErr = err
		})
		return err
	}

	watcher, err := s.teleport.Process.GetAuthServer().NewWatcher(s.ctx, services.Watch{
		Kinds: []services.WatchKind{
			{
				Kind: types.KindAccessRequest,
			},
		},
	})
	c.Assert(err, IsNil)
	defer watcher.Close()
	c.Assert((<-watcher.Events()).Type, Equals, backend.OpInit)

	process := lib.NewProcess(s.ctx)
	for i := 0; i < s.raceNumber; i++ {
		process.SpawnCritical(func(ctx context.Context) error {
			req, err := services.NewAccessRequest(s.userName, "admin")
			if err != nil {
				return setRaceErr(trace.Wrap(err))
			}
			if err := s.teleport.CreateAccessRequest(ctx, req); err != nil {
				return setRaceErr(trace.Wrap(err))
			}
			return nil
		})
		process.SpawnCritical(func(ctx context.Context) error {
			incident, err := s.fakePagerduty.CheckNewIncident(ctx)
			if err := trace.Wrap(err); err != nil {
				return setRaceErr(err)
			}
			if obtained, expected := incident.Status, "triggered"; obtained != expected {
				return setRaceErr(trace.Errorf("wrong incident status. expected %q, obtained %q", expected, obtained))
			}
			ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
			defer cancel()
			return nil
		})
		process.SpawnCritical(func(ctx context.Context) error {
			incident, err := s.fakePagerduty.CheckIncidentUpdate(ctx)
			if err := trace.Wrap(err); err != nil {
				return setRaceErr(err)
			}
			if obtained, expected := incident.Status, "resolved"; obtained != expected {
				return setRaceErr(trace.Errorf("wrong incident status. expected %q, obtained %q", expected, obtained))
			}
			return nil
		})
	}
	for i := 0; i < 2*s.raceNumber; i++ {
		process.SpawnCritical(func(ctx context.Context) error {
			var event services.Event
			select {
			case event = <-watcher.Events():
			case <-ctx.Done():
				return setRaceErr(trace.Wrap(ctx.Err()))
			}
			if obtained, expected := event.Type, backend.OpPut; obtained != expected {
				return setRaceErr(trace.Errorf("wrong event type. expected %v, obtained %v", expected, obtained))
			}
			req := event.Resource.(services.AccessRequest)
			var newCounter int64
			val, _ := requests.LoadOrStore(req.GetName(), &newCounter)
			switch state := req.GetState(); state {
			case types.RequestState_PENDING:
				atomic.AddInt64(val.(*int64), 1)
			case types.RequestState_APPROVED:
				atomic.AddInt64(val.(*int64), -1)
			default:
				return setRaceErr(trace.Errorf("wrong request state %v", state))
			}
			return nil
		})
	}
	process.Terminate()
	<-process.Done()
	c.Assert(raceErr, IsNil)

	var count int
	requests.Range(func(key, val interface{}) bool {
		count++
		c.Assert(*val.(*int64), Equals, int64(0))
		return true
	})
	c.Assert(count, Equals, s.raceNumber)
}
