package main

import (
	"context"
	"time"

	"github.com/gravitational/teleport-plugins/lib"
	"github.com/gravitational/teleport-plugins/lib/logger"
	"github.com/gravitational/teleport/api/client"
	"github.com/gravitational/teleport/api/client/proto"
	"github.com/gravitational/teleport/api/types"
	"google.golang.org/grpc"
	"google.golang.org/grpc/backoff"

	"github.com/gravitational/trace"
)

const (
	// minServerVersion is the minimal teleport version the plugin supports.
	minServerVersion = "6.1.0-beta.1"
	// pluginName is used to tag PluginData and as a Delegator in Audit log.
	pluginName = "pagerduty"
	// backoffMaxDelay is a maximum time GRPC client waits before reconnection attempt.
	backoffMaxDelay = time.Second * 2
	// initTimeout is used to bound execution time of health check and teleport version check.
	initTimeout = time.Second * 10
	// handlerTimeout is used to bound the execution time of watcher event handler.
	handlerTimeout = time.Second * 5
)

// App contains global application state.
type App struct {
	conf Config

	apiClient *client.Client
	bot       Bot
	mainJob   lib.ServiceJob

	*lib.Process
}

func NewApp(conf Config) (*App, error) {
	app := &App{conf: conf}
	app.mainJob = lib.NewServiceJob(app.run)
	return app, nil
}

// Run initializes and runs a watcher and a callback server
func (a *App) Run(ctx context.Context) error {
	// Initialize the process.
	a.Process = lib.NewProcess(ctx)
	a.SpawnCriticalJob(a.mainJob)
	<-a.Process.Done()
	return a.Err()
}

// Err returns the error app finished with.
func (a *App) Err() error {
	return trace.Wrap(a.mainJob.Err())
}

// WaitReady waits for http and watcher service to start up.
func (a *App) WaitReady(ctx context.Context) (bool, error) {
	return a.mainJob.WaitReady(ctx)
}

func (a *App) run(ctx context.Context) error {
	var err error

	log := logger.Get(ctx)
	log.Infof("Starting Teleport Access PagerDuty Plugin %s:%s", Version, Gitref)

	if err = a.init(ctx); err != nil {
		return trace.Wrap(err)
	}

	watcherJob := lib.NewWatcherJob(
		a.apiClient,
		types.Watch{Kinds: []types.WatchKind{types.WatchKind{Kind: types.KindAccessRequest}}},
		a.onWatcherEvent,
	)
	a.SpawnCriticalJob(watcherJob)
	watcherOk, err := watcherJob.WaitReady(ctx)
	if err != nil {
		return trace.Wrap(err)
	}

	a.mainJob.SetReady(watcherOk)

	<-watcherJob.Done()

	return trace.Wrap(watcherJob.Err())
}

func (a *App) init(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, initTimeout)
	defer cancel()
	log := logger.Get(ctx)

	var (
		err  error
		pong proto.PingResponse
	)

	bk := backoff.DefaultConfig
	bk.MaxDelay = backoffMaxDelay
	if a.apiClient, err = client.New(ctx, client.Config{
		Addrs:       []string{a.conf.Teleport.AuthServer},
		Credentials: a.conf.Teleport.Credentials(),
		DialOpts:    []grpc.DialOption{grpc.WithConnectParams(grpc.ConnectParams{Backoff: bk, MinConnectTimeout: initTimeout})},
	}); err != nil {
		return trace.Wrap(err)
	}

	if pong, err = a.checkTeleportVersion(ctx); err != nil {
		return trace.Wrap(err)
	}

	var webProxyAddr string
	if pong.ServerFeatures.AdvancedAccessWorkflows {
		webProxyAddr = pong.ProxyPublicAddr
	}
	a.bot, err = NewBot(a.conf.Pagerduty, pong.ClusterName, webProxyAddr)
	if err != nil {
		return trace.Wrap(err)
	}

	log.Debug("Starting PagerDuty API health check...")
	if err = a.bot.HealthCheck(ctx); err != nil {
		return trace.Wrap(err, "api health check failed. check your credentials and service_id settings")
	}
	log.Debug("PagerDuty API health check finished ok")

	return nil
}

func (a *App) checkTeleportVersion(ctx context.Context) (proto.PingResponse, error) {
	log := logger.Get(ctx)
	log.Debug("Checking Teleport server version")
	pong, err := a.apiClient.WithCallOptions(grpc.WaitForReady(true)).Ping(ctx)
	if err != nil {
		if trace.IsNotImplemented(err) {
			return pong, trace.Wrap(err, "server version must be at least %s", minServerVersion)
		}
		log.Error("Unable to get Teleport server version")
		return pong, trace.Wrap(err)
	}
	err = lib.AssertServerVersion(pong, minServerVersion)
	return pong, trace.Wrap(err)
}

func (a *App) onWatcherEvent(ctx context.Context, event types.Event) error {
	ctx, cancel := context.WithTimeout(ctx, handlerTimeout)
	defer cancel()

	if kind := event.Resource.GetKind(); kind != types.KindAccessRequest {
		return trace.Errorf("unexpected kind %q", kind)
	}
	op := event.Type
	reqID := event.Resource.GetName()
	ctx, _ = logger.WithField(ctx, "request_id", reqID)

	switch op {
	case types.OpPut:
		ctx, log := logger.WithField(ctx, "request_op", "put")
		req, ok := event.Resource.(types.AccessRequest)
		if !ok {
			return trace.Errorf("unexpected resource type %T", event.Resource)
		}

		if !req.GetState().IsPending() {
			log.WithField("event", event).Warn("non-pending request event")
			return nil
		}

		if err := a.onPendingRequest(ctx, req); err != nil {
			log := log.WithError(err)
			log.Errorf("Failed to process pending request")
			log.Debugf("%v", trace.DebugReport(err))
			return err
		}
		return nil
	case types.OpDelete:
		ctx, log := logger.WithField(ctx, "request_op", "delete")

		if err := a.onDeletedRequest(ctx, reqID); err != nil {
			log := log.WithError(err)
			log.Errorf("Failed to process deleted request")
			log.Debugf("%v", trace.DebugReport(err))
			return err
		}
		return nil
	default:
		return trace.BadParameter("unexpected event operation %s", op)
	}
}

func (a *App) onPendingRequest(ctx context.Context, req types.AccessRequest) error {
	reqID := req.GetName()
	reqData := RequestData{User: req.GetUser(), Roles: req.GetRoles(), Created: req.GetCreationTime()}

	pdData, err := a.bot.CreateIncident(ctx, reqID, reqData)
	if err != nil {
		return trace.Wrap(err)
	}

	ctx, log := logger.WithField(ctx, "pd_incident_id", pdData.ID)

	log.Info("PagerDuty incident created")

	err = a.setPluginData(ctx, reqID, PluginData{reqData, pdData})
	if err != nil {
		return trace.Wrap(err)
	}

	if a.conf.Pagerduty.AutoApprove {
		return a.tryAutoApproveRequest(ctx, req, pdData.ID)
	}

	return nil
}

func (a *App) onDeletedRequest(ctx context.Context, reqID string) error {
	log := logger.Get(ctx)

	pluginData, err := a.getPluginData(ctx, reqID)
	if err != nil {
		if trace.IsNotFound(err) {
			log.WithError(err).Warn("Cannot expire unknown request")
			return nil
		}
		return trace.Wrap(err)
	}

	incidentID := pluginData.PagerdutyData.ID
	if incidentID == "" {
		log.Warn("Plugin data is either missing or expired")
		return nil
	}

	if err := a.bot.ResolveIncident(ctx, reqID, incidentID, "expired"); err != nil {
		return trace.Wrap(err)
	}

	log.Info("Successfully marked request as expired")

	return nil
}

func (a *App) setRequestState(ctx context.Context, reqID, incidentID, userEmail string, state types.RequestState) error {
	log := logger.Get(ctx)
	var resolution string

	switch state {
	case types.RequestState_APPROVED:
		resolution = "approved"
	case types.RequestState_DENIED:
		resolution = "denied"
	default:
		return trace.Errorf("unable to set state to %v", state)
	}

	if err := a.apiClient.SetAccessRequestState(ctx, types.AccessRequestUpdate{
		RequestID: reqID,
		State:     state,
	}); err != nil {
		return trace.Wrap(err)
	}
	log.Infof("PagerDuty user %s the request", resolution)

	if err := a.bot.ResolveIncident(ctx, reqID, incidentID, resolution); err != nil {
		return trace.Wrap(err)
	}
	log.Infof("Incident %q has been resolved", incidentID)

	return nil
}

func (a *App) tryAutoApproveRequest(ctx context.Context, req types.AccessRequest, incidentID string) error {
	log := logger.Get(ctx)

	userName := req.GetUser()

	if !lib.IsEmail(userName) {
		logger.Get(ctx).Warningf("Failed to auto-approve the request: %q does not look like a valid email", userName)
		return nil
	}

	user, err := a.bot.GetUserByEmail(ctx, userName)
	if err != nil {
		if trace.IsNotFound(err) {
			log.WithError(err).Debugf("Failed to auto-approve the request")
			return nil
		}
		return err
	}

	ctx, log = logger.WithFields(ctx, logger.Fields{
		"pd_user_email": user.Email,
		"pd_user_name":  user.Name,
	})

	isOnCall, err := a.bot.IsUserOnCall(ctx, user.ID)
	if err != nil {
		return trace.Wrap(err)
	}
	if isOnCall {
		log.Infof("User is now on-call, auto-approving the request")
		return a.setRequestState(ctx, req.GetName(), incidentID, user.Email, types.RequestState_APPROVED)
	}

	log.Debug("User is not on call")
	return nil
}

func (a *App) getPluginData(ctx context.Context, reqID string) (PluginData, error) {
	data, err := a.apiClient.GetPluginData(ctx, types.PluginDataFilter{
		Kind:     types.KindAccessRequest,
		Resource: reqID,
		Plugin:   pluginName,
	})
	if err != nil {
		return PluginData{}, trace.Wrap(err)
	}
	if len(data) == 0 {
		return PluginData{}, nil
	}
	entry := data[0].Entries()[pluginName]
	if entry == nil {
		return PluginData{}, nil
	}
	return DecodePluginData(entry.Data), nil
}

func (a *App) setPluginData(ctx context.Context, reqID string, data PluginData) error {
	return a.apiClient.UpdatePluginData(ctx, types.PluginDataUpdateParams{
		Kind:     types.KindAccessRequest,
		Resource: reqID,
		Plugin:   pluginName,
		Set:      EncodePluginData(data),
	})
}
