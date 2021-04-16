package main

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"
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
	minServerVersion = "5.0.0"
	// pluginName is used to tag PluginData and as a Delegator in Audit log.
	pluginName = "jira"
	// backoffMaxDelay is a maximum time GRPC client waits before reconnection attempt.
	backoffMaxDelay = time.Second * 2
	// initTimeout is used to bound execution time of health check and teleport version check.
	initTimeout = time.Second * 10
	// handlerTimeout is used to bound the execution time of watcher event handler.
	handlerTimeout = time.Second * 5
)

var resolveReasonInlineRegex = regexp.MustCompile(`(?im)^ *(resolution|reason) *: *(.+)$`)
var resolveReasonSeparatorRegex = regexp.MustCompile(`(?im)^ *(resolution|reason) *: *$`)

// App contains global application state.
type App struct {
	conf Config

	apiClient  *client.Client
	bot        *Bot
	webhookSrv *WebhookServer
	mainJob    lib.ServiceJob

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
	return trace.Wrap(a.mainJob.Err())
}

// Err returns the error app finished with.
func (a *App) Err() error {
	return trace.Wrap(a.mainJob.Err())
}

// WaitReady waits for http and watcher service to start up.
func (a *App) WaitReady(ctx context.Context) (bool, error) {
	return a.mainJob.WaitReady(ctx)
}

func (a *App) PublicURL() *url.URL {
	if !a.mainJob.IsReady() {
		panic("app is not running")
	}
	return a.webhookSrv.BaseURL()
}

func (a *App) run(ctx context.Context) (err error) {
	log := logger.Get(ctx)
	log.Infof("Starting Teleport Access JIRAbot %s:%s", Version, Gitref)

	if err = a.init(ctx); err != nil {
		return trace.Wrap(err)
	}

	httpJob := a.webhookSrv.ServiceJob()
	a.SpawnCriticalJob(httpJob)
	httpOk, err := httpJob.WaitReady(ctx)
	if err != nil {
		return
	}

	filter := types.AccessRequestFilter{State: types.RequestState_PENDING}
	watcherJob := lib.NewWatcherJob(
		a.apiClient,
		types.Watch{Kinds: []types.WatchKind{
			types.WatchKind{Kind: types.KindAccessRequest, Filter: filter.IntoMap()}},
		},
		a.onWatcherEvent,
	)
	a.SpawnCriticalJob(watcherJob)
	watcherOk, err := watcherJob.WaitReady(ctx)
	if err != nil {
		return
	}

	a.mainJob.SetReady(httpOk && watcherOk)

	<-httpJob.Done()
	<-watcherJob.Done()

	return trace.NewAggregate(httpJob.Err(), watcherJob.Err())
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

	a.bot = NewBot(a.conf.JIRA, pong.ClusterName)
	log.Debug("Starting JIRA API health check...")
	if err = a.bot.HealthCheck(ctx); err != nil {
		return trace.Wrap(err, "api health check failed")
	}
	log.Debug("JIRA API health check finished ok")

	// Create webhook server providing a.OnJIRAWebhook as a callback function
	if a.webhookSrv, err = NewWebhookServer(a.conf.HTTP, a.onJIRAWebhook); err != nil {
		return trace.Wrap(err)
	}
	if err = a.webhookSrv.EnsureCert(); err != nil {
		return trace.Wrap(err)
	}

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
			log.WithError(err).Errorf("Failed to process pending request")
			return trace.Wrap(err)
		}
		return nil
	case types.OpDelete:
		ctx, log := logger.WithField(ctx, "request_op", "delete")

		if err := a.onDeletedRequest(ctx, reqID); err != nil {
			log.WithError(err).Errorf("Failed to process deleted request")
			return trace.Wrap(err)
		}
		return nil
	default:
		return trace.BadParameter("unexpected event operation %s", op)
	}
}

// onJIRAWebhook processes JIRA webhook and updates the status of an issue
func (a *App) onJIRAWebhook(ctx context.Context, webhook Webhook) error {
	log := logger.Get(ctx)

	if webhook.WebhookEvent != "jira:issue_updated" || webhook.IssueEventTypeName != "issue_generic" {
		return nil
	}

	if webhook.Issue == nil {
		return trace.Errorf("got webhook without issue info")
	}

	issue, err := a.bot.GetIssue(ctx, webhook.Issue.ID)
	if err != nil {
		return trace.Wrap(err)
	}

	statusName := strings.ToLower(issue.Fields.Status.Name)
	if statusName == "pending" {
		log.Debug("Issue is pending, ignoring it")
		return nil
	} else if statusName == "expired" {
		log.Debug("Issue is expired, ignoring it")
		return nil
	} else if statusName != "approved" && statusName != "denied" {
		return trace.BadParameter("unknown JIRA status %q", statusName)
	}

	reqID, err := issue.GetRequestID()
	if err != nil {
		return trace.Wrap(err)
	}
	ctx, log = logger.WithField(ctx, "request_id", reqID)

	reqs, err := a.apiClient.GetAccessRequests(ctx, types.AccessRequestFilter{ID: reqID})
	if err != nil {
		return trace.Wrap(err)
	}
	if len(reqs) == 0 {
		log.Warning("Cannot process expired request")
	}
	req := reqs[0]

	if !req.GetState().IsPending() {
		log.WithField("request_state", req.GetState()).Warningf("Cannot process not pending request")
		return nil
	}

	pluginData, err := a.getPluginData(ctx, reqID)
	if err != nil {
		return trace.Wrap(err)
	}

	ctx, log = logger.WithFields(ctx, logger.Fields{
		"jira_issue_id":  issue.ID,
		"jira_issue_key": issue.Key,
	})

	if pluginData.JiraData.ID != issue.ID {
		log.WithField("plugin_data_issue_id", pluginData.JiraData.ID).Debug("plugin_data.issue_id does not match issue.id")
		return trace.Errorf("issue_id from request's plugin_data does not match")
	}

	var (
		resolution string
		delegator  string
	)
	params := types.AccessRequestUpdate{
		RequestID: req.GetName(),
	}

	issueUpdate, err := issue.GetLastUpdate(statusName)
	if err == nil {
		delegator = fmt.Sprintf("%s:%s", pluginName, issueUpdate.Author.EmailAddress)

		accountID := issueUpdate.Author.AccountID
		err := a.bot.RangeIssueCommentsDescending(ctx, issue.ID, func(page PageOfComments) bool {
			for _, comment := range page.Comments {
				if comment.Author.AccountID != accountID {
					continue
				}
				contents := comment.Body
				if submatch := resolveReasonInlineRegex.FindStringSubmatch(contents); len(submatch) > 0 {
					params.Reason = strings.Trim(submatch[2], " \n")
					return false
				} else if locs := resolveReasonSeparatorRegex.FindStringIndex(contents); len(locs) > 0 {
					params.Reason = strings.TrimLeft(contents[locs[1]:], "\n")
					return false
				}
			}
			return true
		})
		if err != nil {
			log.WithError(err).Error("Cannot load issue comments")
		}
	} else {
		log.WithError(err).Error("Cannot determine who updated the issue status")
	}

	ctx, log = logger.WithFields(ctx, logger.Fields{
		"jira_user_email": issueUpdate.Author.EmailAddress,
		"jira_user_name":  issueUpdate.Author.DisplayName,
		"request_user":    req.GetUser(),
		"request_roles":   req.GetRoles(),
		"reason":          params.Reason,
	})

	switch statusName {
	case "approved":
		params.State = types.RequestState_APPROVED
		resolution = "approved"
	case "denied":
		params.State = types.RequestState_DENIED
		resolution = "denied"
	}

	if err := a.apiClient.SetAccessRequestState(client.WithDelegator(ctx, delegator), params); err != nil {
		return trace.Wrap(err)
	}
	log.Infof("JIRA user %s the request", resolution)

	return nil
}

func (a *App) onPendingRequest(ctx context.Context, req types.AccessRequest) error {
	reqData := RequestData{User: req.GetUser(), Roles: req.GetRoles(), RequestReason: req.GetRequestReason(), Created: req.GetCreationTime()}
	jiraData, err := a.bot.CreateIssue(ctx, req.GetName(), reqData)

	if err != nil {
		return trace.Wrap(err)
	}

	logger.Get(ctx).WithFields(logger.Fields{
		"jira_issue_id":  jiraData.ID,
		"jira_issue_key": jiraData.Key,
	}).Info("JIRA Issue created")

	if err := a.setPluginData(ctx, req.GetName(), PluginData{reqData, jiraData}); err != nil {
		if trace.IsNotFound(err) {
			return trace.Wrap(err, "failed to save plugin data, perhaps due to lack of permissions")
		}
		return trace.Wrap(err)
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

	reqData, jiraData := pluginData.RequestData, pluginData.JiraData
	if jiraData.ID == "" {
		log.Warn("Plugin data is either missing or expired")
		return nil
	}

	if err := a.bot.ExpireIssue(ctx, reqID, reqData, jiraData); err != nil {
		return trace.Wrap(err)
	}

	log.Info("Successfully marked request as expired")

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
