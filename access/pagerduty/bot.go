package main

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"text/template"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/google/go-querystring/query"

	"github.com/gravitational/teleport-plugins/lib"
	"github.com/gravitational/teleport-plugins/lib/logger"
	"github.com/gravitational/trace"
)

const (
	pdMaxConns    = 100
	pdHTTPTimeout = 10 * time.Second
	pdListLimit   = uint(100)

	pdIncidentKeyPrefix  = "teleport-access-request"
	pdApproveAction      = "approve"
	pdApproveActionLabel = "Approve Request"
	pdDenyAction         = "deny"
	pdDenyActionLabel    = "Deny Request"
)

var incidentBodyTemplate *template.Template

func init() {
	var err error
	incidentBodyTemplate, err = template.New("description").Parse(
		`{{.User}} requested permissions for roles {{range $index, $element := .Roles}}{{if $index}}, {{end}}{{ . }}{{end}} on Teleport at {{.Created.Format .TimeFormat}}. To approve or deny the request, please use Special Actions on this incident.
`,
	)
	if err != nil {
		panic(err)
	}
}

// Bot is a wrapper around resty.Client.
type Bot struct {
	client    *resty.Client
	from      string
	serviceID string

	clusterName string
	webProxyURL *url.URL
}

func NewBot(conf PagerdutyConfig, clusterName, webProxyAddr string) (Bot, error) {
	var webProxyURL *url.URL
	if webProxyAddr != "" {
		var err error
		if !strings.HasPrefix(webProxyAddr, "http://") && !strings.HasPrefix(webProxyAddr, "https://") {
			webProxyAddr = "https://" + webProxyAddr
		}
		if webProxyURL, err = url.Parse(webProxyAddr); err != nil {
			return Bot{}, trace.Wrap(err)
		}
		if webProxyURL.Scheme == "https" && webProxyURL.Port() == "443" {
			// Cut off redundant :443
			webProxyURL.Host = webProxyURL.Hostname()
		}
	}

	client := resty.NewWithClient(&http.Client{
		Timeout: pdHTTPTimeout,
		Transport: &http.Transport{
			MaxConnsPerHost:     pdMaxConns,
			MaxIdleConnsPerHost: pdMaxConns,
		},
	})
	// APIEndpoint parameter is set only in tests
	if conf.APIEndpoint != "" {
		client.SetHostURL(conf.APIEndpoint)
	} else {
		client.SetHostURL("https://api.pagerduty.com")
	}
	client.SetHeader("Accept", "application/vnd.pagerduty+json;version=2")
	client.SetHeader("Content-Type", "application/json")
	client.SetHeader("Authorization", "Token token="+conf.APIKey)
	client.OnBeforeRequest(func(_ *resty.Client, req *resty.Request) error {
		req.SetError(&ErrorResult{})
		return nil
	})
	client.OnAfterResponse(func(_ *resty.Client, resp *resty.Response) error {
		if resp.IsError() {
			result := resp.Error()
			if result, ok := result.(*ErrorResult); ok {
				return trace.Errorf("http error code=%v, err_code=%v, message=%v, errors=[%v]", resp.StatusCode(), result.Code, result.Message, strings.Join(result.Errors, ", "))
			}
			return trace.Errorf("unknown error result %#v", result)
		}
		return nil
	})
	return Bot{
		client:      client,
		clusterName: clusterName,
		webProxyURL: webProxyURL,
		from:        conf.UserEmail,
		serviceID:   conf.ServiceID,
	}, nil
}

func (b *Bot) HealthCheck(ctx context.Context) error {
	var result ServiceResult
	resp, err := b.client.NewRequest().
		SetContext(ctx).
		SetResult(&result).
		Get(lib.BuildURLPath("services", b.serviceID))
	// We have to check `resp.IsError()` before the `err != nil` check because we set `err` in OnAfterResponse middleware.
	if resp != nil && resp.IsError() {
		// Check Content-Type first to ensure that this is actually looks like an API endpoint.
		if contentType := resp.Header().Get("Content-Type"); contentType != "application/json" {
			return trace.Errorf("wrong Content-Type in PagerDuty response: %q", contentType)
		}
		// Check for 401 http code. Other codes > 399 result in non-nil `err` and will be checked afterwards.
		if code := resp.StatusCode(); code == http.StatusUnauthorized {
			return trace.Errorf("got %v from API endpoint, perhaps PagerDuty credentials are not configured well", code)
		}
	}
	if err != nil {
		return trace.Wrap(err, "failed to fetch PagerDuty service info: %v", err)
	}
	if result.Service.ID != b.serviceID {
		logger.Get(ctx).Debugf("Got wrong response from services API: %s", resp)
		return trace.Errorf("got wrong response from services API")
	}

	return nil
}

func (b Bot) CreateIncident(ctx context.Context, reqID string, reqData RequestData) (PagerdutyData, error) {
	bodyDetails, err := b.buildIncidentBody(reqID, reqData)
	if err != nil {
		return PagerdutyData{}, trace.Wrap(err)
	}
	body := IncidentBody{
		Title:       fmt.Sprintf("Access request from %s", reqData.User),
		IncidentKey: fmt.Sprintf("%s/%s", pdIncidentKeyPrefix, reqID),
		Service: Reference{
			Type: "service_reference",
			ID:   b.serviceID,
		},
		Body: Details{
			Type:    "incident_body",
			Details: bodyDetails,
		},
	}
	var result IncidentResult

	_, err = b.client.NewRequest().
		SetContext(ctx).
		SetHeader("From", b.from).
		SetBody(&IncidentBodyWrap{body}).
		SetResult(&result).
		Post("incidents")
	if err != nil {
		return PagerdutyData{}, trace.Wrap(err)
	}

	return PagerdutyData{
		ID: result.Incident.ID,
	}, nil
}

func (b Bot) ResolveIncident(ctx context.Context, reqID, incidentID, resolution string) error {
	noteBody := IncidentNoteBody{
		Content: fmt.Sprintf("Access request has been %s", resolution),
	}
	_, err := b.client.NewRequest().
		SetContext(ctx).
		SetHeader("From", b.from).
		SetBody(&IncidentNoteBodyWrap{noteBody}).
		Post(lib.BuildURLPath("incidents", incidentID, "notes"))
	if err != nil {
		return trace.Wrap(err)
	}

	incidentBody := IncidentBody{
		Type:   "incident_reference",
		Status: "resolved",
	}
	_, err = b.client.NewRequest().
		SetContext(ctx).
		SetHeader("From", b.from).
		SetBody(&IncidentBodyWrap{incidentBody}).
		Put(lib.BuildURLPath("incidents", incidentID))
	if err != nil {
		return trace.Wrap(err)
	}

	return nil
}

func (b Bot) GetUserInfo(ctx context.Context, userID string) (User, error) {
	var result UserResult

	_, err := b.client.NewRequest().
		SetContext(ctx).
		SetResult(&result).
		Get(lib.BuildURLPath("users", userID))
	if err != nil {
		return User{}, trace.Wrap(err)
	}

	return result.User, nil
}

func (b Bot) GetUserByEmail(ctx context.Context, userEmail string) (User, error) {
	usersQuery, err := query.Values(ListUsersQuery{
		Query: userEmail,
		PaginationQuery: PaginationQuery{
			Limit: pdListLimit,
		},
	})
	if err != nil {
		return User{}, trace.Wrap(err)
	}

	var result ListUsersResult
	_, err = b.client.NewRequest().
		SetContext(ctx).
		SetQueryParamsFromValues(usersQuery).
		SetResult(&result).
		Get("users")
	if err != nil {
		return User{}, trace.Wrap(err)
	}

	for _, user := range result.Users {
		if user.Email == userEmail {
			return user, nil
		}
	}

	if len(result.Users) > 0 && result.More {
		logger.Get(ctx).Warningf("PagerDuty returned too many results when querying by email %q", userEmail)
	}

	return User{}, trace.NotFound("failed to find pagerduty user by email %q", userEmail)
}

func (b *Bot) IsUserOnCall(ctx context.Context, userID string) (bool, error) {
	var result ServiceResult
	_, err := b.client.NewRequest().
		SetContext(ctx).
		SetResult(&result).
		Get(lib.BuildURLPath("services", b.serviceID))
	if err != nil {
		return false, trace.Wrap(err)
	}
	escalationPolicyID := result.Service.EscalationPolicy.ID

	onCallsQuery, err := query.Values(ListOnCallsQuery{
		UserIDs:             []string{userID},
		EscalationPolicyIDs: []string{escalationPolicyID},
	})
	if err != nil {
		return false, trace.Wrap(err)
	}

	var onCallsResult ListOnCallsResult

	_, err = b.client.NewRequest().
		SetContext(ctx).
		SetQueryParamsFromValues(onCallsQuery).
		SetResult(&onCallsResult).
		Get("oncalls")
	if err != nil {
		return false, trace.Wrap(err)
	}

	for _, onCall := range onCallsResult.OnCalls {
		if onCall.EscalationPolicy.ID == escalationPolicyID && onCall.User.ID == userID {
			return true, nil
		}
	}

	if len(onCallsResult.OnCalls) > 0 {
		logger.Get(ctx).WithFields(logger.Fields{
			"pd_user_id":              userID,
			"pd_escalation_policy_id": escalationPolicyID,
		}).Warningf("PagerDuty returned some oncalls array but none of them matched the query")
	}

	return false, nil
}

func (b *Bot) buildIncidentBody(reqID string, reqData RequestData) (string, error) {
	var builder strings.Builder
	err := incidentBodyTemplate.Execute(&builder, struct {
		ID         string
		TimeFormat string
		RequestData
	}{
		reqID,
		time.RFC822,
		reqData,
	})
	if err != nil {
		return "", trace.Wrap(err)
	}
	return builder.String(), nil
}
