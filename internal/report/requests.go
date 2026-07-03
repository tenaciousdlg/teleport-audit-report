package report

import (
	"context"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/tenaciousdlg/teleport-audit-report/internal/format"
)

// requestEventTypes are the access_request.* lifecycle events, verified
// against gravitational/teleport's lib/events/api.go:206-214 and
// https://goteleport.com/docs/reference/audit-events/ (create/update/review
// documented there; expire/delete confirmed as real constants in source but
// not independently found in the docs page). access_request.search is
// deliberately excluded — it's emitted for resource-search UI queries, not
// a lifecycle transition, and would just be noise here.
var requestEventTypes = []string{
	"access_request.create",
	"access_request.review",
	"access_request.update",
	"access_request.expire",
	"access_request.delete",
}

type requestAgg struct {
	user      string
	roles     string
	reason    string
	created   time.Time
	state     string
	reviewers []string
	decided   *time.Time
}

// Requests reconstructs each access request's lifecycle (create -> review(s)
// -> final state) by grouping the underlying access_request.* events by
// their request ID, since Teleport logs each transition as a separate event
// rather than one row per request.
//
// f.User is applied after aggregation, not to the underlying query: a
// request's create and review events are logged under different users (the
// requester vs. each reviewer), so filtering the raw events by one user
// would silently drop another user's review of the same request — making
// an actually-approved request look stuck at PENDING.
func Requests(ctx context.Context, pool *pgxpool.Pool, f Filter) (format.Result, error) {
	requester := f.User
	f.User = ""
	f.Types = requestEventTypes
	rows, err := queryEvents(ctx, pool, f)
	if err != nil {
		return format.Result{}, err
	}

	order, byID := aggregateRequests(rows)
	return buildRequestsResult(order, byID, requester), nil
}

// aggregateRequests groups access_request.* events by request ID and folds
// each group's events into a single lifecycle summary. Split out from
// Requests so it can be tested with synthetic EventRows, no database needed.
func aggregateRequests(rows []EventRow) ([]string, map[string]*requestAgg) {
	order := []string{}
	byID := map[string]*requestAgg{}
	for _, e := range rows {
		id := rawField(e.Raw, "id")
		if id == "" {
			continue
		}
		agg, ok := byID[id]
		if !ok {
			agg = &requestAgg{state: "PENDING"}
			byID[id] = agg
			order = append(order, id)
		}

		switch e.Type {
		case "access_request.create":
			agg.user = e.User
			agg.roles = rawField(e.Raw, "roles")
			agg.reason = rawField(e.Raw, "reason")
			agg.created = e.Time
			if s := rawField(e.Raw, "state"); s != "" {
				agg.state = s
			}
		case "access_request.review":
			if reviewer := rawField(e.Raw, "reviewer"); reviewer != "" {
				agg.reviewers = append(agg.reviewers, reviewer)
			}
			if s := rawField(e.Raw, "proposed_state"); s != "" && s != "PENDING" {
				agg.state = s
				if agg.decided == nil {
					t := e.Time
					agg.decided = &t
				}
			}
		case "access_request.update":
			if s := rawField(e.Raw, "state"); s != "" {
				agg.state = s
				if s != "PENDING" && agg.decided == nil {
					t := e.Time
					agg.decided = &t
				}
			}
		case "access_request.expire":
			agg.state = "EXPIRED"
			if agg.decided == nil {
				t := e.Time
				agg.decided = &t
			}
		case "access_request.delete":
			agg.state = "DELETED"
		}
	}
	return order, byID
}

// buildRequestsResult filters the aggregated requests by requester (if set)
// and renders them into the report's tabular shape.
func buildRequestsResult(order []string, byID map[string]*requestAgg, requester string) format.Result {
	res := format.Result{Columns: []string{"request_id", "user", "roles", "reason", "created", "state", "reviewers", "time_to_decision"}}
	for _, id := range order {
		agg := byID[id]
		if requester != "" && agg.user != requester {
			continue
		}
		ttd := ""
		if agg.decided != nil && !agg.created.IsZero() {
			ttd = agg.decided.Sub(agg.created).String()
		}
		res.Rows = append(res.Rows, []any{id, agg.user, agg.roles, agg.reason, agg.created, agg.state, strings.Join(agg.reviewers, ","), ttd})
	}
	return res
}
