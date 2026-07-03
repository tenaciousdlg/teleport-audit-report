package report

import (
	"context"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/tenaciousdlg/teleport-audit-report/internal/format"
)

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
	created   time.Time
	state     string
	reviewers []string
	decided   *time.Time
}

// Requests reconstructs each access request's lifecycle (create -> review(s)
// -> final state) by grouping the underlying access_request.* events by
// their request ID, since Teleport logs each transition as a separate event
// rather than one row per request.
func Requests(ctx context.Context, pool *pgxpool.Pool, f Filter) (format.Result, error) {
	f.Types = requestEventTypes
	rows, err := queryEvents(ctx, pool, f)
	if err != nil {
		return format.Result{}, err
	}

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

	res := format.Result{Columns: []string{"request_id", "user", "roles", "created", "state", "reviewers", "time_to_decision"}}
	for _, id := range order {
		agg := byID[id]
		ttd := ""
		if agg.decided != nil && !agg.created.IsZero() {
			ttd = agg.decided.Sub(agg.created).String()
		}
		res.Rows = append(res.Rows, []any{id, agg.user, agg.roles, agg.created, agg.state, strings.Join(agg.reviewers, ","), ttd})
	}
	return res, nil
}
