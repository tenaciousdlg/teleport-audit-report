package report

import (
	"testing"
	"time"
)

func evt(typ, user, raw string, t time.Time) EventRow {
	return EventRow{Type: typ, User: user, Time: t, Raw: []byte(raw)}
}

// TestRequestsUserFilterKeepsFullLifecycle is a regression test for the bug
// where filtering by requester before aggregation could drop a different
// user's review of the same request, making an approved request look stuck
// at PENDING. The fix aggregates first, then filters the final rows.
func TestRequestsUserFilterKeepsFullLifecycle(t *testing.T) {
	created := time.Date(2026, 7, 3, 0, 0, 0, 0, time.UTC)
	reviewed := created.Add(15 * time.Second)

	rows := []EventRow{
		evt("access_request.create", "jdoe@example.com",
			`{"id":"req-1","roles":["prod-access"]}`, created),
		evt("access_request.review", "approver@example.com",
			`{"id":"req-1","reviewer":"approver@example.com","proposed_state":"APPROVED"}`, reviewed),
	}

	order, byID := aggregateRequests(rows)
	res := buildRequestsResult(order, byID, "jdoe@example.com")

	if len(res.Rows) != 1 {
		t.Fatalf("got %d rows, want 1", len(res.Rows))
	}
	row := res.Rows[0]
	// Columns: request_id, user, roles, created, state, reviewers, time_to_decision
	if state := row[4]; state != "APPROVED" {
		t.Errorf("state = %v, want APPROVED (filtering by requester must not lose the reviewer's event)", state)
	}
	if reviewers := row[5]; reviewers != "approver@example.com" {
		t.Errorf("reviewers = %v, want approver@example.com", reviewers)
	}
	if ttd := row[6]; ttd != "15s" {
		t.Errorf("time_to_decision = %v, want 15s", ttd)
	}
}

func TestRequestsUserFilterExcludesOtherRequesters(t *testing.T) {
	created := time.Date(2026, 7, 3, 0, 0, 0, 0, time.UTC)
	rows := []EventRow{
		evt("access_request.create", "alice@example.com", `{"id":"req-alice"}`, created),
		evt("access_request.create", "bob@example.com", `{"id":"req-bob"}`, created),
	}

	order, byID := aggregateRequests(rows)
	res := buildRequestsResult(order, byID, "alice@example.com")

	if len(res.Rows) != 1 {
		t.Fatalf("got %d rows, want 1", len(res.Rows))
	}
	if id := res.Rows[0][0]; id != "req-alice" {
		t.Errorf("request_id = %v, want req-alice", id)
	}
}

func TestRequestsNoUserFilterReturnsAll(t *testing.T) {
	created := time.Date(2026, 7, 3, 0, 0, 0, 0, time.UTC)
	rows := []EventRow{
		evt("access_request.create", "alice@example.com", `{"id":"req-alice"}`, created),
		evt("access_request.create", "bob@example.com", `{"id":"req-bob"}`, created),
	}

	order, byID := aggregateRequests(rows)
	res := buildRequestsResult(order, byID, "")

	if len(res.Rows) != 2 {
		t.Fatalf("got %d rows, want 2", len(res.Rows))
	}
}

func TestRequestsSkipsEventsMissingID(t *testing.T) {
	rows := []EventRow{
		evt("access_request.create", "alice@example.com", `{}`, time.Now()),
	}
	order, byID := aggregateRequests(rows)
	if len(order) != 0 || len(byID) != 0 {
		t.Fatalf("expected events without an id to be skipped, got order=%v byID=%v", order, byID)
	}
}
