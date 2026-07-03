package report

import "testing"

func boolPtr(b bool) *bool { return &b }

// TestFilterSecurityRowsExcludesOnlySuccessfulAuthAttempts is a regression
// test: the original event-type list only had user.login, missing this
// cluster's actual access-denied event (auth) and device.authenticate.
func TestFilterSecurityRowsExcludesOnlySuccessfulAuthAttempts(t *testing.T) {
	rows := []EventRow{
		{Type: "user.login", User: "jdoe@example.com", Success: boolPtr(true)},
		{Type: "auth", User: "jdoe@example.com", Success: boolPtr(false)},
		{Type: "device.authenticate", User: "jdoe@example.com", Success: boolPtr(false)},
		{Type: "lock.created", User: "admin@example.com", Raw: []byte(`{"name":"jdoe@example.com"}`)},
	}

	res := filterSecurityRows(rows)

	if len(res.Rows) != 3 {
		t.Fatalf("got %d rows, want 3 (successful user.login should be excluded): %+v", len(res.Rows), res.Rows)
	}
	for _, row := range res.Rows {
		if row[1] == "user.login" {
			t.Errorf("successful user.login should have been filtered out, got row: %v", row)
		}
	}
}

func TestFilterSecurityRowsKeepsEventsWithNoSuccessField(t *testing.T) {
	// lock.created/role.*/user.create/delete have no meaningful
	// success/failure split — any occurrence should be surfaced.
	rows := []EventRow{
		{Type: "role.updated", User: "admin@example.com", Raw: []byte(`{"name":"prod-access"}`)},
	}
	res := filterSecurityRows(rows)
	if len(res.Rows) != 1 {
		t.Fatalf("got %d rows, want 1", len(res.Rows))
	}
	if detail := res.Rows[0][3]; detail != "prod-access" {
		t.Errorf("detail = %v, want prod-access", detail)
	}
}
