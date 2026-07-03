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
		if row[2] == "user.login" {
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
	if detail := res.Rows[0][4]; detail != "prod-access" {
		t.Errorf("detail = %v, want prod-access", detail)
	}
}

func TestFilterSecurityRowsIncludesSeverityColumn(t *testing.T) {
	rows := []EventRow{
		{Type: "auth_preference.update", User: "admin@example.com"},
		{Type: "auth", User: "jdoe@example.com", Success: boolPtr(false)},
		{Type: "totally.unmapped.event", User: "jdoe@example.com"},
	}
	res := filterSecurityRows(rows)

	if got, want := res.Columns[1], "severity"; got != want {
		t.Fatalf("Columns[1] = %q, want %q", got, want)
	}

	want := map[string]string{
		"auth_preference.update": "CRITICAL",
		"auth":                   "LOW",
		"totally.unmapped.event": "INFO", // unmapped types default to INFO, not an error
	}
	for _, row := range res.Rows {
		eventType := row[2].(string)
		if got := row[1]; got != want[eventType] {
			t.Errorf("severity for %s = %v, want %s", eventType, got, want[eventType])
		}
	}
}

func TestSeverityOfKnownAndUnknownTypes(t *testing.T) {
	if got := severityOf("cert_auth_override.delete"); got != "CRITICAL" {
		t.Errorf("severityOf(cert_auth_override.delete) = %q, want CRITICAL", got)
	}
	if got := severityOf("role.created"); got != "HIGH" {
		t.Errorf("severityOf(role.created) = %q, want HIGH", got)
	}
	if got := severityOf("nonexistent.event.type"); got != "INFO" {
		t.Errorf("severityOf(nonexistent.event.type) = %q, want INFO (safe default)", got)
	}
}
