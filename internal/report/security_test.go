package report

import "testing"

func boolPtr(b bool) *bool { return &b }

// TestFilterSecurityRowsExcludesOnlySuccessfulAuthAttempts is a regression
// test: the original event-type list only had user.login, missing this
// cluster's actual access-denied event (auth) and device.authenticate.
func TestFilterSecurityRowsExcludesOnlySuccessfulAuthAttempts(t *testing.T) {
	rows := []EventRow{
		{UID: "1", Type: "user.login", User: "jdoe@example.com", Success: boolPtr(true)},
		{UID: "2", Type: "auth", User: "jdoe@example.com", Success: boolPtr(false)},
		{UID: "3", Type: "device.authenticate", User: "jdoe@example.com", Success: boolPtr(false)},
		{UID: "4", Type: "lock.created", User: "admin@example.com", Raw: []byte(`{"name":"jdoe@example.com"}`)},
	}

	// No first-login data at all — the successful user.login (uid "1")
	// must not be mistaken for a first-time login just because nothing is
	// known about it; fail closed and hide it, matching pre-existing
	// behavior for a plain repeat login.
	res := filterSecurityRows(rows, map[string]string{})

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
	res := filterSecurityRows(rows, nil)
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
	res := filterSecurityRows(rows, nil)

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

// TestFilterSecurityRowsExcludesBotNoiseButKeepsHumanSignal is a regression
// test from a live-fire exercise against a real cluster: tbot renews its
// own bot identity via user.update every ~20 minutes, and this tool's own
// Event Handler triggers session.recording.access while exporting a
// recording it just streamed. Both are legitimate noise from a bot doing
// its job, but the same two event types are exactly how a human's role
// grants changing, or a human reviewing someone's session, would show up —
// which must NOT be filtered out.
func TestFilterSecurityRowsExcludesBotNoiseButKeepsHumanSignal(t *testing.T) {
	rows := []EventRow{
		// Real shape captured from tbot's own renewal cycle.
		{Type: "user.update", User: "bot-event-handler", Raw: []byte(`{"user":"bot-event-handler","bot_name":"event-handler","connector":"local"}`)},
		// Real shape captured from this tool's own Event Handler exporting
		// a recording it had just streamed.
		{Type: "session.recording.access", User: "bot-event-handler", Raw: []byte(`{"user":"bot-event-handler","bot_name":"event-handler"}`)},
		// A human's account being updated — e.g. a role grant change —
		// must still show up.
		{Type: "user.update", User: "admin@example.com", Raw: []byte(`{"user":"admin@example.com","connector":"okta"}`)},
		{Type: "session.recording.access", User: "auditor@example.com", Raw: []byte(`{"user":"auditor@example.com"}`)},
	}

	res := filterSecurityRows(rows, nil)

	if len(res.Rows) != 2 {
		t.Fatalf("got %d rows, want 2 (bot-attributed rows filtered, human rows kept): %+v", len(res.Rows), res.Rows)
	}
	for _, row := range res.Rows {
		actor := row[3]
		if actor == "bot-event-handler" {
			t.Errorf("bot-attributed row should have been filtered out, got: %v", row)
		}
	}
}

// TestFilterSecurityRowsShowsFirstSeenSuccessfulLoginOnly is a regression
// test for the scenario that motivated this feature: a brand new identity
// logging in successfully was invisible to `security` (which hides ALL
// successful logins by default), even though a new identity authenticating
// for the first time is itself a meaningful signal. Only the first
// successful login for a given user (identified by matching uid against
// firstLoginUID, not just a repeat) should be shown; later ones from the
// same identity should not.
func TestFilterSecurityRowsShowsFirstSeenSuccessfulLoginOnly(t *testing.T) {
	rows := []EventRow{
		{UID: "first-login-uid", Type: "user.login", User: "new-hire@example.com", Success: boolPtr(true), Raw: []byte(`{"connector_id":"okta-preview"}`)},
		{UID: "second-login-uid", Type: "user.login", User: "new-hire@example.com", Success: boolPtr(true), Raw: []byte(`{"connector_id":"okta-preview"}`)},
	}
	firstLoginUID := map[string]string{"new-hire@example.com": "first-login-uid"}

	res := filterSecurityRows(rows, firstLoginUID)

	if len(res.Rows) != 1 {
		t.Fatalf("got %d rows, want 1 (only the first-ever login should show): %+v", len(res.Rows), res.Rows)
	}
	row := res.Rows[0]
	if severity := row[1]; severity != "HIGH" {
		t.Errorf("severity = %v, want HIGH for a first-seen successful login", severity)
	}
	if detail := row[4]; detail != "okta-preview" {
		t.Errorf("detail = %v, want the connector_id (okta-preview)", detail)
	}
}

func TestIsBotEvent(t *testing.T) {
	// user_kind=2 (USER_KIND_BOT) is the official discriminator, verified
	// present on real bot-attributed user.update/session.recording.access
	// events — checked first.
	if !isBotEvent([]byte(`{"user_kind":2}`)) {
		t.Error("expected isBotEvent to be true when user_kind is 2 (USER_KIND_BOT)")
	}
	// bot_name remains a fallback for event types that don't set user_kind
	// (e.g. SSO user.login, confirmed via Teleport source).
	if !isBotEvent([]byte(`{"bot_name":"event-handler"}`)) {
		t.Error("expected isBotEvent to be true when bot_name is present, even without user_kind")
	}
	if isBotEvent([]byte(`{"user":"admin@example.com"}`)) {
		t.Error("expected isBotEvent to be false when neither field indicates a bot")
	}
	if isBotEvent([]byte(`{"user_kind":1}`)) {
		t.Error("expected isBotEvent to be false for user_kind 1 (USER_KIND_HUMAN)")
	}
}

func TestFilterSecurityRowsIncludesSourceIP(t *testing.T) {
	rows := []EventRow{
		{Type: "auth", User: "jdoe@example.com", Success: boolPtr(false), Raw: []byte(`{"addr.remote":"10.0.28.239:29909"}`)},
		// device.authenticate doesn't carry addr.remote on real events —
		// source should just be blank, not an error.
		{Type: "device.authenticate", User: "jdoe@example.com", Success: boolPtr(false), Raw: []byte(`{}`)},
	}
	res := filterSecurityRows(rows, nil)

	if got, want := res.Columns[5], "source"; got != want {
		t.Fatalf("Columns[5] = %q, want %q", got, want)
	}
	if len(res.Rows) != 2 {
		t.Fatalf("got %d rows, want 2", len(res.Rows))
	}
	if source := res.Rows[0][5]; source != "10.0.28.239:29909" {
		t.Errorf("source = %v, want 10.0.28.239:29909", source)
	}
	if source := res.Rows[1][5]; source != "" {
		t.Errorf("source = %v, want empty string when addr.remote is absent", source)
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
