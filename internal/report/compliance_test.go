package report

import "testing"

func TestActorOfFallsBackToRawUserName(t *testing.T) {
	if got := actorOf("jdoe@example.com", []byte(`{"user_name":"bot-slack-plugin"}`)); got != "jdoe@example.com" {
		t.Errorf("actorOf with a non-empty user column = %q, want it unchanged", got)
	}
	if got := actorOf("", []byte(`{"user_name":"bot-slack-plugin"}`)); got != "bot-slack-plugin" {
		t.Errorf("actorOf(\"\", ...) = %q, want the raw user_name fallback", got)
	}
	if got := actorOf("", []byte(`{"reviewer":"dlg@goteleport.com"}`)); got != "dlg@goteleport.com" {
		t.Errorf("actorOf(\"\", ...) = %q, want the raw reviewer fallback", got)
	}
	if got := actorOf("", []byte(`{}`)); got != "" {
		t.Errorf("actorOf(\"\", {}) = %q, want empty string when neither is set", got)
	}
}

func TestComplianceDetailTriesFieldsInOrder(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want string
	}{
		{"role name", `{"name":"prod-access","connector":"okta"}`, "prod-access"},
		{"login connector_id", `{"connector_id":"okta-preview"}`, "okta-preview"},
		{"user.update connector", `{"connector":"local"}`, "local"},
		{"cert_type", `{"cert_type":"user"}`, "user"},
		{"bot.join method", `{"method":"kubernetes"}`, "kubernetes"},
		{"falls back to resource", `{"server_hostname":"prod-web-1"}`, "prod-web-1"},
		{"nothing matches", `{"uid":"1"}`, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := complianceDetail([]byte(c.raw)); got != c.want {
				t.Errorf("complianceDetail(%s) = %q, want %q", c.raw, got, c.want)
			}
		})
	}
}
