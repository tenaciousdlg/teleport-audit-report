package report

import "testing"

func TestResourceOfPicksTheOnePopulatedField(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want string
	}{
		{"ssh", `{"server_hostname":"prod-web-1"}`, "prod-web-1"},
		{"database", `{"db_service":"postgres-prod"}`, "postgres-prod"},
		{"app_or_mcp", `{"app_name":"awsconsole-a"}`, "awsconsole-a"},
		{"kube", `{"kubernetes_cluster":"eks-prod"}`, "eks-prod"},
		{"windows_desktop", `{"desktop_name":"WIN-DESKTOP-1"}`, "WIN-DESKTOP-1"},
		{"none", `{"session_id":"abc"}`, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := resourceOf([]byte(c.raw)); got != c.want {
				t.Errorf("resourceOf(%s) = %q, want %q", c.raw, got, c.want)
			}
		})
	}
}

func TestActivityIncludesResourceColumn(t *testing.T) {
	rows := []EventRow{
		{Type: "session.start", User: "jdoe@example.com", SessionID: "sess-1", Raw: []byte(`{"server_hostname":"prod-web-1"}`)},
	}
	res := activityResult(rows)

	idx := -1
	for i, c := range res.Columns {
		if c == "resource" {
			idx = i
		}
	}
	if idx == -1 {
		t.Fatalf("Columns = %v, want a resource column", res.Columns)
	}
	if got := res.Rows[0][idx]; got != "prod-web-1" {
		t.Errorf("resource = %v, want prod-web-1", got)
	}
}
