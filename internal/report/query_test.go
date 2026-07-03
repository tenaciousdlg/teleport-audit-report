package report

import "testing"

func TestRawField(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		key  string
		want string
	}{
		{"top-level string", `{"reviewer":"alice"}`, "reviewer", "alice"},
		{"missing key", `{"reviewer":"alice"}`, "id", ""},
		{"null value", `{"id":null}`, "id", ""},
		{"non-string value gets marshaled", `{"roles":["a","b"]}`, "roles", `["a","b"]`},
		{"invalid json", `not json`, "id", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := rawField([]byte(c.raw), c.key)
			if got != c.want {
				t.Errorf("rawField(%q, %q) = %q, want %q", c.raw, c.key, got, c.want)
			}
		})
	}
}

func TestRawDuration(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want string
	}{
		{"numeric duration field (nanoseconds)", `{"duration":5000000000}`, "5s"},
		{
			"session_start/session_stop gap",
			`{"session_start":"2026-07-03T00:00:00Z","session_stop":"2026-07-03T00:01:30Z"}`,
			"1m30s",
		},
		{"neither field present", `{"event":"session.start"}`, ""},
		{"only session_start present", `{"session_start":"2026-07-03T00:00:00Z"}`, ""},
		{"unparseable timestamps", `{"session_start":"not-a-time","session_stop":"also-not"}`, ""},
		{"invalid json", `not json`, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := rawDuration([]byte(c.raw))
			if got != c.want {
				t.Errorf("rawDuration(%q) = %q, want %q", c.raw, got, c.want)
			}
		})
	}
}
