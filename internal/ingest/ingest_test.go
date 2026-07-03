package ingest

import (
	"context"
	"encoding/json"
	"testing"
)

// TestActorFallbackChain is a regression test covering three real gaps
// found in production, each where Teleport puts the acting identity under a
// different field than the last: cert.create-shaped events nest it under
// identity.user; bot.join uses a top-level user_name instead, which
// originally caused every bot.join row to show a blank actor (including in
// the database column itself, breaking --user=<bot> filtering, not just
// display); access_request.review has none of those and instead carries
// the reviewer's identity under reviewer.
func TestActorFallbackChain(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want string
	}{
		{
			name: "top-level user field",
			raw:  `{"uid":"1","event":"user.login","user":"jdoe@example.com"}`,
			want: "jdoe@example.com",
		},
		{
			name: "falls back to identity.user when user is absent",
			raw:  `{"uid":"2","event":"cert.create","identity":{"user":"bot-event-handler"}}`,
			want: "bot-event-handler",
		},
		{
			name: "top-level user takes priority over identity.user if both present",
			raw:  `{"uid":"3","event":"weird","user":"top-level","identity":{"user":"nested"}}`,
			want: "top-level",
		},
		{
			name: "falls back to user_name for bot.join, which has neither user nor identity.user",
			raw:  `{"uid":"4","event":"bot.join","user_name":"bot-slack-plugin"}`,
			want: "bot-slack-plugin",
		},
		{
			name: "falls back to reviewer for access_request.review, which has none of the above",
			raw:  `{"uid":"5","event":"access_request.review","reviewer":"dlg@goteleport.com"}`,
			want: "dlg@goteleport.com",
		},
		{
			name: "none present",
			raw:  `{"uid":"6","event":"access_request.expire"}`,
			want: "",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var e event
			if err := json.Unmarshal([]byte(c.raw), &e); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if got := e.actor(); got != c.want {
				t.Errorf("actor() = %q, want %q", got, c.want)
			}
		})
	}
}

func TestUpsertRejectsEventsMissingUID(t *testing.T) {
	// No pool needed: Upsert must reject a missing uid before ever touching
	// the database.
	s := NewStore(nil)
	err := s.Upsert(context.Background(), []byte(`{"event":"user.login"}`))
	if err == nil {
		t.Fatal("expected an error for an event with no uid, got nil")
	}
}

func TestUpsertRejectsInvalidJSON(t *testing.T) {
	s := NewStore(nil)
	err := s.Upsert(context.Background(), []byte(`not json`))
	if err == nil {
		t.Fatal("expected an error for invalid JSON, got nil")
	}
}
