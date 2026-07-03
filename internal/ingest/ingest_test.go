package ingest

import (
	"context"
	"encoding/json"
	"testing"
)

// TestActorFallsBackToIdentityUser is a regression test: cert.create and
// other bot-related events nest the actor under identity.user instead of a
// top-level user field, which the ingest logic originally missed entirely.
func TestActorFallsBackToIdentityUser(t *testing.T) {
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
			name: "neither present",
			raw:  `{"uid":"4","event":"bot.join"}`,
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
