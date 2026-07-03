package main

import (
	"math"
	"testing"
	"time"
)

func TestParseTimeArgRFC3339(t *testing.T) {
	got, err := parseTimeArg("2026-07-01T00:00:00Z")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	if !got.Equal(want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestParseTimeArgNow(t *testing.T) {
	got, err := parseTimeArg("now")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if diff := time.Since(got); diff < 0 || diff > time.Second {
		t.Errorf("parseTimeArg(now) = %v, too far from actual now (diff %v)", got, diff)
	}
}

func TestParseTimeArgTodayIsLocalMidnight(t *testing.T) {
	got, err := parseTimeArg("today")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Hour() != 0 || got.Minute() != 0 || got.Second() != 0 {
		t.Errorf("today = %v, want midnight", got)
	}
	now := time.Now()
	y1, m1, d1 := got.Date()
	y2, m2, d2 := now.Date()
	if y1 != y2 || m1 != m2 || d1 != d2 {
		t.Errorf("today = %v, want same calendar day as %v", got, now)
	}
}

func TestParseTimeArgYesterdayIsOneDayBeforeToday(t *testing.T) {
	today, err := parseTimeArg("today")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	yesterday, err := parseTimeArg("yesterday")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got, want := today.Sub(yesterday), 24*time.Hour; got != want {
		t.Errorf("today - yesterday = %v, want %v", got, want)
	}
}

func TestParseTimeArgDurationAgo(t *testing.T) {
	got, err := parseTimeArg("-15m")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := time.Now().Add(-15 * time.Minute)
	if diff := math.Abs(want.Sub(got).Seconds()); diff > 1 {
		t.Errorf("got %v, want ~%v (diff %.2fs)", got, want, diff)
	}
}

func TestParseTimeArgInvalid(t *testing.T) {
	if _, err := parseTimeArg("last tuesday"); err == nil {
		t.Error("expected an error for an unparseable time argument, got nil")
	}
}
