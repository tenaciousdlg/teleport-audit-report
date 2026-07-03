package format

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func sampleResult() Result {
	return Result{
		Columns: []string{"time", "user", "raw"},
		Rows: [][]any{
			{
				time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC),
				"jdoe@example.com",
				json.RawMessage(`{"event":"user.login"}`),
			},
		},
	}
}

func TestWriteTable(t *testing.T) {
	var buf bytes.Buffer
	if err := Write(&buf, "table", sampleResult()); err != nil {
		t.Fatalf("Write: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "time") || !strings.Contains(out, "user") {
		t.Errorf("table output missing headers: %q", out)
	}
	if !strings.Contains(out, "jdoe@example.com") {
		t.Errorf("table output missing row data: %q", out)
	}
	if !strings.Contains(out, "2026-07-03T12:00:00Z") {
		t.Errorf("table output should format time.Time as RFC3339: %q", out)
	}
}

func TestWriteTableDefaultsToEmptyFormat(t *testing.T) {
	var buf bytes.Buffer
	if err := Write(&buf, "", sampleResult()); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if buf.Len() == 0 {
		t.Error("expected default (empty format string) to behave like table, got no output")
	}
}

func TestWriteCSV(t *testing.T) {
	var buf bytes.Buffer
	if err := Write(&buf, "csv", sampleResult()); err != nil {
		t.Fatalf("Write: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected header + 1 data row, got %d lines: %q", len(lines), buf.String())
	}
	if lines[0] != "time,user,raw" {
		t.Errorf("csv header = %q, want %q", lines[0], "time,user,raw")
	}
}

func TestWriteJSONEmbedsRawMessageAsStructuredJSON(t *testing.T) {
	var buf bytes.Buffer
	if err := Write(&buf, "json", sampleResult()); err != nil {
		t.Fatalf("Write: %v", err)
	}

	var decoded []map[string]any
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, buf.String())
	}
	if len(decoded) != 1 {
		t.Fatalf("got %d objects, want 1", len(decoded))
	}

	// The raw column should decode as a nested object, not a JSON-encoded
	// string — that's the whole point of keeping json.RawMessage typed
	// through to the JSON writer instead of stringifying it first.
	raw, ok := decoded[0]["raw"].(map[string]any)
	if !ok {
		t.Fatalf("raw field decoded as %T, want a nested object: %v", decoded[0]["raw"], decoded[0]["raw"])
	}
	if raw["event"] != "user.login" {
		t.Errorf("raw.event = %v, want user.login", raw["event"])
	}
}

func TestWriteUnknownFormat(t *testing.T) {
	var buf bytes.Buffer
	err := Write(&buf, "xml", sampleResult())
	if err == nil {
		t.Fatal("expected an error for an unknown format")
	}
}

func TestStringifyNilAndBool(t *testing.T) {
	cases := []struct {
		in   any
		want string
	}{
		{nil, ""},
		{true, "true"},
		{false, "false"},
		{"plain", "plain"},
	}
	for _, c := range cases {
		if got := stringify(c.in); got != c.want {
			t.Errorf("stringify(%v) = %q, want %q", c.in, got, c.want)
		}
	}
}
