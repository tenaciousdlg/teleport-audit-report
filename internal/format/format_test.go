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
	if err := Write(&buf, "table", sampleResult(), false); err != nil {
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
		t.Errorf("table output should format time.Time as RFC3339 when humanTime is false: %q", out)
	}
}

func TestWriteTableHumanTime(t *testing.T) {
	var buf bytes.Buffer
	if err := Write(&buf, "table", sampleResult(), true); err != nil {
		t.Fatalf("Write: %v", err)
	}
	out := buf.String()
	if strings.Contains(out, "2026-07-03T12:00:00Z") {
		t.Errorf("humanTime=true should not leave RFC3339 'T' separator/Z in output: %q", out)
	}
	if !strings.Contains(out, "2026-07-03") {
		t.Errorf("humanTime output should still contain the date: %q", out)
	}
}

func TestWriteTableDefaultsToEmptyFormat(t *testing.T) {
	var buf bytes.Buffer
	if err := Write(&buf, "", sampleResult(), false); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if buf.Len() == 0 {
		t.Error("expected default (empty format string) to behave like table, got no output")
	}
}

func TestWriteCSV(t *testing.T) {
	var buf bytes.Buffer
	if err := Write(&buf, "csv", sampleResult(), false); err != nil {
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
	if err := Write(&buf, "json", sampleResult(), false); err != nil {
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

func TestWriteJSONIgnoresHumanTime(t *testing.T) {
	var buf bytes.Buffer
	if err := Write(&buf, "json", sampleResult(), true); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if !strings.Contains(buf.String(), "2026-07-03T12:00:00Z") {
		t.Errorf("json output should always use RFC3339 regardless of humanTime: %q", buf.String())
	}
}

func TestWriteUnknownFormat(t *testing.T) {
	var buf bytes.Buffer
	err := Write(&buf, "xml", sampleResult(), false)
	if err == nil {
		t.Fatal("expected an error for an unknown format")
	}
}

func TestSummarize(t *testing.T) {
	res := Result{
		Columns: []string{"time", "event_type", "user"},
		Rows: [][]any{
			{time.Now(), "cert.create", "a"},
			{time.Now(), "user.login", "b"},
			{time.Now(), "cert.create", "c"},
			{time.Now(), "cert.create", "d"},
		},
	}

	out := Summarize(res, "event_type")

	if got, want := out.Columns, []string{"event_type", "count"}; got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("Columns = %v, want %v", got, want)
	}
	if len(out.Rows) != 2 {
		t.Fatalf("got %d rows, want 2 (cert.create, user.login): %+v", len(out.Rows), out.Rows)
	}
	// Sorted by count descending — cert.create (3) before user.login (1).
	if out.Rows[0][0] != "cert.create" || out.Rows[0][1] != 3 {
		t.Errorf("Rows[0] = %v, want [cert.create 3]", out.Rows[0])
	}
	if out.Rows[1][0] != "user.login" || out.Rows[1][1] != 1 {
		t.Errorf("Rows[1] = %v, want [user.login 1]", out.Rows[1])
	}
}

func TestSummarizeUnknownColumnReturnsUnchanged(t *testing.T) {
	res := sampleResult()
	out := Summarize(res, "does_not_exist")
	if len(out.Columns) != len(res.Columns) || len(out.Rows) != len(res.Rows) {
		t.Errorf("Summarize with an unknown column should return res unchanged, got %+v", out)
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
		if got := stringify(c.in, false); got != c.want {
			t.Errorf("stringify(%v) = %q, want %q", c.in, got, c.want)
		}
	}
}
