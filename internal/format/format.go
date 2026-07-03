// Package format renders a report.Result as a table (for terminals), CSV,
// or JSON.
package format

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"
)

// Result is the shared shape every report produces: a header row plus data
// rows. Values keep their native Go type (string, bool, time.Time,
// json.RawMessage, ...) so JSON output can embed structured data (e.g. the
// full raw event) instead of a doubly-escaped string.
type Result struct {
	Columns []string
	Rows    [][]any
}

// humanTimeLayout drops the RFC3339 "T" separator and numeric offset in
// favor of a space and a local zone abbreviation, and converts to the
// caller's local timezone — meant for a human looking at a terminal, not
// a machine parsing output. Kept sortable (still YYYY-MM-DD HH:MM:SS) by
// design.
const humanTimeLayout = "2006-01-02 15:04:05 MST"

// Write renders res in the given format. humanTime only affects table and
// csv — json always uses RFC3339 (via time.Time's native MarshalJSON) since
// it's meant for machine consumption/round-tripping, not reading.
func Write(w io.Writer, format string, res Result, humanTime bool) error {
	switch format {
	case "", "table":
		return writeTable(w, res, humanTime)
	case "csv":
		return writeCSV(w, res, humanTime)
	case "json":
		return writeJSON(w, res)
	default:
		return fmt.Errorf("unknown format %q (want table, csv, or json)", format)
	}
}

func writeTable(w io.Writer, res Result, humanTime bool) error {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, strings.Join(res.Columns, "\t"))
	for _, row := range res.Rows {
		cells := make([]string, len(row))
		for i, v := range row {
			cells[i] = stringify(v, humanTime)
		}
		fmt.Fprintln(tw, strings.Join(cells, "\t"))
	}
	return tw.Flush()
}

func writeCSV(w io.Writer, res Result, humanTime bool) error {
	cw := csv.NewWriter(w)
	if err := cw.Write(res.Columns); err != nil {
		return err
	}
	for _, row := range res.Rows {
		cells := make([]string, len(row))
		for i, v := range row {
			cells[i] = stringify(v, humanTime)
		}
		if err := cw.Write(cells); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

func writeJSON(w io.Writer, res Result) error {
	objs := make([]map[string]any, len(res.Rows))
	for i, row := range res.Rows {
		obj := make(map[string]any, len(res.Columns))
		for j, col := range res.Columns {
			if j < len(row) {
				obj[col] = row[j]
			}
		}
		objs[i] = obj
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(objs)
}

func stringify(v any, humanTime bool) string {
	if v == nil {
		return ""
	}
	switch b := v.(type) {
	case time.Time:
		if humanTime {
			return b.Local().Format(humanTimeLayout)
		}
		return b.Format(time.RFC3339)
	case json.RawMessage:
		return string(b)
	case []byte:
		return string(b)
	}
	if s, ok := v.(fmt.Stringer); ok {
		return s.String()
	}
	return fmt.Sprint(v)
}
