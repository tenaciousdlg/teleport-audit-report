// audit-report is a CLI for querying the events database populated by
// audit-sink, producing the four report types over a time range.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/tenaciousdlg/teleport-audit-report/internal/format"
	"github.com/tenaciousdlg/teleport-audit-report/internal/report"
)

// version is set at build time via -ldflags "-X main.version=...";
// goreleaser injects the tag. Defaults to "dev" for `go run`/`go build`.
var version = "dev"

// commands drives both the top-level help listing and command validation,
// so adding a report type only means updating this and the switch in
// runReport.
var commands = []struct {
	name, help string
}{
	{"activity", "Session/access activity: SSH, Kubernetes, database, and app sessions"},
	{"requests", "Access-request lifecycle: created, reviewed, approved/denied"},
	{"security", "Failed authentication attempts and privilege-affecting changes"},
	{"compliance", "Raw, filtered event export for a time range"},
	{"version", "Print the audit-report version"},
	{"help", "Show this help"},
}

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 {
		printUsage(os.Stderr)
		return 1
	}
	sub, rest := args[0], args[1:]

	switch sub {
	case "version", "--version", "-v":
		fmt.Println("audit-report", version)
		return 0
	case "help", "--help", "-h":
		printUsage(os.Stdout)
		return 0
	default:
		if strings.HasPrefix(sub, "-") {
			// No report type given — just flags, e.g. `audit-report --watch`
			// or `audit-report --raw`. Pick a sensible default report rather
			// than erroring: --raw only means anything for compliance (the
			// only report with a raw JSON column to toggle), so route there
			// if it's present; otherwise default to security, the "is
			// anything wrong right now" view a bare `--watch` is usually
			// actually asking for.
			sub = "security"
			if wantsRaw(args) {
				sub = "compliance"
			}
			rest = args
		}
	}

	if err := runReportCommand(sub, rest); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			// The flag package already printed this command's usage.
			return 0
		}
		fmt.Fprintln(os.Stderr, "audit-report:", err)
		return 1
	}
	return 0
}

// wantsRaw checks for --raw/-raw among bare top-level args (before any
// report-specific flagset has parsed them), including the explicit-value
// forms --raw=true/-raw=false. Only used to pick a default report when none
// was given; runReportCommand's own flagset does the real parsing.
func wantsRaw(args []string) bool {
	for _, a := range args {
		switch {
		case a == "--raw" || a == "-raw":
			return true
		case strings.HasPrefix(a, "--raw=") || strings.HasPrefix(a, "-raw="):
			v := a[strings.Index(a, "=")+1:]
			return v != "false" && v != "0"
		}
	}
	return false
}

func printUsage(w io.Writer) {
	fmt.Fprintf(w, "audit-report — audit reporting for a Teleport cluster, backed by the\nPostgres database audit-sink populates from Teleport's Event Handler.\n\n")
	fmt.Fprintf(w, "Usage:\n  audit-report <command> [flags]\n\n")
	fmt.Fprintln(w, "Commands:")
	for _, c := range commands {
		fmt.Fprintf(w, "  %-11s %s\n", c.name, c.help)
	}
	fmt.Fprintf(w, `
Flags (activity, requests, security, compliance):
  --from string       Start time, RFC3339 (default: 24h ago)
  --to string         End time, RFC3339, ignored with --watch (default: now)
  --user string       Filter to one user (activity/security/compliance: actor; requests: requester)
  --format string     table, csv, or json (default: table)
  --human             Render timestamps in your local timezone, human-readable (table/csv only)
  --raw               compliance only: include the full raw JSON column in table output (csv/json always include it)
  --summary           Show a count-by-type breakdown instead of individual rows (by event_type, or by state for requests)
  --db string         Postgres connection string (default: $DATABASE_URL)
  --watch             Poll and re-render continuously instead of running once
  --interval duration Refresh interval when --watch is set (default: 5s)

Examples:
  audit-report activity --from=2026-07-01T00:00:00Z --to=2026-07-03T00:00:00Z
  audit-report security --watch --human
  audit-report compliance --user=jdoe@example.com --format=csv > export.csv
  audit-report compliance --summary --from=2026-07-01T00:00:00Z   # what happened, at a glance
  audit-report --watch       # shorthand for: security --watch
  audit-report --raw         # shorthand for: compliance --raw (--raw implies compliance when no command is given)
  audit-report --watch --raw --human   # shorthand for: compliance --watch --raw --human

Requires: the ingestion pipeline (postgres, tbot, event-handler, audit-sink)
running via Docker Compose, and DATABASE_URL pointing at it — see this
repo's README.md for setup. Run 'audit-report <command> -h' for
command-specific flag details, or see REPORTS.md for what Teleport audit
event types feed each report and why you'd use one over another.
`)
}

func runReportCommand(sub string, rest []string) error {
	if !isReportCommand(sub) {
		return fmt.Errorf("unknown command %q — run 'audit-report help' for the list of commands", sub)
	}

	fs := flag.NewFlagSet(sub, flag.ContinueOnError)
	from := fs.String("from", time.Now().Add(-24*time.Hour).Format(time.RFC3339), "start time (RFC3339)")
	to := fs.String("to", time.Now().Format(time.RFC3339), "end time (RFC3339, ignored with --watch)")
	user := fs.String("user", "", "filter to a single user (activity, security, compliance: actor; requests: requester)")
	outFormat := fs.String("format", "table", "output format: table, csv, json")
	humanTime := fs.Bool("human", false, "render timestamps in your local timezone, human-readable (table/csv only)")
	rawColumn := fs.Bool("raw", false, "compliance only: include the full raw JSON column in table output (csv/json always include it)")
	summary := fs.Bool("summary", false, "show a count-by-type breakdown instead of individual rows")
	dbURL := fs.String("db", os.Getenv("DATABASE_URL"), "Postgres connection string (default: $DATABASE_URL)")
	watch := fs.Bool("watch", false, "poll and re-render continuously instead of running once, like the watch(1) command")
	interval := fs.Duration("interval", 5*time.Second, "how often to refresh when --watch is set")
	fs.Usage = func() {
		desc := ""
		for _, c := range commands {
			if c.name == sub {
				desc = c.help
			}
		}
		fmt.Fprintf(fs.Output(), "audit-report %s — %s\n\nFlags:\n", sub, desc)
		fs.PrintDefaults()
	}
	if err := fs.Parse(rest); err != nil {
		return err
	}

	fromTime, err := time.Parse(time.RFC3339, *from)
	if err != nil {
		return fmt.Errorf("invalid --from: %w", err)
	}
	toTime, err := time.Parse(time.RFC3339, *to)
	if err != nil {
		return fmt.Errorf("invalid --to: %w", err)
	}
	if *dbURL == "" {
		return errors.New("missing Postgres connection string: pass --db or set $DATABASE_URL " +
			"(see README.md's Setup section — you likely just need to `source .env`)")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	pool, err := pgxpool.New(ctx, *dbURL)
	if err != nil {
		return fmt.Errorf("invalid --db/DATABASE_URL: %w", err)
	}
	defer pool.Close()

	// pgxpool.New only parses the connection string; it doesn't actually
	// connect until first use. Ping now so a down/unreachable pipeline
	// fails fast with an actionable message instead of a raw dial error
	// surfacing later from inside a query.
	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		cfg := pool.Config().ConnConfig
		return fmt.Errorf("cannot reach Postgres at %s:%d: %w\n\n"+
			"Is the ingestion pipeline running? From the repo root:\n"+
			"  docker compose up -d\n"+
			"Then re-run this command. See README.md's Setup section if you haven't\n"+
			"bootstrapped the stack yet.", cfg.Host, cfg.Port, err)
	}

	runReport := func(ctx context.Context, to time.Time) (format.Result, error) {
		filter := report.Filter{From: fromTime, To: to, User: *user}
		switch sub {
		case "activity":
			return report.Activity(ctx, pool, filter)
		case "requests":
			return report.Requests(ctx, pool, filter)
		case "security":
			return report.Security(ctx, pool, filter)
		case "compliance":
			// csv/json are for export/processing, where completeness is
			// the point — always include raw there. table is for reading
			// in a terminal, where a giant single-line JSON blob per row
			// isn't; only include it there on explicit request (--raw).
			includeRaw := *rawColumn || *outFormat != "table"
			return report.Compliance(ctx, pool, filter, includeRaw)
		default:
			return format.Result{}, fmt.Errorf("unknown report %q", sub)
		}
	}

	if *summary {
		// requests has no event_type column (it's already aggregated to
		// one row per request) — summarize by state instead. Every other
		// report has event_type. Wrapping runReport here, rather than
		// teaching watchLoop about --summary, keeps it a plain
		// Result-in-Result-out function either way.
		summarizeColumn := "event_type"
		if sub == "requests" {
			summarizeColumn = "state"
		}
		baseRunReport := runReport
		runReport = func(ctx context.Context, to time.Time) (format.Result, error) {
			res, err := baseRunReport(ctx, to)
			if err != nil {
				return res, err
			}
			return format.Summarize(res, summarizeColumn), nil
		}
	}

	if !*watch {
		res, err := runReport(ctx, toTime)
		if err != nil {
			return fmt.Errorf("run %s report: %w", sub, err)
		}
		return format.Write(os.Stdout, *outFormat, res, *humanTime)
	}

	return watchLoop(ctx, sub, *interval, *outFormat, *humanTime, runReport)
}

func isReportCommand(sub string) bool {
	switch sub {
	case "activity", "requests", "security", "compliance":
		return true
	default:
		return false
	}
}

// Enter/exit the terminal's alternate screen buffer — the same mechanism
// `less`, `vim`, `htop`, and the watch(1) command itself use. Redrawing
// with just "move cursor home + clear screen" (\033[H\033[2J) is not
// reliable across terminals: some interpret \033[2J as clearing only the
// current viewport without resetting scroll position, so each tick's
// output gets appended below the "cleared" content instead of overwriting
// it. The alternate screen buffer is a genuinely separate canvas — clearing
// it is unambiguous, and leaving it restores the user's prior terminal
// content exactly as it was, like closing `less`.
const (
	enterAltScreen  = "\033[?1049h"
	exitAltScreen   = "\033[?1049l"
	cursorHomeClear = "\033[H\033[2J"
)

// suppressEcho best-effort disables local terminal echo and returns a
// function to restore it. If stdin isn't a real terminal (piped, redirected,
// no `stty` available), the stty invocation just fails and this is a
// silent no-op — watch mode doesn't depend on it working.
func suppressEcho() func() {
	if err := runStty("-echo"); err != nil {
		return func() {}
	}
	return func() { _ = runStty("echo") }
}

func runStty(arg string) error {
	cmd := exec.Command("stty", arg)
	cmd.Stdin = os.Stdin
	return cmd.Run()
}

// watchLoop re-runs the report on a fixed interval against a continuously
// advancing "to" (always now), fully re-rendering each time rather than
// diffing against the previous output. That makes it robust against
// disconnects and restarts — there's no cursor or notification to miss, the
// next tick just recomputes ground truth from the database — at the cost of
// re-querying the whole window every tick. Keep --from recent when using
// --watch so each refresh stays a reasonable size.
func watchLoop(ctx context.Context, sub string, interval time.Duration, outFormat string, humanTime bool, runReport func(context.Context, time.Time) (format.Result, error)) error {
	fmt.Print(enterAltScreen)
	defer fmt.Print(exitAltScreen)

	// Watch mode doesn't read stdin at all — e.g. arrow keys pressed while
	// trying to scroll (scrolling isn't supported in the alternate screen,
	// same as in less/vim/htop) would otherwise just sit unread and get
	// locally echoed by the terminal as raw escape bytes until the next
	// redraw. Best-effort only: if stdin isn't a real terminal, this is a
	// silent no-op and watch mode still works.
	defer suppressEcho()()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		res, err := runReport(ctx, time.Now())
		if err != nil {
			return fmt.Errorf("run %s report: %w", sub, err)
		}
		fmt.Print(cursorHomeClear)
		fmt.Printf("%s report — updated %s (refreshing every %s, Ctrl+C to stop)\n\n", sub, watchTimestamp(humanTime), interval)
		if err := format.Write(os.Stdout, outFormat, res, humanTime); err != nil {
			return err
		}

		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

func watchTimestamp(human bool) string {
	now := time.Now()
	if human {
		return now.Local().Format("2006-01-02 15:04:05 MST")
	}
	return now.Format(time.RFC3339)
}
