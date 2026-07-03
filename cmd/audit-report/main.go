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
	"os/signal"
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
	case "--watch", "-watch":
		// `audit-report --watch` alone (no report type) live-tails
		// everything via compliance, which has no event-type filter —
		// the closest thing to "just show me what's happening."
		sub, rest = "compliance", args
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
  --db string         Postgres connection string (default: $DATABASE_URL)
  --watch             Poll and re-render continuously instead of running once
  --interval duration Refresh interval when --watch is set (default: 5s)

Examples:
  audit-report activity --from=2026-07-01T00:00:00Z --to=2026-07-03T00:00:00Z
  audit-report security --watch --human
  audit-report compliance --user=jdoe@example.com --format=csv > export.csv
  audit-report --watch    # shorthand for: compliance --watch

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
			return report.Compliance(ctx, pool, filter)
		default:
			return format.Result{}, fmt.Errorf("unknown report %q", sub)
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
