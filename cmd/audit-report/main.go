// audit-report is a CLI for querying the events database populated by
// audit-sink, producing the four report types over a time range.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
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

const usage = "usage: audit-report <activity|requests|security|compliance|version> [flags]"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "audit-report:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return errors.New(usage)
	}
	sub, rest := args[0], args[1:]

	switch sub {
	case "version", "--version", "-v":
		fmt.Println("audit-report", version)
		return nil
	case "help", "--help", "-h":
		fmt.Println(usage)
		return nil
	}

	fs := flag.NewFlagSet(sub, flag.ContinueOnError)
	from := fs.String("from", time.Now().Add(-24*time.Hour).Format(time.RFC3339), "start time (RFC3339)")
	to := fs.String("to", time.Now().Format(time.RFC3339), "end time (RFC3339, ignored with --watch)")
	user := fs.String("user", "", "filter to a single user (activity, compliance; requests filters by requester)")
	outFormat := fs.String("format", "table", "output format: table, csv, json")
	dbURL := fs.String("db", os.Getenv("DATABASE_URL"), "Postgres connection string (default: $DATABASE_URL)")
	watch := fs.Bool("watch", false, "poll and re-render continuously instead of running once, like `watch`")
	interval := fs.Duration("interval", 5*time.Second, "how often to refresh when --watch is set")
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
		return fmt.Errorf("missing --db (or set DATABASE_URL)")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	pool, err := pgxpool.New(ctx, *dbURL)
	if err != nil {
		return fmt.Errorf("connect to postgres: %w", err)
	}
	defer pool.Close()

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
			return format.Result{}, fmt.Errorf("unknown report %q (want activity, requests, security, or compliance)", sub)
		}
	}

	if !*watch {
		res, err := runReport(ctx, toTime)
		if err != nil {
			return fmt.Errorf("run %s report: %w", sub, err)
		}
		return format.Write(os.Stdout, *outFormat, res)
	}

	return watchLoop(ctx, sub, *interval, *outFormat, runReport)
}

// watchLoop re-runs the report on a fixed interval against a continuously
// advancing "to" (always now), fully re-rendering each time rather than
// diffing against the previous output. That makes it robust against
// disconnects and restarts — there's no cursor or notification to miss, the
// next tick just recomputes ground truth from the database — at the cost of
// re-querying the whole window every tick. Keep --from recent when using
// --watch so each refresh stays a reasonable size.
func watchLoop(ctx context.Context, sub string, interval time.Duration, outFormat string, runReport func(context.Context, time.Time) (format.Result, error)) error {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		res, err := runReport(ctx, time.Now())
		if err != nil {
			return fmt.Errorf("run %s report: %w", sub, err)
		}
		fmt.Print("\033[H\033[2J")
		fmt.Printf("%s report — updated %s (refreshing every %s, Ctrl+C to stop)\n\n", sub, time.Now().Format(time.RFC3339), interval)
		if err := format.Write(os.Stdout, outFormat, res); err != nil {
			return err
		}

		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}
