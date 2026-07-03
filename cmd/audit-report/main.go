// audit-report is a CLI for querying the events database populated by
// audit-sink, producing the four report types over a time range.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/tenaciousdlg/teleport-audit-report/internal/format"
	"github.com/tenaciousdlg/teleport-audit-report/internal/report"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "audit-report:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: audit-report <activity|requests|security|compliance> [flags]")
	}
	sub, rest := args[0], args[1:]

	fs := flag.NewFlagSet(sub, flag.ContinueOnError)
	from := fs.String("from", time.Now().Add(-24*time.Hour).Format(time.RFC3339), "start time (RFC3339)")
	to := fs.String("to", time.Now().Format(time.RFC3339), "end time (RFC3339)")
	user := fs.String("user", "", "filter to a single user (activity, compliance)")
	outFormat := fs.String("format", "table", "output format: table, csv, json")
	dbURL := fs.String("db", os.Getenv("DATABASE_URL"), "Postgres connection string (default: $DATABASE_URL)")
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

	ctx := context.Background()
	pool, err := pgxpool.New(ctx, *dbURL)
	if err != nil {
		return fmt.Errorf("connect to postgres: %w", err)
	}
	defer pool.Close()

	filter := report.Filter{From: fromTime, To: toTime, User: *user}

	var res format.Result
	switch sub {
	case "activity":
		res, err = report.Activity(ctx, pool, filter)
	case "requests":
		res, err = report.Requests(ctx, pool, filter)
	case "security":
		res, err = report.Security(ctx, pool, filter)
	case "compliance":
		res, err = report.Compliance(ctx, pool, filter)
	default:
		return fmt.Errorf("unknown report %q (want activity, requests, security, or compliance)", sub)
	}
	if err != nil {
		return fmt.Errorf("run %s report: %w", sub, err)
	}

	return format.Write(os.Stdout, *outFormat, res)
}
