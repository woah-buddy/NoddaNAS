// Package testutil provides shared helpers for integration tests.
package testutil

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/woah-buddy/FrontDir/internal/secure"
	"github.com/woah-buddy/FrontDir/internal/store/postgres"
)

// Postgres returns a migrated store in a fresh, private schema. Tests are
// skipped unless FRONTDIR_TEST_DATABASE_URL points at a PostgreSQL server.
func Postgres(t *testing.T) *postgres.Store {
	st, _ := PostgresSchema(t)
	return st
}

// PostgresSchema is Postgres, also returning the name of the private schema.
func PostgresSchema(t *testing.T) (*postgres.Store, string) {
	t.Helper()
	dsn := os.Getenv("FRONTDIR_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("FRONTDIR_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	schema := "t_" + secure.NewID()[:16]
	admin := adminConn(t, dsn)
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = admin.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE") })
	st, err := postgres.Open(ctx, withSchema(dsn, schema))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	return st, schema
}

// RestoreCopy simulates backing up the database in schema `from` and
// restoring it on a new server: it creates a fresh, migrated schema, copies
// every row into it, and returns a store on the copy.
//
// dump is every row of every table as JSON text, which is exactly the
// information a database backup holds, so tests can inspect it.
func RestoreCopy(t *testing.T, from string) (restored *postgres.Store, dump string) {
	t.Helper()
	dsn := os.Getenv("FRONTDIR_TEST_DATABASE_URL")
	ctx := context.Background()
	to, schema := PostgresSchema(t)
	admin := adminConn(t, dsn)
	rows, err := admin.Query(ctx, `SELECT table_name FROM information_schema.tables
		WHERE table_schema = $1 AND table_type = 'BASE TABLE' AND table_name <> 'schema_migrations' ORDER BY table_name`, from)
	if err != nil {
		t.Fatal(err)
	}
	tables, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		t.Fatal(err)
	}
	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	// Load rows in any order, as pg_restore does, without firing foreign-key
	// triggers mid-load (the data was consistent when it was taken).
	if _, err := tx.Exec(ctx, "SET LOCAL session_replication_role = replica"); err != nil {
		t.Fatal(err)
	}
	var sb strings.Builder
	for _, tbl := range tables {
		src := pgx.Identifier{from, tbl}.Sanitize()
		dst := pgx.Identifier{schema, tbl}.Sanitize()
		if _, err := tx.Exec(ctx, "INSERT INTO "+dst+" SELECT * FROM "+src); err != nil {
			t.Fatalf("copy %s: %v", tbl, err)
		}
		var rowsJSON string
		if err := tx.QueryRow(ctx, "SELECT coalesce(json_agg(t)::text, '[]') FROM "+src+" t").Scan(&rowsJSON); err != nil {
			t.Fatal(err)
		}
		sb.WriteString(tbl + " " + rowsJSON + "\n")
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	return to, sb.String()
}

// Exec runs SQL directly in a test schema, for tests that play a server
// whose database has been tampered with.
func Exec(t *testing.T, schema, sql string, args ...any) int64 {
	t.Helper()
	c := adminConn(t, withSchema(os.Getenv("FRONTDIR_TEST_DATABASE_URL"), schema))
	tag, err := c.Exec(context.Background(), sql, args...)
	if err != nil {
		t.Fatal(err)
	}
	return tag.RowsAffected()
}

func adminConn(t *testing.T, dsn string) *pgx.Conn {
	t.Helper()
	c, err := pgx.Connect(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close(context.Background()) })
	return c
}

func withSchema(dsn, schema string) string {
	sep := "?"
	if strings.Contains(dsn, "?") {
		sep = "&"
	}
	return dsn + sep + "search_path=" + schema
}
