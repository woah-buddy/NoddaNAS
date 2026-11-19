// Package testutil provides shared helpers for integration tests.
package testutil

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/woah-buddy/NoddaNAS/internal/secure"
	"github.com/woah-buddy/NoddaNAS/internal/store/postgres"
)

// Postgres returns a migrated store in a fresh, private schema. Tests are
// skipped unless NODDANAS_TEST_DATABASE_URL points at a PostgreSQL server.
func Postgres(t *testing.T) *postgres.Store {
	t.Helper()
	dsn := os.Getenv("NODDANAS_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("NODDANAS_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	schema := "t_" + secure.NewID()[:16]
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		admin.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE")
		admin.Close(context.Background())
	})
	sep := "?"
	if strings.Contains(dsn, "?") {
		sep = "&"
	}
	st, err := postgres.Open(ctx, dsn+sep+"search_path="+schema)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	if err := st.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	return st
}
