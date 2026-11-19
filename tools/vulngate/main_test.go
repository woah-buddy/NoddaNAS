package main

import (
	"strings"
	"testing"
	"time"
)

const cfg = `{"config":{"protocol_version":"v1.0.0","scanner_name":"govulncheck"}}`

func called(id, mod string) string {
	return `{"finding":{"osv":"` + id + `","trace":[{"module":"` + mod + `","version":"v1.0.0","package":"` + mod + `/x","function":"Parse"}]}}`
}

func importedOnly(id, mod string) string {
	return `{"finding":{"osv":"` + id + `","trace":[{"module":"` + mod + `","version":"v1.0.0"}]}}`
}

func TestGate(t *testing.T) {
	now := time.Date(2026, 11, 19, 0, 0, 0, 0, time.UTC)
	ok := Exception{ID: "GO-1", Module: "example.com/m", Expires: "2026-12-31", Reason: "fixed in our version; record stale"}
	cases := []struct {
		name   string
		stream string
		exc    []Exception
		pass   bool
	}{
		{"clean", cfg, nil, true},
		{"reachable, no exception", cfg + called("GO-1", "example.com/m"), nil, false},
		{"reachable, valid exception", cfg + called("GO-1", "example.com/m"), []Exception{ok}, true},
		{"exception for another module", cfg + called("GO-1", "example.com/other"), []Exception{ok}, false},
		{"only imported, not called", cfg + importedOnly("GO-2", "example.com/n"), nil, true},
		{"expired exception", cfg + called("GO-1", "example.com/m"), []Exception{{ID: "GO-1", Module: "example.com/m", Expires: "2026-11-19", Reason: "x"}}, false},
		{"exception too far ahead", cfg, []Exception{{ID: "GO-1", Module: "example.com/m", Expires: "2027-06-01", Reason: "x"}}, false},
		{"exception without reason", cfg, []Exception{{ID: "GO-1", Module: "example.com/m", Expires: "2026-12-01"}}, false},
		{"no output at all (fail closed)", "", nil, false},
		{"unknown finding shape (fail closed)", cfg + `{"finding":{"id":"GO-1","frames":[]}}`, nil, false},
		{"garbage (fail closed)", cfg + `{"finding":`, nil, false},
	}
	for _, c := range cases {
		report, err := gate(strings.NewReader(c.stream), c.exc, now)
		if (err == nil) != c.pass {
			t.Errorf("%s: pass=%v, want %v\n%s", c.name, err == nil, c.pass, report)
		}
	}
}
