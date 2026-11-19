// Command vulngate turns govulncheck's JSON output into a pass/fail CI gate
// with reviewed, time-limited exceptions.
//
//	govulncheck -format json ./... | go run ./tools/vulngate -exceptions .github/govulncheck-exceptions.json
//
// It fails on every vulnerability our code actually calls (symbol-level
// finding) unless an exception names that exact advisory and module, gives
// a reason, and has not expired. Exceptions may last at most 90 days, so
// an accepted risk is always re-reviewed. It fails closed: output it does
// not recognize is an error, never a pass.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"
)

// MaxExceptionAge bounds how far ahead an exception may expire.
const MaxExceptionAge = 90 * 24 * time.Hour

// Exception is a reviewed, time-limited acceptance of one advisory.
type Exception struct {
	ID      string `json:"id"`      // e.g. GO-2026-6909
	Module  string `json:"module"`  // e.g. github.com/crewjam/saml
	Expires string `json:"expires"` // YYYY-MM-DD; invalid from that day on
	Reason  string `json:"reason"`  // why it does not affect us, with evidence
}

type frame struct {
	Module   string `json:"module"`
	Package  string `json:"package"`
	Function string `json:"function"`
}

type finding struct {
	OSV   string   `json:"osv"`
	Trace []*frame `json:"trace"`
}

func main() {
	excPath := flag.String("exceptions", "", "JSON file of exceptions")
	flag.Parse()
	var exc []Exception
	if *excPath != "" {
		raw, err := os.ReadFile(*excPath) // #nosec G304 G703 -- a path in this repository, given in CI
		if err != nil {
			fail(err)
		}
		dec := json.NewDecoder(strings.NewReader(string(raw)))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&exc); err != nil {
			fail(fmt.Errorf("%s: %w", *excPath, err))
		}
	}
	report, err := gate(os.Stdin, exc, time.Now().UTC())
	fmt.Print(report)
	if err != nil {
		fail(err)
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "vulngate:", err)
	os.Exit(1)
}

// gate reads a govulncheck JSON stream and applies the exceptions.
func gate(r io.Reader, exceptions []Exception, now time.Time) (string, error) {
	var out strings.Builder
	var problems []string
	valid := map[string]Exception{}
	for _, e := range exceptions {
		exp, err := time.Parse("2006-01-02", e.Expires)
		switch {
		case e.ID == "" || e.Module == "" || strings.TrimSpace(e.Reason) == "" || err != nil:
			problems = append(problems, fmt.Sprintf("exception %q is incomplete: id, module, reason and expires (YYYY-MM-DD) are required", e.ID))
		case !now.Before(exp):
			problems = append(problems, fmt.Sprintf("exception for %s (%s) expired on %s: re-review it", e.ID, e.Module, e.Expires))
		case exp.Sub(now) > MaxExceptionAge:
			problems = append(problems, fmt.Sprintf("exception for %s expires %s, more than 90 days ahead", e.ID, e.Expires))
		default:
			valid[e.ID+"|"+e.Module] = e
		}
	}

	dec := json.NewDecoder(r)
	sawConfig := false
	called := map[string]string{} // "id|module" -> example call site
	for {
		var msg map[string]json.RawMessage
		if err := dec.Decode(&msg); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return out.String(), fmt.Errorf("unreadable govulncheck output: %w", err)
		}
		if _, ok := msg["config"]; ok {
			sawConfig = true
		}
		raw, ok := msg["finding"]
		if !ok {
			continue
		}
		var f finding
		if err := json.Unmarshal(raw, &f); err != nil || f.OSV == "" || len(f.Trace) == 0 || f.Trace[0] == nil || f.Trace[0].Module == "" {
			return out.String(), errors.New("unrecognized govulncheck finding format; refusing to pass")
		}
		if f.Trace[0].Function == "" {
			continue // imported or required, but our code never calls the vulnerable symbol
		}
		key := f.OSV + "|" + f.Trace[0].Module
		if _, seen := called[key]; !seen {
			called[key] = f.Trace[0].Package + "." + f.Trace[0].Function
		}
	}
	if !sawConfig {
		return out.String(), errors.New("no govulncheck output (did it run?); refusing to pass")
	}

	keys := make([]string, 0, len(called))
	for k := range called {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		id, mod, _ := strings.Cut(k, "|")
		if e, ok := valid[k]; ok {
			fmt.Fprintf(&out, "accepted  %s in %s (reaches %s) until %s: %s\n", id, mod, called[k], e.Expires, e.Reason)
			delete(valid, k)
			continue
		}
		problems = append(problems, fmt.Sprintf("%s in %s is reachable (%s)", id, mod, called[k]))
	}
	for _, e := range valid {
		fmt.Fprintf(&out, "notice    exception for %s no longer matches any finding; remove it\n", e.ID)
	}
	if len(problems) > 0 {
		for _, p := range problems {
			fmt.Fprintf(&out, "FAIL      %s\n", p)
		}
		return out.String(), fmt.Errorf("%d problem(s)", len(problems))
	}
	fmt.Fprintf(&out, "ok        %d reachable finding(s), all covered by reviewed exceptions\n", len(called))
	return out.String(), nil
}
