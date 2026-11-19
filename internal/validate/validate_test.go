package validate

import (
	"strings"
	"testing"
)

func TestName(t *testing.T) {
	good := map[string]string{
		"report.pdf":                   "report.pdf",
		"Ünïcödé ✓":                    "Ünïcödé ✓",
		"éte":                         "éte", // normalized to NFC
		".hidden":                      ".hidden",
		"a" + strings.Repeat("b", 254): "a" + strings.Repeat("b", 254),
	}
	for in, want := range good {
		got, err := Name(in)
		if err != nil || got != want {
			t.Errorf("Name(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{
		"", ".", "..", "...", "a/b", `a\b`, "nul\x00", "tab\there", "new\nline", " lead", "trail ",
		"evil\u202efdp.exe", "x\u2066y", strings.Repeat("a", 256), "\xff\xfe",
	} {
		if _, err := Name(bad); err == nil {
			t.Errorf("Name(%q) accepted", bad)
		}
	}
}

func TestNameKeyIsCaseInsensitive(t *testing.T) {
	if NameKey("Report.PDF") != NameKey("report.pdf") || NameKey("STRASSE") != NameKey("straße") {
		t.Fatal("name keys must fold case")
	}
}

func TestIDAndHash(t *testing.T) {
	if ID("0123456789abcdef0123456789abcdef") != nil || ID("0123456789ABCDEF0123456789abcdef") == nil ||
		ID("../../../../etc/passwd") == nil || ID("") == nil {
		t.Fatal("ID validation wrong")
	}
	if SHA256Hex(strings.Repeat("a", 64)) != nil || SHA256Hex(strings.Repeat("g", 64)) == nil {
		t.Fatal("SHA256Hex validation wrong")
	}
}

func TestContentTypeAndEmail(t *testing.T) {
	if ContentType("text/html; charset=utf-8") != "text/html" || ContentType("garbage") != "application/octet-stream" {
		t.Fatal("ContentType wrong")
	}
	if e, err := Email("Alice@Example.COM"); err != nil || e != "alice@example.com" {
		t.Fatalf("Email = %q, %v", e, err)
	}
	for _, bad := range []string{"", "not-an-email", "Alice <alice@example.com>", "a@b@c"} {
		if _, err := Email(bad); err == nil {
			t.Errorf("Email(%q) accepted", bad)
		}
	}
}
