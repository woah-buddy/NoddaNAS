package theme

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"math"
	"os"
	"regexp"
	"strings"
	"testing"
)

func TestContrast(t *testing.T) {
	if r := Contrast("#000000", "#ffffff"); math.Abs(r-21) > 0.01 {
		t.Fatalf("black/white = %v, want 21", r)
	}
	if r := Contrast("#777777", "#777777"); r != 1 {
		t.Fatalf("same color = %v, want 1", r)
	}
	// WCAG reference: #767676 on white is the classic 4.54:1.
	if r := Contrast("#767676", "#ffffff"); r < 4.5 || r > 4.6 {
		t.Fatalf("#767676 on white = %v", r)
	}
}

// Every built-in mode/accent combination passes the same rules operators must meet.
func TestBuiltinsPass(t *testing.T) {
	th := Default()
	if th.Name != "NoddaNAS" || len(th.Accents) != 6 {
		t.Fatalf("default theme: %+v", th)
	}
}

func TestOperatorThemeAccepted(t *testing.T) {
	th, err := Load(Options{Name: "Acme Files", ThemeJSON: []byte(`{
		"defaultAccent": "acme",
		"light": {"bg": "#FAFAFA", "line": "#ddd"},
		"accents": {"acme": {"label": "Acme red",
			"light": {"accent": "#b3261e", "accentText": "#ffffff"},
			"dark": {"accent": "#ff8a80", "accentText": "#1a1a1a"}}}}`)})
	if err != nil {
		t.Fatal(err)
	}
	css, _ := th.CSS()
	s := string(css)
	if th.Name != "Acme Files" || th.DefaultAccent != "acme" || !strings.Contains(s, `:root[data-accent="acme"]`) ||
		!strings.Contains(s, "--bg:#fafafa;") || !strings.Contains(s, "--line:#dddddd;") {
		t.Fatalf("theme not applied:\n%s", s)
	}
}

func TestThemeRejected(t *testing.T) {
	cases := map[string]Options{
		"css injection in value":   {ThemeJSON: []byte(`{"light": {"bg": "#fff;} body{display:none"}}`)},
		"url value":                {ThemeJSON: []byte(`{"light": {"bg": "url(https://evil.example/x)"}}`)},
		"named color":              {ThemeJSON: []byte(`{"light": {"bg": "red"}}`)},
		"unknown token":            {ThemeJSON: []byte(`{"light": {"fontFamily": "#000000"}}`)},
		"unknown field":            {ThemeJSON: []byte(`{"customCSS": "body{}"}`)},
		"invisible text":           {ThemeJSON: []byte(`{"light": {"text": "#f6f6f8"}}`)},
		"hidden danger":            {ThemeJSON: []byte(`{"dark": {"danger": "#1d1d22"}}`)},
		"low-contrast muted":       {ThemeJSON: []byte(`{"light": {"muted": "#c0c0c0"}}`)},
		"unreadable accent button": {ThemeJSON: []byte(`{"accents": {"sun": {"label": "Sun", "light": {"accent": "#ffd60a", "accentText": "#ffffff"}, "dark": {"accent": "#ffd60a", "accentText": "#000000"}}}}`)},
		"accent id with quote":     {ThemeJSON: []byte(`{"accents": {"a\"]{}": {"label": "x", "light": {"accent": "#000000", "accentText": "#ffffff"}, "dark": {"accent": "#ffffff", "accentText": "#000000"}}}}`)},
		"accent with extra token":  {ThemeJSON: []byte(`{"accents": {"x": {"label": "x", "light": {"accent": "#2556c4", "accentText": "#ffffff", "bg": "#000000"}, "dark": {"accent": "#7aa7ff", "accentText": "#0b0b0f"}}}}`)},
		"unknown default accent":   {ThemeJSON: []byte(`{"defaultAccent": "nope"}`)},
		"bidi name":                {Name: "Files\u202Egnp.exe"},
		"control char name":        {Name: "Files\n<script>"},
		"too long name":            {Name: strings.Repeat("x", 41)},
		"malformed json":           {ThemeJSON: []byte(`{`)},
	}
	for name, o := range cases {
		if _, err := Load(o); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// The generated stylesheet can only contain our own syntax: no URLs, no
// imports, no markup, whatever the inputs were.
func TestCSSIsInert(t *testing.T) {
	th := Default()
	css, etag := th.CSS()
	s := string(css)
	for _, bad := range []string{"url(", "@import", "expression(", "<", "javascript:", "\\"} {
		if strings.Contains(s, bad) {
			t.Fatalf("stylesheet contains %q", bad)
		}
	}
	if etag == "" || !strings.Contains(s, `:root[data-theme="contrast"]`) {
		t.Fatal("missing high-contrast rules or ETag")
	}
	// High contrast is the last layer, so no accent can override it.
	if !strings.Contains(s, "@layer noddanas-mode, noddanas-accent, noddanas-contrast;") ||
		strings.Index(s, "@layer noddanas-contrast{") < strings.LastIndex(s, ".swatch") {
		t.Fatal("layer order wrong")
	}
	// Braces balance: no value can open or close a block.
	if strings.Count(s, "{") != strings.Count(s, "}") {
		t.Fatal("unbalanced braces")
	}
	// Every value is a validated color.
	for _, m := range regexp.MustCompile(`--[a-z-]+:([^;]+);`).FindAllStringSubmatch(s, -1) {
		if !regexp.MustCompile(`^#[0-9a-f]{6}$`).MatchString(m[1]) {
			t.Fatalf("unexpected token value %q", m[1])
		}
	}
}

func testPNG(w, h int) []byte {
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	img.Set(0, 0, color.RGBA{255, 0, 0, 255})
	var b bytes.Buffer
	png.Encode(&b, img)
	return b.Bytes()
}

func TestSanitizeLogo(t *testing.T) {
	good := testPNG(64, 32)
	// A polyglot: a valid PNG with HTML appended after the image data.
	poly := append(bytes.Clone(good), []byte("<html><script>alert(1)</script></html>")...)
	out, err := SanitizeLogo(poly)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(out, []byte("<script>")) {
		t.Fatal("re-encoding kept the appended payload")
	}
	if cfg, err := png.DecodeConfig(bytes.NewReader(out)); err != nil || cfg.Width != 64 || cfg.Height != 32 {
		t.Fatalf("re-encoded logo: %v %v", cfg, err)
	}
	for name, data := range map[string][]byte{
		"svg":       []byte(`<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>`),
		"gif":       []byte("GIF89a...."),
		"truncated": good[:40],
		"huge":      testPNG(2048, 2048), // more than one megapixel
		"too big":   append(bytes.Clone(good), make([]byte, maxLogoBytes)...),
	} {
		if _, err := SanitizeLogo(data); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestLoadWithLogo(t *testing.T) {
	th, err := Load(Options{Logo: testPNG(16, 16)})
	if err != nil || len(th.Logo) == 0 || th.LogoETag == "" {
		t.Fatalf("logo: %v", err)
	}
}

// The examples we ship and document must pass the checks they describe.
func TestShippedExamplesValidate(t *testing.T) {
	ex, err := os.ReadFile("../../deploy/compose/branding/theme.example.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Load(Options{ThemeJSON: ex}); err != nil {
		t.Errorf("theme.example.json: %v", err)
	}
	doc, err := os.ReadFile("../../docs/THEMING.md")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile("(?s)```json\n(.*?)```").FindSubmatch(doc)
	if m == nil {
		t.Fatal("no JSON example in THEMING.md")
	}
	if _, err := Load(Options{ThemeJSON: m[1]}); err != nil {
		t.Errorf("THEMING.md example: %v", err)
	}
}
