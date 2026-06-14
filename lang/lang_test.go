package lang

import (
	"bytes"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/hashicorp/hcl/v2"
)

// --- helpers ---------------------------------------------------------------

// posAt builds an hcl.Pos for a byte offset. Only Byte is consulted by hcl's
// range containment, but Line/Column are filled for realism.
func posAt(src string, b int) hcl.Pos {
	line, col := 1, 1
	for i := 0; i < b && i < len(src); i++ {
		if src[i] == '\n' {
			line++
			col = 1
		} else {
			col++
		}
	}
	return hcl.Pos{Line: line, Column: col, Byte: b}
}

// cursor returns the position `plus` bytes past the first occurrence of anchor.
func cursor(t *testing.T, src, anchor string, plus int) hcl.Pos {
	t.Helper()
	i := strings.Index(src, anchor)
	if i < 0 {
		t.Fatalf("anchor %q not found in source", anchor)
	}
	return posAt(src, i+plus)
}

func labels(cands []Candidate) []string {
	out := make([]string, len(cands))
	for i, c := range cands {
		out[i] = c.Label
	}
	return out
}

func contains(ss []string, want string) bool {
	return slices.Contains(ss, want)
}

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return b
}

func errorsOnly(diags hcl.Diagnostics) hcl.Diagnostics {
	var out hcl.Diagnostics
	for _, d := range diags {
		if d.Severity == hcl.DiagError {
			out = append(out, d)
		}
	}
	return out
}

// --- diagnostics -----------------------------------------------------------

func TestDiagnosticsValid(t *testing.T) {
	src := readFixture(t, "valid.hcl")
	diags := Diagnostics("valid.hcl", src)
	if errs := errorsOnly(diags); len(errs) > 0 {
		t.Fatalf("expected no error diagnostics for valid fixture, got: %v", errs)
	}
}

func TestDiagnosticsInvalidEnum(t *testing.T) {
	src := readFixture(t, "invalid-enum.hcl")
	diags := Diagnostics("invalid-enum.hcl", src)

	var gotErr, gotWarn *hcl.Diagnostic
	for _, d := range diags {
		switch d.Severity {
		case hcl.DiagError:
			gotErr = d
		case hcl.DiagWarning:
			gotWarn = d
		}
	}

	if gotErr == nil {
		t.Fatalf("expected an error diagnostic for the bad risk likelihood; diags=%v", diags)
	}
	if gotErr.Summary != "Invalid risk likelihood" {
		t.Errorf("error summary = %q, want %q", gotErr.Summary, "Invalid risk likelihood")
	}
	if got := rangeText(src, gotErr.Subject); !strings.Contains(got, "extremely_high") {
		t.Errorf("error range covers %q, want it to include %q", got, "extremely_high")
	}

	if gotWarn == nil {
		t.Fatalf("expected a warning diagnostic for the bad stride value; diags=%v", diags)
	}
	if gotWarn.Summary != "Unknown stride value" {
		t.Errorf("warning summary = %q, want %q", gotWarn.Summary, "Unknown stride value")
	}
	if got := rangeText(src, gotWarn.Subject); !strings.Contains(got, "Nonsense") {
		t.Errorf("warning range covers %q, want it to include %q", got, "Nonsense")
	}
}

func TestDiagnosticsUnknownBlockAndAttr(t *testing.T) {
	src := readFixture(t, "unknown.hcl")
	diags := Diagnostics("unknown.hcl", src)

	var sawAttr, sawBlock bool
	for _, d := range diags {
		switch d.Summary {
		case "Unsupported argument":
			sawAttr = true
		case "Unsupported block type":
			sawBlock = true
		}
	}
	if !sawAttr {
		t.Errorf("expected an 'Unsupported argument' diagnostic for bogus_attr; diags=%v", diags)
	}
	if !sawBlock {
		t.Errorf("expected an 'Unsupported block type' diagnostic for bogus_block; diags=%v", diags)
	}
}

func rangeText(src []byte, r *hcl.Range) string {
	if r == nil {
		return ""
	}
	s, e := r.Start.Byte, r.End.Byte
	if s < 0 || e > len(src) || s > e {
		return ""
	}
	return string(src[s:e])
}

// --- completion ------------------------------------------------------------

func TestCompletionBlockAndAttrContext(t *testing.T) {
	src := "threatmodel \"M\" {\n  author = \"x\"\n\n  threat \"t\" {\n    description = \"d\"\n  }\n}\n"
	pf, _ := ParseSource("t.hcl", []byte(src))

	got := labels(CompletionsAt(pf, cursor(t, src, "\n\n", 1)))
	for _, want := range []string{"threat", "author", "description"} {
		if !contains(got, want) {
			t.Errorf("completion at threatmodel body missing %q; got %v", want, got)
		}
	}
}

func TestCompletionEnumValueContext(t *testing.T) {
	src := "threatmodel \"M\" {\n  author = \"x\"\n  threat \"t\" {\n    description = \"d\"\n    stride = [\"Spoofing\"]\n  }\n}\n"
	pf, _ := ParseSource("t.hcl", []byte(src))

	got := labels(CompletionsAt(pf, cursor(t, src, "stride = ", len("stride = "))))
	if !contains(got, "Spoofing") {
		t.Errorf("expected stride enum values in completion, got %v", got)
	}
	// Should be enum values only, not block keywords.
	if contains(got, "threat") {
		t.Errorf("attribute-value slot should not offer block keywords; got %v", got)
	}
}

func TestCompletionToleratesIncompleteLine(t *testing.T) {
	// `thr` is a half-typed identifier (a syntax error), but the enclosing
	// threatmodel block is still recovered, so completion must still work.
	src := "threatmodel \"M\" {\n  author = \"x\"\n  thr\n}\n"
	pf, _ := ParseSource("t.hcl", []byte(src))
	if pf.Body == nil {
		t.Fatal("expected a recovered body even with a syntax error")
	}

	// Anchor on "thr\n" so we match the standalone identifier, not "threatmodel".
	got := labels(CompletionsAt(pf, cursor(t, src, "thr\n", len("thr"))))
	if !contains(got, "threat") {
		t.Errorf("expected 'threat' among completions on incomplete line; got %v", got)
	}
}

// --- hover -----------------------------------------------------------------

func TestHoverAttribute(t *testing.T) {
	src := "threatmodel \"M\" {\n  author = \"x\"\n}\n"
	pf, _ := ParseSource("t.hcl", []byte(src))

	h := HoverAt(pf, cursor(t, src, "author", 1))
	if h == nil {
		t.Fatal("expected hover on the author attribute")
	}
	if !strings.Contains(h.Contents, "author") || !strings.Contains(h.Contents, "authored") {
		t.Errorf("author hover contents = %q", h.Contents)
	}
}

func TestHoverBlockKeyword(t *testing.T) {
	src := "threatmodel \"M\" {\n  author = \"x\"\n}\n"
	pf, _ := ParseSource("t.hcl", []byte(src))

	h := HoverAt(pf, cursor(t, src, "threatmodel", 1))
	if h == nil {
		t.Fatal("expected hover on the threatmodel keyword")
	}
	if !strings.Contains(h.Contents, "threatmodel") {
		t.Errorf("threatmodel hover contents = %q", h.Contents)
	}
}

// --- symbols ---------------------------------------------------------------

func TestSymbolsOutline(t *testing.T) {
	pf, _ := ParseSource("valid.hcl", readFixture(t, "valid.hcl"))
	syms := Symbols(pf)

	if len(syms) != 1 {
		t.Fatalf("expected 1 top-level symbol, got %d (%v)", len(syms), syms)
	}
	root := syms[0]
	if root.Name != "Test Model" {
		t.Errorf("root symbol name = %q, want %q", root.Name, "Test Model")
	}
	if root.Kind != SymbolKindNamespace {
		t.Errorf("threatmodel symbol kind = %v, want Namespace", root.Kind)
	}
	if findSymbol(syms, "phishing") == nil {
		t.Errorf("expected a descendant symbol named 'phishing'; tree=%v", syms)
	}
	if findSymbol(syms, "mfa") == nil {
		t.Errorf("expected a descendant symbol named 'mfa'; tree=%v", syms)
	}
}

func findSymbol(syms []Symbol, name string) *Symbol {
	for i := range syms {
		if syms[i].Name == name {
			return &syms[i]
		}
		if s := findSymbol(syms[i].Children, name); s != nil {
			return s
		}
	}
	return nil
}

// --- format ----------------------------------------------------------------

func TestFormatValidIsIdempotentAndIndents(t *testing.T) {
	src := []byte("threatmodel \"M\" {\nauthor = \"x\"\n}\n")
	out, diags := Format("t.hcl", src)
	if diags.HasErrors() {
		t.Fatalf("unexpected diags formatting valid source: %v", diags)
	}
	if bytes.Equal(out, src) {
		t.Error("expected Format to re-indent the misformatted source")
	}
	if !strings.Contains(string(out), "  author") {
		t.Errorf("expected 2-space indented author line, got:\n%s", out)
	}
	again, _ := Format("t.hcl", out)
	if !bytes.Equal(again, out) {
		t.Error("Format is not idempotent")
	}
}

func TestFormatBrokenReturnsDiagsUnchanged(t *testing.T) {
	src := []byte("threatmodel \"M\" {\n  author = \"x\"\n") // missing closing brace
	out, diags := Format("t.hcl", src)
	if !diags.HasErrors() {
		t.Fatal("expected diagnostics for syntactically broken source")
	}
	if !bytes.Equal(out, src) {
		t.Error("expected broken source to be returned unchanged")
	}
}
