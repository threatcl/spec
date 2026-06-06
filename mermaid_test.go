package spec

import (
	"io"
	"strings"
	"testing"
)

func parseRaw(t *testing.T, src string) *ThreatmodelParser {
	t.Helper()
	cfg := &ThreatmodelSpecConfig{}
	cfg.setDefaults()
	p := NewThreatmodelParser(cfg)
	if err := p.ParseHCLRaw([]byte(src)); err != nil {
		t.Fatalf("parse failed:\n--- HCL ---\n%s\n--- ERR ---\n%s", src, err)
	}
	return p
}

func TestMermaidParseSingle(t *testing.T) {
	src := `spec_version = "` + Version + `"

threatmodel "Payments API" {
  author = "@security-team"

  mermaid "Login sequence" {
    description = "How the login flow works"

    content = <<-EOT
      sequenceDiagram
        participant U as User
        participant F as Frontend
        participant A as API
        U->>F: login
        F->>A: POST /auth
        A-->>F: JWT
    EOT
  }
}
`
	p := parseRaw(t, src)
	tm := p.GetWrapped().Threatmodels[0]

	if len(tm.MermaidDiagrams) != 1 {
		t.Fatalf("expected 1 mermaid diagram, got %d", len(tm.MermaidDiagrams))
	}
	m := tm.MermaidDiagrams[0]
	if m.Name != "Login sequence" {
		t.Errorf("mermaid name = %q, want %q", m.Name, "Login sequence")
	}
	if m.Description != "How the login flow works" {
		t.Errorf("mermaid description = %q", m.Description)
	}
	for _, want := range []string{"sequenceDiagram", "U->>F: login", "A-->>F: JWT"} {
		if !strings.Contains(m.Content, want) {
			t.Errorf("mermaid content missing %q:\n%s", want, m.Content)
		}
	}
}

func TestMermaidParseMultiple(t *testing.T) {
	src := `spec_version = "` + Version + `"

threatmodel "Payments API" {
  author = "@security-team"

  mermaid "Login sequence" {
    content = <<-EOT
      sequenceDiagram
        U->>A: POST /auth
    EOT
  }

  mermaid "Token refresh" {
    description = "Refreshing the JWT"
    content = <<-EOT
      sequenceDiagram
        U->>A: POST /refresh
    EOT
  }
}
`
	p := parseRaw(t, src)
	tm := p.GetWrapped().Threatmodels[0]

	if len(tm.MermaidDiagrams) != 2 {
		t.Fatalf("expected 2 mermaid diagrams, got %d", len(tm.MermaidDiagrams))
	}
	if tm.MermaidDiagrams[0].Name != "Login sequence" {
		t.Errorf("first mermaid name = %q", tm.MermaidDiagrams[0].Name)
	}
	if tm.MermaidDiagrams[1].Name != "Token refresh" {
		t.Errorf("second mermaid name = %q", tm.MermaidDiagrams[1].Name)
	}
	if tm.MermaidDiagrams[0].Description != "" {
		t.Errorf("first mermaid should have no description, got %q", tm.MermaidDiagrams[0].Description)
	}
	if !strings.Contains(tm.MermaidDiagrams[1].Content, "POST /refresh") {
		t.Errorf("second mermaid content lost: %q", tm.MermaidDiagrams[1].Content)
	}
}

// TestMermaidHeredocBraces proves a heredoc body containing braces (a flowchart
// decision node and a class diagram body) is preserved verbatim through parsing
// and survives a full HCL round-trip without being mangled.
func TestMermaidHeredocBraces(t *testing.T) {
	src := `spec_version = "` + Version + `"

threatmodel "Braces" {
  author = "@me"

  mermaid "Decision flow" {
    content = <<-EOT
      flowchart TD
        A{Decision} -->|yes| B[Proceed]
        A -->|no| C[Stop]
    EOT
  }

  mermaid "Class shape" {
    content = <<-EOT
      classDiagram
        class Token {
          +String value
          +validate()
        }
    EOT
  }
}
`
	p := parseRaw(t, src)
	tm := p.GetWrapped().Threatmodels[0]

	if len(tm.MermaidDiagrams) != 2 {
		t.Fatalf("expected 2 mermaid diagrams, got %d", len(tm.MermaidDiagrams))
	}

	flow := tm.MermaidDiagrams[0].Content
	class := tm.MermaidDiagrams[1].Content

	for _, want := range []string{"flowchart TD", "A{Decision}", "B[Proceed]"} {
		if !strings.Contains(flow, want) {
			t.Errorf("flowchart content missing %q:\n%s", want, flow)
		}
	}
	for _, want := range []string{"classDiagram", "class Token {", "+validate()", "}"} {
		if !strings.Contains(class, want) {
			t.Errorf("class diagram content missing %q:\n%s", want, class)
		}
	}

	// Round-trip: emit HCL, parse it back, and assert the content values are
	// byte-for-byte identical to what we first parsed.
	p2 := reparse(t, p)
	tm2 := p2.GetWrapped().Threatmodels[0]
	if len(tm2.MermaidDiagrams) != 2 {
		t.Fatalf("round-trip lost mermaid diagrams, got %d", len(tm2.MermaidDiagrams))
	}
	if tm2.MermaidDiagrams[0].Content != flow {
		t.Errorf("flowchart content mangled across round-trip:\nbefore:\n%q\nafter:\n%q", flow, tm2.MermaidDiagrams[0].Content)
	}
	if tm2.MermaidDiagrams[1].Content != class {
		t.Errorf("class diagram content mangled across round-trip:\nbefore:\n%q\nafter:\n%q", class, tm2.MermaidDiagrams[1].Content)
	}
}

func TestRoundTripMermaidBlockSyntax(t *testing.T) {
	src := `spec_version = "` + Version + `"

threatmodel "Payments API" {
  author = "@security-team"

  mermaid "Login sequence" {
    description = "How the login flow works"
    content = <<-EOT
      sequenceDiagram
        U->>A: POST /auth
    EOT
  }
}
`
	p := parseRaw(t, src)

	out := p.HclString()
	if !strings.Contains(out, `mermaid "Login sequence"`) {
		t.Errorf("expected proper block syntax, got:\n%s", out)
	}
	if strings.Contains(out, "mermaid = [") {
		t.Errorf("output uses list-of-objects encoding instead of block syntax:\n%s", out)
	}

	p2 := reparse(t, p)
	tm := p2.GetWrapped().Threatmodels[0]
	if len(tm.MermaidDiagrams) != 1 {
		t.Fatalf("expected 1 mermaid diagram after round-trip, got %d", len(tm.MermaidDiagrams))
	}
	m := tm.MermaidDiagrams[0]
	if m.Name != "Login sequence" {
		t.Errorf("name = %q after round-trip", m.Name)
	}
	if m.Description != "How the login flow works" {
		t.Errorf("description = %q after round-trip", m.Description)
	}
	if !strings.Contains(m.Content, "POST /auth") {
		t.Errorf("content lost after round-trip: %q", m.Content)
	}
}

// TestMermaidMarkdownRender confirms the default markdown template emits each
// mermaid block's content inside a fenced ```mermaid code block.
func TestMermaidMarkdownRender(t *testing.T) {
	tm := &Threatmodel{
		Name:   "Payments API",
		Author: "@me",
		MermaidDiagrams: []*MermaidDiagram{
			{
				Name:        "Login sequence",
				Description: "How login works",
				Content:     "sequenceDiagram\n  U->>A: POST /auth\n",
			},
		},
	}

	buf, err := tm.RenderMarkdown(TmMDTemplate)
	if err != nil {
		t.Fatalf("render failed: %s", err)
	}
	out := new(strings.Builder)
	if _, err := io.Copy(out, buf); err != nil {
		t.Fatalf("copy failed: %s", err)
	}
	md := out.String()

	for _, want := range []string{
		"## Diagrams",
		"### Login sequence",
		"How login works",
		"```mermaid",
		"U->>A: POST /auth",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown missing %q:\n%s", want, md)
		}
	}
}

// TestMermaidOptionalDescription confirms an omitted description does not emit
// noise (description = "") in the round-tripped HCL.
func TestMermaidOptionalDescription(t *testing.T) {
	src := `spec_version = "` + Version + `"

threatmodel "NoDesc" {
  author = "@me"

  mermaid "diagram only" {
    content = <<-EOT
      graph LR
        A --> B
    EOT
  }
}
`
	p := parseRaw(t, src)
	out := p.HclString()
	if strings.Contains(out, "description") {
		t.Errorf("output should not emit an empty description:\n%s", out)
	}

	p2 := reparse(t, p)
	tm := p2.GetWrapped().Threatmodels[0]
	if len(tm.MermaidDiagrams) != 1 || tm.MermaidDiagrams[0].Description != "" {
		t.Errorf("expected single mermaid with empty description, got %+v", tm.MermaidDiagrams)
	}
}
