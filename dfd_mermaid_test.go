package spec

import (
	"strings"
	"testing"
)

func TestDfdMermaidGenerate(t *testing.T) {
	cases := []struct {
		name string
		tm   *Threatmodel
		want []string
	}{
		{
			"valid_full_dfd",
			fullDfdTm(),
			[]string{"flowchart LR", `n_proc1(("proc1"))`, `n_data1[("data1")]`, `n_external1{"external1"}`, "-->"},
		},
		{
			"valid_full_dfd2",
			fullDfdTm2(),
			[]string{"flowchart LR", `subgraph z_zone1 ["zone1"]`, `n_proc2(("proc2"))`, "end"},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			for _, adfd := range tc.tm.DataFlowDiagrams {
				out, err := adfd.GenerateMermaid(tc.tm.Name)
				if err != nil {
					t.Fatalf("%s: error generating mermaid: %s", tc.name, err)
				}
				for _, frag := range tc.want {
					if !strings.Contains(out, frag) {
						t.Errorf("%s: expected output to contain %q, got:\n%s", tc.name, frag, out)
					}
				}
			}
		})
	}
}

func TestDfdMermaidParallelFlows(t *testing.T) {
	tm := parallelFlowsDfdTm()
	dfd := tm.DataFlowDiagrams[0]

	out, err := dfd.GenerateMermaid(tm.Name)
	if err != nil {
		t.Fatalf("Error generating mermaid: %s", err)
	}

	// Mermaid renders parallel edges as separate `a -- "label" --> b` lines.
	if c := strings.Count(out, `-- "http" -->`); c != 1 {
		t.Errorf("expected 1 occurrence of `-- \"http\" -->`, got %d in:\n%s", c, out)
	}
	if c := strings.Count(out, `-- "websocket" -->`); c != 1 {
		t.Errorf("expected 1 occurrence of `-- \"websocket\" -->`, got %d in:\n%s", c, out)
	}
}

func TestDfdMermaidUnknownFlowEndpoint(t *testing.T) {
	tm := &Threatmodel{
		Name: "broken",
		DataFlowDiagrams: []*DataFlowDiagram{{
			Processes: []*DfdProcess{{Name: "p1"}},
			Flows:     []*DfdFlow{{Name: "flow", From: "p1", To: "ghost"}},
		}},
	}
	_, err := tm.DataFlowDiagrams[0].GenerateMermaid(tm.Name)
	if err == nil {
		t.Fatal("expected error for unknown flow endpoint, got nil")
	}
	if !strings.Contains(err.Error(), "ghost") {
		t.Errorf("expected error to mention the missing node, got: %s", err)
	}
}
