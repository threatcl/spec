package spec

import (
	"strings"
	"testing"
)

func TestDfdD2ParallelFlows(t *testing.T) {
	tm := parallelFlowsDfdTm()
	dfd := tm.DataFlowDiagrams[0]

	out, err := dfd.GenerateD2(tm.Name, DfdRenderOptions{})
	if err != nil {
		t.Fatalf("Error generating d2: %s", err)
	}

	// D2 supports parallel edges natively — one `a -> b: "label"` per flow.
	if c := strings.Count(out, `-> n_server: "http"`); c != 1 {
		t.Errorf("expected 1 occurrence of `-> n_server: \"http\"`, got %d in:\n%s", c, out)
	}
	if c := strings.Count(out, `-> n_server: "websocket"`); c != 1 {
		t.Errorf("expected 1 occurrence of `-> n_server: \"websocket\"`, got %d in:\n%s", c, out)
	}
}

func TestDfdD2ProtocolStyles(t *testing.T) {
	dfd := protocolFlowsDfdTm()

	const amqpColor = "#E69F00"
	const httpsColor = "#56B4E9"

	cases := []struct {
		name      string
		style     ProtocolStyle
		expect    []string
		notExpect []string
	}{
		{
			name:  "label_default",
			style: ProtocolStyleLabel,
			expect: []string{
				`: "login (https)"`,
				`: "events (amqp)"`,
			},
			notExpect: []string{"style.stroke: \"#", "legend: "},
		},
		{
			name:  "none",
			style: ProtocolStyleNone,
			expect: []string{
				`: "login"`,
				`: "events"`,
			},
			notExpect: []string{"https", "amqp", "legend: "},
		},
		{
			name:  "color",
			style: ProtocolStyleColor,
			expect: []string{
				`: "login" { style.stroke: "` + httpsColor + `" }`,
				`: "events" { style.stroke: "` + amqpColor + `" }`,
				`legend: "Protocols" {`,
				`: "amqp" { style.stroke: "` + amqpColor + `" }`,
				`: "https" { style.stroke: "` + httpsColor + `" }`,
			},
			notExpect: []string{`"login (https)"`},
		},
		{
			name:  "both",
			style: ProtocolStyleBoth,
			expect: []string{
				`: "login (https)" { style.stroke: "` + httpsColor + `" }`,
				`legend: "Protocols" {`,
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got, err := dfd.GenerateD2("tm", DfdRenderOptions{ProtocolStyle: tc.style})
			if err != nil {
				t.Fatalf("GenerateD2: %s", err)
			}
			for _, want := range tc.expect {
				if !strings.Contains(got, want) {
					t.Errorf("expected %q in output:\n%s", want, got)
				}
			}
			for _, unwanted := range tc.notExpect {
				if strings.Contains(got, unwanted) {
					t.Errorf("did not expect %q in output:\n%s", unwanted, got)
				}
			}
		})
	}
}

func TestDfdD2Generate(t *testing.T) {
	cases := []struct {
		name string
		tm   *Threatmodel
		want []string
	}{
		{
			"valid_full_dfd",
			fullDfdTm(),
			[]string{"direction: right", "shape: circle", "shape: cylinder", "shape: rectangle", " -> "},
		},
		{
			"valid_full_dfd2",
			fullDfdTm2(),
			[]string{`z_zone1: "zone1"`, "style.stroke: red", "style.stroke-dash: 4"},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			for _, adfd := range tc.tm.DataFlowDiagrams {
				out, err := adfd.GenerateD2(tc.tm.Name, DfdRenderOptions{})
				if err != nil {
					t.Fatalf("%s: error generating d2: %s", tc.name, err)
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
