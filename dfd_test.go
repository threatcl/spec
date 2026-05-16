package spec

import (
	"io/ioutil"
	"os"
	"strings"
	"testing"
)

func dfdTm() *Threatmodel {
	tm := &Threatmodel{
		Name:   "test",
		Author: "x",
		DataFlowDiagrams: []*DataFlowDiagram{
			{
				Processes: []*DfdProcess{
					{
						Name: "proc1",
					},
				},
			},
		},
	}

	return tm
}

func fullDfdTm() *Threatmodel {

	tm := &Threatmodel{
		Name:   "test",
		Author: "x",
		DataFlowDiagrams: []*DataFlowDiagram{
			{
				Processes: []*DfdProcess{
					{
						Name: "proc1",
					},
					{
						Name:      "proc2",
						TrustZone: "zone1",
					},
				},
				DataStores: []*DfdData{
					{
						Name: "data1",
					},
					{
						Name:      "data2",
						TrustZone: "zone2",
					},
				},
				ExternalElements: []*DfdExternal{
					{
						Name: "external1",
					},
					{
						Name:      "external2",
						TrustZone: "zone3",
					},
				},
				Flows: []*DfdFlow{
					{
						Name: "flow",
						From: "proc1",
						To:   "data1",
					},
					{
						Name: "flow",
						From: "external1",
						To:   "proc1",
					},
					{
						Name: "flow",
						From: "data1",
						To:   "external1",
					},
				},
			},
		},
	}

	return tm

}

func fullDfdTm2() *Threatmodel {

	tm := &Threatmodel{
		Name:   "test",
		Author: "x",
		DataFlowDiagrams: []*DataFlowDiagram{
			{
				TrustZones: []*DfdTrustZone{
					{
						Name: "zone1",
						Processes: []*DfdProcess{
							{
								Name:      "proc2",
								TrustZone: "zone1",
							},
							{
								Name: "proc9",
							},
						},
						DataStores: []*DfdData{
							{
								Name: "new_data",
							},
						},
						ExternalElements: []*DfdExternal{
							{
								Name: "ee5",
							},
						},
					},
				},
				Processes: []*DfdProcess{
					{
						Name: "proc1",
					},
				},
				DataStores: []*DfdData{
					{
						Name: "data1",
					},
					{
						Name:      "data2",
						TrustZone: "zone2",
					},
				},
				ExternalElements: []*DfdExternal{
					{
						Name: "external1",
					},
					{
						Name:      "external2",
						TrustZone: "zone3",
					},
				},
				Flows: []*DfdFlow{
					{
						Name: "flow",
						From: "proc1",
						To:   "data1",
					},
					{
						Name: "flow",
						From: "external1",
						To:   "proc1",
					},
					{
						Name: "flow",
						From: "data1",
						To:   "external1",
					},
				},
			},
		},
	}

	return tm

}

// protocolFlowsDfdTm returns a diagram with two flows sharing a protocol and
// one with a different protocol. Exercises sorted color assignment and the
// legend dedup logic.
func protocolFlowsDfdTm() *DataFlowDiagram {
	return &DataFlowDiagram{
		Name: "proto",
		Processes: []*DfdProcess{
			{Name: "client"},
			{Name: "server"},
			{Name: "worker"},
		},
		Flows: []*DfdFlow{
			{Name: "login", From: "client", To: "server", Protocol: "https"},
			{Name: "events", From: "server", To: "worker", Protocol: "amqp"},
			{Name: "static", From: "client", To: "server", Protocol: "https"},
		},
	}
}

// parallelFlowsDfdTm returns a threatmodel with multiple flow blocks sharing
// the same from→to but distinct names. Used to verify that renderers emit
// parallel edges, one per flow, with each label intact.
func parallelFlowsDfdTm() *Threatmodel {
	return &Threatmodel{
		Name:   "test",
		Author: "x",
		DataFlowDiagrams: []*DataFlowDiagram{
			{
				Name: "parallel",
				Processes: []*DfdProcess{
					{Name: "client"},
					{Name: "server"},
				},
				Flows: []*DfdFlow{
					{Name: "http", From: "client", To: "server"},
					{Name: "websocket", From: "client", To: "server"},
				},
			},
		},
	}
}

func TestDfdDotParallelFlows(t *testing.T) {
	tm := parallelFlowsDfdTm()
	dfd := tm.DataFlowDiagrams[0]

	dotSrc, err := dfd.GenerateDot(tm.Name, DfdRenderOptions{})
	if err != nil {
		t.Fatalf("Error generating dot: %s", err)
	}

	// DOT supports parallel edges natively — one edge line per flow, each
	// carrying its own label.
	if c := strings.Count(dotSrc, `label="http"`); c != 1 {
		t.Errorf("expected 1 occurrence of label=\"http\", got %d in:\n%s", c, dotSrc)
	}
	if c := strings.Count(dotSrc, `label="websocket"`); c != 1 {
		t.Errorf("expected 1 occurrence of label=\"websocket\", got %d in:\n%s", c, dotSrc)
	}
}

func TestDfdDotProtocolStyles(t *testing.T) {
	dfd := protocolFlowsDfdTm()

	// Palette assignment is alphabetical on distinct protocols: amqp -> first
	// color (#E69F00), https -> second (#56B4E9).
	const amqpColor = "#E69F00"
	const httpsColor = "#56B4E9"

	cases := []struct {
		name     string
		style    ProtocolStyle
		expect   []string
		notExpect []string
	}{
		{
			name:  "label_default",
			style: ProtocolStyleLabel,
			expect: []string{
				`label="login (https)"`,
				`label="events (amqp)"`,
				`label="static (https)"`,
			},
			notExpect: []string{amqpColor, httpsColor, `label="Protocols"`},
		},
		{
			name:  "none",
			style: ProtocolStyleNone,
			expect: []string{
				`label="login"`,
				`label="events"`,
				`label="static"`,
			},
			notExpect: []string{"https", "amqp", `label="Protocols"`},
		},
		{
			name:  "color",
			style: ProtocolStyleColor,
			expect: []string{
				`label="login"`,
				amqpColor,
				httpsColor,
				`label="Protocols"`,
				`label="amqp"`,
				`label="https"`,
			},
			notExpect: []string{`label="login (https)"`},
		},
		{
			name:  "both",
			style: ProtocolStyleBoth,
			expect: []string{
				`label="login (https)"`,
				`label="events (amqp)"`,
				amqpColor,
				httpsColor,
				`label="Protocols"`,
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got, err := dfd.GenerateDot("tm", DfdRenderOptions{ProtocolStyle: tc.style})
			if err != nil {
				t.Fatalf("GenerateDot: %s", err)
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

func TestDfdDotGenerate(t *testing.T) {
	cases := []struct {
		name        string
		tm          *Threatmodel
		exp         string
		errorthrown bool
	}{
		{
			"valid_full_dfd",
			fullDfdTm(),
			"",
			false,
		},
		{
			"valid_full_dfd2",
			fullDfdTm2(),
			"",
			false,
		},
	}

	for _, tc := range cases {
		tc := tc

		t.Run(tc.name, func(t *testing.T) {
			// t.Parallel()

			d, err := ioutil.TempDir("", "")
			if err != nil {
				t.Fatalf("Error creating tmp dir: %s", err)
			}
			defer os.RemoveAll(d)

			for _, adfd := range tc.tm.DataFlowDiagrams {

				dot, err := adfd.GenerateDot(tc.tm.Name, DfdRenderOptions{})

				if err != nil {
					if !strings.Contains(err.Error(), tc.exp) {
						t.Errorf("%s: Error rendering png: %s", tc.name, err)
					}
				} else {
					if tc.errorthrown {
						t.Errorf("%s: an error was thrown when it shoulnd't have", tc.name)
					} else {
						if !strings.Contains(dot, "graph") {
							t.Errorf("%s: Could not find `graph` in DOT output", tc.name)
						}
					}
				}
			}
		})
	}
}
