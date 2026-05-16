package spec

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/emicklei/dot"
)

// DFD shape conventions, matching the legacy xntrik/go-dfd defaults so existing
// diagrams keep their look-and-feel.
const (
	processShape  = "circle"
	externalShape = "diamond"
	dataStoreCap  = "cylinder"

	processFill  = "#9ed3ff"
	externalFill = "#ffd59e"
	dataStoreFill = "#fffb9e"

	trustBoundaryColor = "red"
)

var safeIDPattern = regexp.MustCompile(`[^a-zA-Z0-9_]+`)

func safeID(prefix, name string) string {
	clean := safeIDPattern.ReplaceAllString(name, "_")
	return fmt.Sprintf("%s_%s", prefix, clean)
}

// GenerateDot returns the DFD rendered as Graphviz DOT source.
func (d *DataFlowDiagram) GenerateDot(tmName string) (string, error) {
	g, err := d.buildDotGraph(tmName)
	if err != nil {
		return "", err
	}
	return g.String(), nil
}

// GenerateDfdPng writes the DFD as a PNG to filepath.
func (d *DataFlowDiagram) GenerateDfdPng(filepath, tmName string) error {
	dotSrc, err := d.GenerateDot(tmName)
	if err != nil {
		return err
	}
	return dotToPng([]byte(dotSrc), filepath)
}

// GenerateDfdSvg writes the DFD as an SVG to filepath.
func (d *DataFlowDiagram) GenerateDfdSvg(filepath, tmName string) error {
	dotSrc, err := d.GenerateDot(tmName)
	if err != nil {
		return err
	}
	return dotToSvg([]byte(dotSrc), filepath)
}

// GenerateDfdPngBytes returns the DFD as PNG bytes.
func (d *DataFlowDiagram) GenerateDfdPngBytes(tmName string) ([]byte, error) {
	dotSrc, err := d.GenerateDot(tmName)
	if err != nil {
		return nil, err
	}
	return dotToPngBytes([]byte(dotSrc))
}

// GenerateDfdSvgBytes returns the DFD as SVG bytes.
func (d *DataFlowDiagram) GenerateDfdSvgBytes(tmName string) ([]byte, error) {
	dotSrc, err := d.GenerateDot(tmName)
	if err != nil {
		return nil, err
	}
	return dotToSvgBytes([]byte(dotSrc))
}

// generateDfdDot is the historical internal name used by tests; it stays as a
// thin wrapper around GenerateDot.
func (d *DataFlowDiagram) generateDfdDot(tmName string) (string, error) {
	return d.GenerateDot(tmName)
}

func (d *DataFlowDiagram) buildDotGraph(tmName string) (*dot.Graph, error) {
	g := dot.NewGraph(dot.Directed)
	g.Attr("label", fmt.Sprintf("%s_%s", tmName, d.Name))
	g.Attr("labelloc", "t")
	g.Attr("rankdir", "LR")

	nodes := map[string]dot.Node{}
	zones := map[string]*dot.Graph{}

	getOrCreateZone := func(name string) *dot.Graph {
		if z, ok := zones[name]; ok {
			return z
		}
		sub := g.Subgraph(safeID("cluster", name), dot.ClusterOption{})
		sub.Attr("label", name)
		sub.Attr("style", "dashed")
		sub.Attr("color", trustBoundaryColor)
		sub.Attr("fontcolor", trustBoundaryColor)
		zones[name] = sub
		return sub
	}

	addProcess := func(parent *dot.Graph, name string) {
		if _, exists := nodes[name]; exists {
			return
		}
		n := parent.Node(name).
			Attr("shape", processShape).
			Attr("style", "filled").
			Attr("fillcolor", processFill)
		nodes[name] = n
	}

	addExternal := func(parent *dot.Graph, name string) {
		if _, exists := nodes[name]; exists {
			return
		}
		n := parent.Node(name).
			Attr("shape", externalShape).
			Attr("style", "filled").
			Attr("fillcolor", externalFill)
		nodes[name] = n
	}

	addDataStore := func(parent *dot.Graph, name string) {
		if _, exists := nodes[name]; exists {
			return
		}
		n := parent.Node(name).
			Attr("shape", dataStoreCap).
			Attr("style", "filled").
			Attr("fillcolor", dataStoreFill)
		nodes[name] = n
	}

	for _, zone := range d.TrustZones {
		z := getOrCreateZone(zone.Name)
		for _, p := range zone.Processes {
			addProcess(z, p.Name)
		}
		for _, e := range zone.ExternalElements {
			addExternal(z, e.Name)
		}
		for _, s := range zone.DataStores {
			addDataStore(z, s.Name)
		}
	}

	for _, p := range d.Processes {
		parent := g
		if p.TrustZone != "" {
			parent = getOrCreateZone(p.TrustZone)
		}
		addProcess(parent, p.Name)
	}

	for _, e := range d.ExternalElements {
		parent := g
		if e.TrustZone != "" {
			parent = getOrCreateZone(e.TrustZone)
		}
		addExternal(parent, e.Name)
	}

	for _, s := range d.DataStores {
		parent := g
		if s.TrustZone != "" {
			parent = getOrCreateZone(s.TrustZone)
		}
		addDataStore(parent, s.Name)
	}

	for _, flow := range d.Flows {
		from, fromOK := nodes[flow.From]
		to, toOK := nodes[flow.To]
		if !fromOK {
			return nil, fmt.Errorf("flow %q references unknown source node %q", flow.Name, flow.From)
		}
		if !toOK {
			return nil, fmt.Errorf("flow %q references unknown destination node %q", flow.Name, flow.To)
		}
		edge := g.Edge(from, to)
		if strings.TrimSpace(flow.Name) != "" {
			edge.Attr("label", flow.Name)
		}
	}

	return g, nil
}
