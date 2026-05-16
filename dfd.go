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
func (d *DataFlowDiagram) GenerateDot(tmName string, opts DfdRenderOptions) (string, error) {
	g, err := d.buildDotGraph(tmName, opts)
	if err != nil {
		return "", err
	}
	return g.String(), nil
}

// GenerateDfdPng writes the DFD as a PNG to filepath.
func (d *DataFlowDiagram) GenerateDfdPng(filepath, tmName string, opts DfdRenderOptions) error {
	dotSrc, err := d.GenerateDot(tmName, opts)
	if err != nil {
		return err
	}
	return dotToPng([]byte(dotSrc), filepath)
}

// GenerateDfdSvg writes the DFD as an SVG to filepath.
func (d *DataFlowDiagram) GenerateDfdSvg(filepath, tmName string, opts DfdRenderOptions) error {
	dotSrc, err := d.GenerateDot(tmName, opts)
	if err != nil {
		return err
	}
	return dotToSvg([]byte(dotSrc), filepath)
}

// GenerateDfdPngBytes returns the DFD as PNG bytes.
func (d *DataFlowDiagram) GenerateDfdPngBytes(tmName string, opts DfdRenderOptions) ([]byte, error) {
	dotSrc, err := d.GenerateDot(tmName, opts)
	if err != nil {
		return nil, err
	}
	return dotToPngBytes([]byte(dotSrc))
}

// GenerateDfdSvgBytes returns the DFD as SVG bytes.
func (d *DataFlowDiagram) GenerateDfdSvgBytes(tmName string, opts DfdRenderOptions) ([]byte, error) {
	dotSrc, err := d.GenerateDot(tmName, opts)
	if err != nil {
		return nil, err
	}
	return dotToSvgBytes([]byte(dotSrc))
}

// generateDfdDot is the historical internal name used by tests; it stays as a
// thin wrapper around GenerateDot.
func (d *DataFlowDiagram) generateDfdDot(tmName string, opts DfdRenderOptions) (string, error) {
	return d.GenerateDot(tmName, opts)
}

func (d *DataFlowDiagram) buildDotGraph(tmName string, opts DfdRenderOptions) (*dot.Graph, error) {
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

	colors, legendOrder := assignProtocolColors(d.Flows)

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
		if label := flowLabel(flow, opts.ProtocolStyle); label != "" {
			edge.Attr("label", label)
		}
		if opts.ProtocolStyle.shouldColor() {
			if c, ok := colors[strings.TrimSpace(flow.Protocol)]; ok {
				edge.Attr("color", c)
				edge.Attr("fontcolor", c)
			}
		}
	}

	if opts.ProtocolStyle.shouldColor() && len(legendOrder) > 0 {
		addDotLegend(g, legendOrder, colors)
	}

	return g, nil
}

// addDotLegend builds a separate cluster_legend subgraph with one colored
// sample edge per protocol. Source/sink nodes are invisible so only the labeled
// edges show.
func addDotLegend(g *dot.Graph, protocols []string, colors map[string]string) {
	legend := g.Subgraph("cluster_legend", dot.ClusterOption{})
	legend.Attr("label", "Protocols")
	legend.Attr("style", "dashed")
	legend.Attr("color", "gray")
	legend.Attr("fontcolor", "gray")

	for i, p := range protocols {
		src := legend.Node(fmt.Sprintf("legend_src_%d", i)).
			Attr("shape", "point").
			Attr("style", "invis").
			Attr("width", "0").
			Attr("height", "0")
		dst := legend.Node(fmt.Sprintf("legend_dst_%d", i)).
			Attr("shape", "point").
			Attr("style", "invis").
			Attr("width", "0").
			Attr("height", "0")
		legend.Edge(src, dst).
			Attr("label", p).
			Attr("color", colors[p]).
			Attr("fontcolor", colors[p])
	}
}
