package spec

import (
	"sort"
	"strings"
)

// ProtocolStyle controls how the optional `protocol` attribute on a DfdFlow is
// surfaced in rendered diagrams.
type ProtocolStyle int

const (
	// ProtocolStyleLabel appends " (protocol)" to each flow's label. Default.
	ProtocolStyleLabel ProtocolStyle = iota
	// ProtocolStyleNone ignores the protocol attribute entirely.
	ProtocolStyleNone
	// ProtocolStyleColor colors each flow's edge by protocol and emits a legend.
	ProtocolStyleColor
	// ProtocolStyleBoth combines Label and Color: appended labels plus colored
	// edges and a legend.
	ProtocolStyleBoth
)

// DfdRenderOptions configures how a DataFlowDiagram is rendered. The zero
// value (ProtocolStyleLabel) preserves the simplest behavior: protocol shown
// inline in labels, no color machinery.
type DfdRenderOptions struct {
	ProtocolStyle ProtocolStyle
}

// Okabe-Ito colorblind-safe palette. Eight distinct hues; protocols beyond
// the palette length wrap around.
var protocolPalette = []string{
	"#E69F00",
	"#56B4E9",
	"#009E73",
	"#F0E442",
	"#0072B2",
	"#D55E00",
	"#CC79A7",
	"#000000",
}

// assignProtocolColors collects the distinct, non-empty protocols across the
// given flows, sorts them alphabetically, and assigns palette colors in order.
// Returns the protocol->color map plus the sorted slice for stable legend
// ordering.
func assignProtocolColors(flows []*DfdFlow) (map[string]string, []string) {
	seen := map[string]bool{}
	var protocols []string
	for _, f := range flows {
		p := strings.TrimSpace(f.Protocol)
		if p == "" || seen[p] {
			continue
		}
		seen[p] = true
		protocols = append(protocols, p)
	}
	sort.Strings(protocols)
	colors := make(map[string]string, len(protocols))
	for i, p := range protocols {
		colors[p] = protocolPalette[i%len(protocolPalette)]
	}
	return colors, protocols
}

// flowLabel produces the rendered label for a flow under the given style.
// Returns an empty string when there is nothing to render (no name and the
// style suppresses the protocol).
func flowLabel(f *DfdFlow, style ProtocolStyle) string {
	name := strings.TrimSpace(f.Name)
	protocol := strings.TrimSpace(f.Protocol)
	showProtocol := protocol != "" && (style == ProtocolStyleLabel || style == ProtocolStyleBoth)
	switch {
	case name != "" && showProtocol:
		return name + " (" + protocol + ")"
	case name != "":
		return name
	case showProtocol:
		return "(" + protocol + ")"
	default:
		return ""
	}
}

// shouldColor reports whether edges should be styled with protocol colors.
func (s ProtocolStyle) shouldColor() bool {
	return s == ProtocolStyleColor || s == ProtocolStyleBoth
}
