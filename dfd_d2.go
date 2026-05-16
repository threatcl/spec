package spec

import (
	"fmt"
	"strings"
)

// GenerateD2 returns the DFD rendered as D2 source
// (https://d2lang.com). The text can be rendered to SVG/PNG with the d2 CLI or
// the d2lib Go library; this emitter only produces source so the package keeps
// its small dependency footprint.
func (d *DataFlowDiagram) GenerateD2(tmName string) (string, error) {
	idMap := map[string]string{}
	d2ID := func(name string) string {
		if id, ok := idMap[name]; ok {
			return id
		}
		id := safeID("n", name)
		idMap[name] = id
		return id
	}

	type d2Node struct {
		name string
		kind mermaidNodeKind
		zone string
	}

	var nodes []d2Node
	seen := map[string]bool{}
	add := func(name string, kind mermaidNodeKind, zone string) {
		if seen[name] {
			return
		}
		seen[name] = true
		nodes = append(nodes, d2Node{name, kind, zone})
	}

	for _, zone := range d.TrustZones {
		for _, p := range zone.Processes {
			add(p.Name, mermaidProcess, zone.Name)
		}
		for _, e := range zone.ExternalElements {
			add(e.Name, mermaidExternal, zone.Name)
		}
		for _, s := range zone.DataStores {
			add(s.Name, mermaidDataStore, zone.Name)
		}
	}
	for _, p := range d.Processes {
		add(p.Name, mermaidProcess, p.TrustZone)
	}
	for _, e := range d.ExternalElements {
		add(e.Name, mermaidExternal, e.TrustZone)
	}
	for _, s := range d.DataStores {
		add(s.Name, mermaidDataStore, s.TrustZone)
	}

	zoneOrder := []string{}
	zoneMembers := map[string][]d2Node{}
	var zoneless []d2Node
	for _, n := range nodes {
		if n.zone == "" {
			zoneless = append(zoneless, n)
			continue
		}
		if _, exists := zoneMembers[n.zone]; !exists {
			zoneOrder = append(zoneOrder, n.zone)
		}
		zoneMembers[n.zone] = append(zoneMembers[n.zone], n)
	}

	var b strings.Builder
	fmt.Fprintf(&b, "# %s_%s\n", tmName, d.Name)
	b.WriteString("direction: right\n\n")

	// fully-qualified id used when emitting flows (zone.node or node)
	fqid := map[string]string{}

	writeNode := func(indent, container string, n d2Node) {
		id := d2ID(n.name)
		var shape string
		switch n.kind {
		case mermaidProcess:
			shape = "circle"
		case mermaidExternal:
			shape = "rectangle"
		case mermaidDataStore:
			shape = "cylinder"
		}
		fmt.Fprintf(&b, "%s%s: %q {\n", indent, id, n.name)
		fmt.Fprintf(&b, "%s  shape: %s\n", indent, shape)
		fmt.Fprintf(&b, "%s}\n", indent)
		if container == "" {
			fqid[n.name] = id
		} else {
			fqid[n.name] = container + "." + id
		}
	}

	for _, zoneName := range zoneOrder {
		zID := safeID("z", zoneName)
		fmt.Fprintf(&b, "%s: %q {\n", zID, zoneName)
		b.WriteString("  style.stroke: red\n")
		b.WriteString("  style.stroke-dash: 4\n")
		for _, n := range zoneMembers[zoneName] {
			writeNode("  ", zID, n)
		}
		b.WriteString("}\n\n")
	}
	for _, n := range zoneless {
		writeNode("", "", n)
	}
	if len(zoneless) > 0 {
		b.WriteString("\n")
	}

	for _, flow := range d.Flows {
		from, fromOK := fqid[flow.From]
		to, toOK := fqid[flow.To]
		if !fromOK {
			return "", fmt.Errorf("flow %q references unknown source node %q", flow.Name, flow.From)
		}
		if !toOK {
			return "", fmt.Errorf("flow %q references unknown destination node %q", flow.Name, flow.To)
		}
		label := strings.TrimSpace(flow.Name)
		if label == "" {
			fmt.Fprintf(&b, "%s -> %s\n", from, to)
		} else {
			fmt.Fprintf(&b, "%s -> %s: %q\n", from, to, label)
		}
	}

	return b.String(), nil
}
