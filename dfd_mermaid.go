package spec

import (
	"fmt"
	"strings"
)

type mermaidNodeKind int

const (
	mermaidProcess mermaidNodeKind = iota
	mermaidExternal
	mermaidDataStore
)

type mermaidNode struct {
	name string
	kind mermaidNodeKind
	zone string
}

// GenerateMermaid returns the DFD rendered as a Mermaid flowchart. The output
// is plain text suitable for embedding in Markdown rendered by GitHub, GitLab,
// or any Mermaid-aware viewer.
func (d *DataFlowDiagram) GenerateMermaid(tmName string) (string, error) {
	idMap := map[string]string{}
	mermaidID := func(name string) string {
		if id, ok := idMap[name]; ok {
			return id
		}
		id := safeID("n", name)
		idMap[name] = id
		return id
	}

	// Collect every node along with the zone it belongs to. Order of first
	// appearance is preserved so the rendered output is stable.
	var nodes []mermaidNode
	seen := map[string]bool{}
	add := func(name string, kind mermaidNodeKind, zone string) {
		if seen[name] {
			return
		}
		seen[name] = true
		nodes = append(nodes, mermaidNode{name, kind, zone})
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

	// Group by zone, preserving first-appearance order.
	zoneOrder := []string{}
	zoneMembers := map[string][]mermaidNode{}
	var zoneless []mermaidNode
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
	fmt.Fprintf(&b, "%%%% %s_%s\n", tmName, d.Name)
	b.WriteString("flowchart LR\n")

	writeNode := func(indent string, n mermaidNode) {
		id := mermaidID(n.name)
		switch n.kind {
		case mermaidProcess:
			fmt.Fprintf(&b, "%s%s((%q))\n", indent, id, n.name)
		case mermaidExternal:
			fmt.Fprintf(&b, "%s%s{%q}\n", indent, id, n.name)
		case mermaidDataStore:
			fmt.Fprintf(&b, "%s%s[(%q)]\n", indent, id, n.name)
		}
	}

	for _, zoneName := range zoneOrder {
		fmt.Fprintf(&b, "  subgraph %s [%q]\n", safeID("z", zoneName), zoneName)
		for _, n := range zoneMembers[zoneName] {
			writeNode("    ", n)
		}
		b.WriteString("  end\n")
	}
	for _, n := range zoneless {
		writeNode("  ", n)
	}

	for _, flow := range d.Flows {
		if _, ok := idMap[flow.From]; !ok {
			return "", fmt.Errorf("flow %q references unknown source node %q", flow.Name, flow.From)
		}
		if _, ok := idMap[flow.To]; !ok {
			return "", fmt.Errorf("flow %q references unknown destination node %q", flow.Name, flow.To)
		}
		label := strings.TrimSpace(flow.Name)
		if label == "" {
			fmt.Fprintf(&b, "  %s --> %s\n", mermaidID(flow.From), mermaidID(flow.To))
		} else {
			fmt.Fprintf(&b, "  %s -- %q --> %s\n", mermaidID(flow.From), label, mermaidID(flow.To))
		}
	}

	return b.String(), nil
}
