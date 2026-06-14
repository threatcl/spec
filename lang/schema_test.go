package lang

import (
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/threatcl/spec"
)

// TestSchemaDriftGuard is the keystone test for this package: it derives the
// "true" schema directly from the spec struct tags via reflection and asserts a
// two-way match against the hand-authored Schema(). Any block/attribute added
// to (or removed from) the spec structs without a matching Schema() edit fails
// here, so the descriptor — and the docs/completion/hover that ride on it — can
// never silently drift out of sync with the format.
//
// It deliberately ignores Doc, Type, and EnumValues (those are authored, not
// derivable from tags); it checks block/attribute presence, label names,
// repeatability, and required-vs-optional.
func TestSchemaDriftGuard(t *testing.T) {
	ref := reflectBody(reflect.TypeFor[spec.ThreatmodelWrapped]())
	got := *Schema()

	diffs := diffBody("(root)", ref, got)
	if len(diffs) > 0 {
		sort.Strings(diffs)
		t.Fatalf("Schema() drifted from spec struct tags:\n  - %s", strings.Join(diffs, "\n  - "))
	}
}

// TestSchemaEnumsPopulated guards that the attributes we advertise as enums
// actually carry a non-empty value set seeded from the spec config / risk vars.
func TestSchemaEnumsPopulated(t *testing.T) {
	want := map[string]string{
		"threatmodel/attributes/initiative_size":                   "",
		"threatmodel/information_asset/information_classification": "",
		"threatmodel/threat/impacts":                               "",
		"threatmodel/threat/stride":                                "",
		"threatmodel/threat/risk/likelihood":                       "",
		"threatmodel/threat/risk/impact":                           "",
		"threatmodel/threat/risk/severity":                         "",
		"threatmodel/third_party_dependency/uptime_dependency":     "",
	}
	for path := range want {
		if a := lookupAttr(Schema(), path); a == nil {
			t.Errorf("enum attr %q not found in Schema()", path)
		} else if len(a.EnumValues) == 0 {
			t.Errorf("enum attr %q has no EnumValues", path)
		}
	}
}

// lookupAttr resolves a "block/block/attr" path against a BodySchema.
func lookupAttr(bs *BodySchema, path string) *AttrSchema {
	parts := strings.Split(path, "/")
	cur := bs
	for _, p := range parts[:len(parts)-1] {
		var next *BodySchema
		for i := range cur.Blocks {
			if cur.Blocks[i].Type == p {
				next = &cur.Blocks[i].Body
				break
			}
		}
		if next == nil {
			return nil
		}
		cur = next
	}
	leaf := parts[len(parts)-1]
	for i := range cur.Attrs {
		if cur.Attrs[i].Name == leaf {
			return &cur.Attrs[i]
		}
	}
	return nil
}

// reflectBody builds a reference BodySchema (presence/labels/repeatable/required
// only) from a struct type's hcl tags, recursing into nested block structs.
func reflectBody(t reflect.Type) BodySchema {
	var bs BodySchema
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		name, kind, ok := parseHCLFieldTag(f.Tag.Get("hcl"))
		if !ok {
			continue
		}
		switch kind {
		case "label":
			// Labels belong to the parent block header, gathered separately.
			continue
		case "block":
			et := elemStruct(f.Type)
			bs.Blocks = append(bs.Blocks, BlockSchema{
				Type:       name,
				Labels:     structLabels(et),
				Repeatable: f.Type.Kind() == reflect.Slice || f.Type.Kind() == reflect.Array,
				Body:       reflectBody(et),
			})
		default:
			// "attr", "optional", or "" (a bare required attribute).
			bs.Attrs = append(bs.Attrs, AttrSchema{Name: name, Required: kind != "optional"})
		}
	}
	return bs
}

// parseHCLFieldTag splits an `hcl:"name,kind"` tag. ok is false for untagged or
// `-` fields (which carry no HCL representation).
func parseHCLFieldTag(raw string) (name, kind string, ok bool) {
	if raw == "" || raw == "-" {
		return "", "", false
	}
	parts := strings.Split(raw, ",")
	if len(parts) > 1 {
		return parts[0], parts[1], true
	}
	return parts[0], "", true
}

// structLabels returns the label field names of a block struct, in order.
func structLabels(t reflect.Type) []string {
	var labels []string
	for i := 0; i < t.NumField(); i++ {
		name, kind, ok := parseHCLFieldTag(t.Field(i).Tag.Get("hcl"))
		if ok && kind == "label" {
			labels = append(labels, name)
		}
	}
	return labels
}

func elemStruct(t reflect.Type) reflect.Type {
	for t.Kind() == reflect.Slice || t.Kind() == reflect.Array || t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	return t
}

// diffBody recursively reports every difference between a reflected reference
// body and the authored body, as human-readable lines (empty == in sync).
func diffBody(path string, ref, got BodySchema) []string {
	var diffs []string

	refAttr := indexAttrs(ref.Attrs)
	gotAttr := indexAttrs(got.Attrs)
	for name, ra := range refAttr {
		ga, ok := gotAttr[name]
		if !ok {
			diffs = append(diffs, path+": attr "+name+" has a struct tag but is missing from Schema()")
			continue
		}
		if ra.Required != ga.Required {
			diffs = append(diffs, path+"."+name+": required mismatch (structs="+b2s(ra.Required)+" schema="+b2s(ga.Required)+")")
		}
	}
	for name := range gotAttr {
		if _, ok := refAttr[name]; !ok {
			diffs = append(diffs, path+": attr "+name+" is in Schema() but has no struct tag")
		}
	}

	refBlk := indexBlocks(ref.Blocks)
	gotBlk := indexBlocks(got.Blocks)
	for typ, rb := range refBlk {
		gb, ok := gotBlk[typ]
		if !ok {
			diffs = append(diffs, path+": block "+typ+" has a struct tag but is missing from Schema()")
			continue
		}
		if !equalStrings(rb.Labels, gb.Labels) {
			diffs = append(diffs, path+"/"+typ+": labels mismatch (structs="+strings.Join(rb.Labels, ",")+" schema="+strings.Join(gb.Labels, ",")+")")
		}
		if rb.Repeatable != gb.Repeatable {
			diffs = append(diffs, path+"/"+typ+": repeatable mismatch (structs="+b2s(rb.Repeatable)+" schema="+b2s(gb.Repeatable)+")")
		}
		diffs = append(diffs, diffBody(path+"/"+typ, rb.Body, gb.Body)...)
	}
	for typ := range gotBlk {
		if _, ok := refBlk[typ]; !ok {
			diffs = append(diffs, path+": block "+typ+" is in Schema() but has no struct tag")
		}
	}

	return diffs
}

func indexAttrs(as []AttrSchema) map[string]AttrSchema {
	m := make(map[string]AttrSchema, len(as))
	for _, a := range as {
		m[a.Name] = a
	}
	return m
}

func indexBlocks(bs []BlockSchema) map[string]BlockSchema {
	m := make(map[string]BlockSchema, len(bs))
	for _, b := range bs {
		m[b.Type] = b
	}
	return m
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func b2s(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
