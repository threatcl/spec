package spec

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/hashicorp/hcl/v2/hclwrite"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/gocty"
)

// encodeWrappedToHCL renders a ThreatmodelWrapped to HCL bytes using a
// reflection-based walker that correctly emits repeated block syntax for
// []*Struct fields tagged `hcl:"...,block"`. gohcl.EncodeIntoBody only
// handles value-slice block fields and silently degrades pointer slices to
// list-of-objects attribute encoding (`control = [{...}]`), which doesn't
// round-trip through the parser.
func encodeWrappedToHCL(w *ThreatmodelWrapped) []byte {
	f := hclwrite.NewEmptyFile()
	encodeBody(f.Body(), reflect.ValueOf(w).Elem())
	return f.Bytes()
}

type hclTagInfo struct {
	name string
	kind string // "label", "attr", "optional", "block", or "" (treated as required attr)
	skip bool
}

func parseHclTag(t reflect.StructTag) hclTagInfo {
	raw := t.Get("hcl")
	if raw == "" || raw == "-" {
		return hclTagInfo{skip: true}
	}
	parts := strings.Split(raw, ",")
	info := hclTagInfo{name: parts[0]}
	if len(parts) > 1 {
		info.kind = parts[1]
	}
	return info
}

// encodeBody writes the fields of struct value v into body. Attributes are
// emitted before blocks so the output reads naturally.
func encodeBody(body *hclwrite.Body, v reflect.Value) {
	for v.Kind() == reflect.Pointer {
		if v.IsNil() {
			return
		}
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return
	}
	t := v.Type()

	for i := 0; i < t.NumField(); i++ {
		tag := parseHclTag(t.Field(i).Tag)
		if tag.skip || tag.kind == "label" || tag.kind == "block" {
			continue
		}
		fv := v.Field(i)
		if tag.kind == "optional" && isZeroForHcl(fv) {
			continue
		}
		val, ok := makeCtyValue(fv)
		if !ok {
			continue
		}
		body.SetAttributeValue(tag.name, val)
	}

	for i := 0; i < t.NumField(); i++ {
		tag := parseHclTag(t.Field(i).Tag)
		if tag.skip || tag.kind != "block" {
			continue
		}
		emitBlockField(body, tag.name, v.Field(i))
	}
}

func emitBlockField(parent *hclwrite.Body, name string, fv reflect.Value) {
	switch fv.Kind() {
	case reflect.Slice, reflect.Array:
		for i := 0; i < fv.Len(); i++ {
			elem := fv.Index(i)
			if elem.Kind() == reflect.Pointer && elem.IsNil() {
				continue
			}
			emitOneBlock(parent, name, elem)
		}
	case reflect.Pointer:
		if fv.IsNil() {
			return
		}
		emitOneBlock(parent, name, fv)
	case reflect.Struct:
		emitOneBlock(parent, name, fv)
	}
}

func emitOneBlock(parent *hclwrite.Body, typeName string, elem reflect.Value) {
	for elem.Kind() == reflect.Pointer {
		if elem.IsNil() {
			return
		}
		elem = elem.Elem()
	}
	if elem.Kind() != reflect.Struct {
		return
	}
	t := elem.Type()
	var labels []string
	for i := 0; i < t.NumField(); i++ {
		tag := parseHclTag(t.Field(i).Tag)
		if tag.kind == "label" {
			labels = append(labels, fmt.Sprintf("%v", elem.Field(i).Interface()))
		}
	}
	block := parent.AppendNewBlock(typeName, labels)
	encodeBody(block.Body(), elem)
}

// isZeroForHcl decides whether a field should be skipped when its hcl tag is
// optional. Nil/empty slices and maps count as zero so we don't emit
// `imports = null` or `stride = []` for unused optionals.
func isZeroForHcl(v reflect.Value) bool {
	switch v.Kind() {
	case reflect.String:
		return v.Len() == 0
	case reflect.Bool:
		return !v.Bool()
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return v.Int() == 0
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return v.Uint() == 0
	case reflect.Float32, reflect.Float64:
		return v.Float() == 0
	case reflect.Slice, reflect.Map:
		return v.IsNil() || v.Len() == 0
	case reflect.Pointer, reflect.Interface:
		return v.IsNil()
	case reflect.Struct:
		return v.IsZero()
	}
	return false
}

func makeCtyValue(v reflect.Value) (cty.Value, bool) {
	// A nil slice converts to cty.NullVal, which prints as `attr = null`.
	// Required slice attrs in the spec are rare/non-existent, but be safe
	// and emit an empty list of the element type instead.
	if v.Kind() == reflect.Slice && v.IsNil() {
		if ety, err := gocty.ImpliedType(reflect.New(v.Type().Elem()).Elem().Interface()); err == nil {
			return cty.ListValEmpty(ety), true
		}
	}
	iface := v.Interface()
	ty, err := gocty.ImpliedType(iface)
	if err != nil {
		return cty.NilVal, false
	}
	val, err := gocty.ToCtyValue(iface, ty)
	if err != nil {
		return cty.NilVal, false
	}
	return val, true
}
