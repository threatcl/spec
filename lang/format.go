package lang

import (
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclwrite"
)

// Format canonically formats a threatcl document. It applies purely lexical
// formatting (indentation and spacing) via hclwrite.Format, which preserves
// comments and never resolves imports, merges blocks, or re-orders — the
// behaviour an editor's format-on-save expects.
//
// If src has fatal syntax errors it cannot be formatted safely, so the original
// bytes are returned unchanged alongside the diagnostics. (This is distinct from
// the spec package's HclString encoder, which semantically round-trips a parsed
// model and is therefore unsuitable for format-on-save.)
func Format(filename string, src []byte) ([]byte, hcl.Diagnostics) {
	if _, diags := ParseSource(filename, src); diags.HasErrors() {
		return src, diags
	}
	return hclwrite.Format(src), nil
}
