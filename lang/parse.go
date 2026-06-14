// Package lang provides language-server primitives for threatcl threat models:
// error-tolerant positional parsing, an explicit (drift-guarded) schema model
// with docs, range-carrying diagnostics, and completion/hover/symbol/format
// computation.
//
// It is the language-intelligence layer beneath an LSP server (see the
// `threatcl lsp` subcommand in the threatcl/threatcl repo). Everything here
// speaks plain Go plus hashicorp/hcl types only — no LSP/JSON-RPC protocol
// types ever enter this package, and nothing here writes to stdout/stderr
// (stdout is the LSP transport, so chatter would corrupt the protocol). The
// CLI translates these neutral results into LSP protocol types.
package lang

import (
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
)

// ParsedFile is the result of an error-tolerant parse. It keeps the
// token-level hclsyntax AST (whose nodes all carry hcl.Range positions) so the
// completion/hover/symbol passes can locate a cursor without re-parsing, and it
// retains the syntax diagnostics rather than discarding the file on the first
// error.
type ParsedFile struct {
	Filename string
	Src      []byte
	File     *hcl.File
	Body     *hclsyntax.Body
	// Diags holds syntax diagnostics gathered during parsing. They are kept,
	// not fatal: a half-typed document still yields a (partial) Body.
	Diags hcl.Diagnostics
}

// ParseSource parses src with hclsyntax and returns a ParsedFile plus the
// syntax diagnostics. The diagnostics are also stored on the returned
// ParsedFile (pf.Diags); they are returned separately too so callers that only
// want "did this parse cleanly" don't have to reach into the struct.
//
// Even when diagnostics contain errors, the returned *ParsedFile is non-nil and
// its Body is the best-effort AST hclsyntax could recover, so downstream
// interaction features keep working on incomplete input.
func ParseSource(filename string, src []byte) (*ParsedFile, hcl.Diagnostics) {
	file, diags := hclsyntax.ParseConfig(src, filename, hcl.InitialPos)

	pf := &ParsedFile{
		Filename: filename,
		Src:      src,
		File:     file,
		Diags:    diags,
	}
	if file != nil {
		// hclsyntax.ParseConfig always returns an *hcl.File whose Body is a
		// *hclsyntax.Body; the assertion is safe but guarded so a future
		// change can't panic the LSP.
		if body, ok := file.Body.(*hclsyntax.Body); ok {
			pf.Body = body
		}
	}
	return pf, diags
}
