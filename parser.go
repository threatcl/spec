package spec

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/davecgh/go-spew/spew"
	"github.com/hashicorp/go-multierror"
	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/gohcl"
	"github.com/hashicorp/hcl/v2/hclparse"
	"github.com/zclconf/go-cty/cty"
)

type ThreatmodelParser struct {
	initiativeSizeOptions          map[string]bool
	defaultInitiativeSize          string
	infoClassifications            map[string]bool
	impactTypes                    map[string]bool
	strideElements                 map[string]bool
	riskLevels                     map[string]bool
	severityLevels                 map[string]bool
	uptimeDepClassification        map[string]bool
	defaultUptimeDepClassification UptimeDependencyClassification
	defaultInfoClassification      string
	wrapped                        *ThreatmodelWrapped
	specCfg                        *ThreatmodelSpecConfig
	skipExtendsResolution          bool
}

func NewThreatmodelParser(cfg *ThreatmodelSpecConfig) *ThreatmodelParser {
	tmParser := &ThreatmodelParser{
		initiativeSizeOptions:   map[string]bool{},
		infoClassifications:     map[string]bool{},
		impactTypes:             map[string]bool{},
		strideElements:          map[string]bool{},
		riskLevels:              map[string]bool{},
		severityLevels:          map[string]bool{},
		uptimeDepClassification: map[string]bool{},
		wrapped:                 &ThreatmodelWrapped{},
		specCfg:                 cfg,
	}
	tmParser.populateInitiativeSizeOptions()
	tmParser.populateInfoClassifications()
	tmParser.populateImpactTypes()
	tmParser.populateStrideElements()
	tmParser.populateRiskLevels()
	tmParser.populateSeverityLevels()
	tmParser.populateUptimeDepClassifications()
	return tmParser
}

func (p *ThreatmodelParser) GetWrapped() *ThreatmodelWrapped {
	return p.wrapped
}

// SetSkipExtendsResolution controls whether parsing resolves `extends`
// inheritance across the parsed content. When skipped, an extends target
// missing from the parsed content is not an error and no inherited entities
// are materialized — the Extends field stays populated for the consumer to
// resolve later, so a single file of a multi-file set can be parsed
// file-faithfully. All other validation and normalization is unchanged.
func (p *ThreatmodelParser) SetSkipExtendsResolution(skip bool) {
	p.skipExtendsResolution = skip
}

func (p *ThreatmodelParser) HclString() string {
	for _, tm := range p.wrapped.Threatmodels {
		for _, threat := range tm.Threats {
			threat.ControlImports = nil
			// ExpandedControls are merged into Controls during parsing
			// (see processControlImports); clearing here prevents the
			// round-tripped HCL from duplicating them as both `control`
			// and `expanded_control` blocks.
			threat.ExpandedControls = nil
		}
	}
	return string(encodeWrappedToHCL(p.wrapped))
}

func (p *ThreatmodelParser) AddTMAndWrite(tm Threatmodel, f io.Writer, debug bool) error {

	if debug {
		spew.Dump(tm)
	}

	// A declared id gets the same validation here as at parse time:
	// identifier-safe, and unique against the models already in the set.
	if tm.Id != "" {
		if !ValidIdentifier(tm.Id) {
			return fmt.Errorf(
				"TM '%s': invalid id '%s' - must be dot-separated segments of lowercase letters, digits or underscores, each starting with a letter",
				tm.Name,
				tm.Id,
			)
		}
		for _, existing := range p.wrapped.Threatmodels {
			if existing.Id == tm.Id {
				return fmt.Errorf(
					"TM '%s': duplicate id '%s'",
					tm.Name,
					tm.Id,
				)
			}
		}
	}

	if p.wrapped.SpecVersion == "" {
		// We haven't yet set the SpecVersion for this model, which may mean that we're adding a new TM to an existing wrapped object. Let's set it from the loaded CFG
		p.wrapped.SpecVersion = p.specCfg.Version
	}

	p.wrapped.Threatmodels = append(p.wrapped.Threatmodels, tm)

	w := bufio.NewWriter(f)
	defer w.Flush()
	_, err := w.Write(encodeWrappedToHCL(p.wrapped))
	if err != nil {
		return err
	}

	return nil
}

func (p *ThreatmodelParser) validateTms() error {
	// Validating all the threatmodels
	var errMap error
	tmMap := make(map[string]interface{})

	newWrapped := []Threatmodel{}
	for _, t := range p.wrapped.Threatmodels {
		t.shiftLegacyDfd()
		newWrapped = append(newWrapped, t)
	}

	p.wrapped.Threatmodels = newWrapped

	tmIds := make(map[string]string)

	for _, t := range p.wrapped.Threatmodels {
		// Validating unique threatmodel name
		if _, ok := tmMap[t.Name]; ok {
			errMap = multierror.Append(errMap, fmt.Errorf(
				"TM '%s': duplicate found",
				t.Name,
			))
		}
		tmMap[t.Name] = nil

		// Validating declared ids: identifier-safe and unique. Derived
		// identifiers (see Identifier()) are deliberately not checked here -
		// enforcing uniqueness on derivations would invalidate existing
		// models whose names happen to collide once slugified.
		if t.Id != "" {
			if !ValidIdentifier(t.Id) {
				errMap = multierror.Append(errMap, fmt.Errorf(
					"TM '%s': invalid id '%s' - must be dot-separated segments of lowercase letters, digits or underscores, each starting with a letter",
					t.Name,
					t.Id,
				))
			}
			if _, ok := tmIds[t.Id]; ok {
				errMap = multierror.Append(errMap, fmt.Errorf(
					"TM '%s': duplicate id '%s'",
					t.Name,
					t.Id,
				))
			}
			tmIds[t.Id] = t.Name
		}

		// err := p.ValidateTm(&t)
		err := t.ValidateTm(p)
		if err != nil {
			errMap = multierror.Append(errMap, err)
		}

	}

	// A model may sit at another model's namespace — id "buildings" with
	// children "buildings.tower", "buildings.bridge" — since reference trees
	// place children alongside the parent model's fields. That coexistence is
	// exactly why a child's segment directly beneath a parent model's id
	// can't be a threat model field name: "buildings.threats" would shadow
	// the parent's threats. Second pass so ordering in the file doesn't
	// matter.
	for _, t := range p.wrapped.Threatmodels {
		if t.Id == "" {
			continue
		}
		for _, prefix := range IdentifierPrefixes(t.Id) {
			if _, ok := tmIds[prefix]; !ok {
				continue
			}
			segment := t.Id[len(prefix)+1:]
			if dot := strings.Index(segment, "."); dot >= 0 {
				segment = segment[:dot]
			}
			if ReservedIdSegment(segment) {
				errMap = multierror.Append(errMap, fmt.Errorf(
					"TM '%s': id '%s' uses reserved segment '%s' directly beneath model id '%s' (TM '%s') - it would shadow that threat model's '%s' field in references",
					t.Name,
					t.Id,
					segment,
					prefix,
					tmIds[prefix],
					segment,
				))
			}
		}
	}

	if !p.skipExtendsResolution {
		if err := p.resolveExtends(); err != nil {
			errMap = multierror.Append(errMap, err)
		}
	}

	if errMap != nil {
		return errMap
	}

	return nil
}

func (p *ThreatmodelParser) validateBackend() error {
	var errMap error

	// Check that there is at most one backend block
	if len(p.wrapped.Backends) > 1 {
		errMap = multierror.Append(errMap, fmt.Errorf(
			"only one backend block is allowed, found %d",
			len(p.wrapped.Backends),
		))
	}

	// If there is a backend block, validate it has an organization
	if len(p.wrapped.Backends) > 0 {
		backend := p.wrapped.Backends[0]
		if backend.BackendOrg == "" {
			errMap = multierror.Append(errMap, fmt.Errorf(
				"backend '%s': organization is required",
				backend.BackendName,
			))
		}
	}

	if errMap != nil {
		return errMap
	}

	return nil
}

func (p *ThreatmodelParser) validateSpec(filename string) {
	// @TODO: This has been edited to not print to STDOUT - it should be wrapped in a DEBUG flag

	// Check the version in the file against the current config
	if p.wrapped.SpecVersion != "" {
		if p.wrapped.SpecVersion != p.specCfg.Version {
			// fmt.Fprintf(os.Stdout, "%s: Provided version ('%s') doesn't match the hcltm version ('%s')\n", filename, p.wrapped.SpecVersion, p.specCfg.Version)
		}
	} else {
		fmt.Fprintf(os.Stdout, "%s: No provided version. The current hcltm version is '%s'\n", filename, p.specCfg.Version)
	}

}

// extractVars does a shallow parsing of an HCL file looking for
// 'variable' blocks
func extractVars(f *hcl.File) (map[string]string, error) {
	output := make(map[string]string)
	var errMap error

	extract, _, diags := f.Body.PartialContent(&hcl.BodySchema{
		Blocks: []hcl.BlockHeaderSchema{
			{
				Type:       "variable",
				LabelNames: []string{"name"},
			},
		},
	})

	if diags.HasErrors() {
		return output, diags
	}

	for _, b := range extract.Blocks {
		attributeExtract, _, _ := b.Body.PartialContent(&hcl.BodySchema{
			Attributes: []hcl.AttributeSchema{
				{
					Name: "value",
				},
			},
		})

		if attr, exist := attributeExtract.Attributes["value"]; exist {
			value_extract := ""
			attrDiags := gohcl.DecodeExpression(attr.Expr, nil, &value_extract)
			if attrDiags.HasErrors() {
				errMap = multierror.Append(errMap, attrDiags)
			} else {
				if len(value_extract) > 0 && len(b.Labels) > 0 {
					output[b.Labels[0]] = value_extract
				}
			}
		}
	}

	return output, nil

}

func (p *ThreatmodelParser) buildVarCtx(ctx *hcl.EvalContext, varMap map[string]string) {

	// var varMapOut map[string]cty.Value
	varMapOut := make(map[string]cty.Value)

	for k, v := range varMap {
		varMapOut[k] = cty.StringVal(v)
	}

	ctx.Variables["var"] = cty.ObjectVal(varMapOut)

}

// checkEmptyIds does a shallow parsing of an HCL file looking for
// 'threatmodel' blocks that declare a literal empty id. After decoding, an
// empty string is indistinguishable from an absent optional attribute — which
// would let `id = ""` silently bypass id validation — so the check has to
// happen here at the syntax level. Non-literal expressions (e.g. var
// references) are skipped; their decoded values are validated after parsing
// like any other declared id.
func checkEmptyIds(f *hcl.File) error {
	var errMap error

	extract, _, diags := f.Body.PartialContent(&hcl.BodySchema{
		Blocks: []hcl.BlockHeaderSchema{
			{
				Type:       "threatmodel",
				LabelNames: []string{"name"},
			},
		},
	})

	if diags.HasErrors() {
		return diags
	}

	for _, b := range extract.Blocks {
		attributeExtract, _, _ := b.Body.PartialContent(&hcl.BodySchema{
			Attributes: []hcl.AttributeSchema{
				{
					Name: "id",
				},
			},
		})

		attr, exist := attributeExtract.Attributes["id"]
		if !exist {
			continue
		}

		idVal := ""
		attrDiags := gohcl.DecodeExpression(attr.Expr, nil, &idVal)
		if attrDiags.HasErrors() {
			continue
		}

		if idVal == "" && len(b.Labels) > 0 {
			errMap = multierror.Append(errMap, fmt.Errorf(
				"TM '%s': id must not be empty when declared",
				b.Labels[0],
			))
		}
	}

	return errMap
}

// extractImports does a shallow parsing of an HCL file looking for
// 'threatmodel' blocks that include 'imports' attributes
func extractImports(f *hcl.File) ([]string, error) {
	output := []string{}
	var errMap error

	extract, _, diags := f.Body.PartialContent(&hcl.BodySchema{
		Blocks: []hcl.BlockHeaderSchema{
			{
				Type:       "threatmodel",
				LabelNames: []string{"name"},
			},
		},
	})

	if diags.HasErrors() {
		return output, diags
	}

	for _, b := range extract.Blocks {
		attributeExtract, _, _ := b.Body.PartialContent(&hcl.BodySchema{
			Attributes: []hcl.AttributeSchema{
				{
					Name: "imports",
				},
			},
		})

		if attr, exist := attributeExtract.Attributes["imports"]; exist {
			imports := []string{}
			attrDiags := gohcl.DecodeExpression(attr.Expr, nil, &imports)
			if attrDiags.HasErrors() {
				errMap = multierror.Append(errMap, attrDiags)
			} else {
				for _, i := range imports {
					foundOutput := false
					for _, existingOutput := range output {
						if existingOutput == i {
							foundOutput = true
						}
					}

					if !foundOutput {
						output = append(output, i)
					}
				}
			}
		}
	}

	return output, errMap
}

func (p *ThreatmodelParser) buildCtx(ctx *hcl.EvalContext, imports []string, parentfilename string) error {
	var controls map[string]cty.Value
	var expandedControls map[string]cty.Value
	controls = make(map[string]cty.Value)
	expandedControls = make(map[string]cty.Value)

	for _, i := range imports {
		importTmp, err := fetchRemoteTm(p.specCfg, i, parentfilename)
		if err != nil {
			return err
		}

		// Handle all component-based controls
		for _, c := range importTmp.GetWrapped().Components {
			// Create control object with required fields
			controlObj := map[string]cty.Value{
				"description": cty.StringVal(c.Description),
			}

			// Route to appropriate import path based on component type
			if c.ComponentType == "control" {
				// For control type, add all optional fields and route to controls map
				controlObj["implemented"] = cty.BoolVal(c.Implemented)

				if c.ImplementationNotes != "" {
					controlObj["implementation_notes"] = cty.StringVal(c.ImplementationNotes)
				} else {
					controlObj["implementation_notes"] = cty.StringVal("")
				}

				controlObj["risk_reduction"] = cty.NumberIntVal(int64(c.RiskReduction))

				// Handle control attributes
				if len(c.Attributes) > 0 {
					attributes := make(map[string]cty.Value)
					for _, attr := range c.Attributes {
						attributes[attr.Name] = cty.StringVal(attr.Value)
					}
					controlObj["attribute"] = cty.ObjectVal(attributes)
				} else {
					controlObj["attribute"] = cty.ObjectVal(map[string]cty.Value{})
				}

				controls[c.ComponentName] = cty.ObjectVal(controlObj)
			} else if c.ComponentType == "expanded_control" {
				// For expanded_control type (deprecated), add all optional fields and route to expanded_controls map
				controlObj["implemented"] = cty.BoolVal(c.Implemented)

				if c.ImplementationNotes != "" {
					controlObj["implementation_notes"] = cty.StringVal(c.ImplementationNotes)
				} else {
					controlObj["implementation_notes"] = cty.StringVal("")
				}

				controlObj["risk_reduction"] = cty.NumberIntVal(int64(c.RiskReduction))

				// Handle control attributes
				if len(c.Attributes) > 0 {
					attributes := make(map[string]cty.Value)
					for _, attr := range c.Attributes {
						attributes[attr.Name] = cty.StringVal(attr.Value)
					}
					controlObj["attribute"] = cty.ObjectVal(attributes)
				} else {
					controlObj["attribute"] = cty.ObjectVal(map[string]cty.Value{})
				}

				expandedControls[c.ComponentName] = cty.ObjectVal(controlObj)
			} else {
				// For other component types, only description is available
				controls[c.ComponentName] = cty.ObjectVal(controlObj)
			}
		}
	}

	// Create the import object with both control types
	ctx.Variables["import"] = cty.ObjectVal(map[string]cty.Value{
		"control":          cty.ObjectVal(controls),
		"expanded_control": cty.ObjectVal(expandedControls),
	})

	return nil
}

// decodeHCL handles the per-file portion of parsing — building the eval
// context (imports, vars, element reference slugs), syntax-level id checks,
// decoding into wrapped, and control-import resolution. Set-level validation
// is left to the caller, so multiple files can decode into one set before
// validating (see ParseHCLRawSet).
func (p *ThreatmodelParser) decodeHCL(f *hcl.File, filename string, isChild bool, wrapped *ThreatmodelWrapped) error {

	ctx := &hcl.EvalContext{}
	ctx.Variables = map[string]cty.Value{}

	// @TODO while imports should only be in the parent, variables can be in sub files?
	if !isChild {
		// extract any imports = [] from this hcl file
		imports, err := extractImports(f)
		if err != nil {
			return err
		}

		// if we have imports we need to build EvalContext for them
		if len(imports) > 0 {
			if filename == "STDIN" {
				fmt.Printf("Warning: STDIN processing of hcltm files doesn't handle imports, and we've detected an import\n")
			}

			err = p.buildCtx(ctx, imports, filename)

			if err != nil {
				return err
			}
		}

		// extract any variables from this hcl file
		varMap, err := extractVars(f)
		if err != nil {
			return err
		}

		if len(varMap) > 0 {
			p.buildVarCtx(ctx, varMap)
		}
	}

	// Element labels are file-local, so the dot-notation reference namespaces
	// (process.<slug>, information_asset.<slug>, ...) are built for child
	// files too.
	p.buildRefCtx(ctx, extractRefSlugs(f))

	// A literal `id = ""` is indistinguishable from an absent id after
	// decoding, so it is rejected at the syntax level.
	if err := checkEmptyIds(f); err != nil {
		return err
	}

	// var diags hcl.Diagnostics

	diags := gohcl.DecodeBody(f.Body, ctx, wrapped)

	if diags.HasErrors() {
		return diags
	}

	// @TODO: This has been commented out to not print to STDOUT - it should be wrapped in a DEBUG flag
	// p.validateSpec(filename)

	// Process control imports after parsing
	return p.processControlImports(ctx, wrapped)
}

// parseHCL actually does the parsing - called by either ParseHCLFile or ParseHCLRaw
func (p *ThreatmodelParser) parseHCL(f *hcl.File, filename string, isChild bool) error {
	err := p.decodeHCL(f, filename, isChild, p.wrapped)
	if err != nil {
		return err
	}

	err = p.validateBackend()
	if err != nil {
		return err
	}

	return p.validateTms()
}

// processControlImports handles control_import fields by resolving them from imports
// and merging them into the Controls array
func (p *ThreatmodelParser) processControlImports(ctx *hcl.EvalContext, wrapped *ThreatmodelWrapped) error {
	// We need to re-parse the HCL to extract control_import expressions
	// This is a more complex approach that requires custom HCL parsing

	// For now, let's implement a simpler approach where we expect
	// the control_imports to be provided as string references that we can resolve
	for i := range wrapped.Threatmodels {
		tm := &wrapped.Threatmodels[i]
		for _, threat := range tm.Threats {
			// Merge deprecated ExpandedControls into Controls for backward compatibility
			if len(threat.ExpandedControls) > 0 {
				threat.Controls = append(threat.Controls, threat.ExpandedControls...)
			}

			if len(threat.ControlImports) > 0 {
				// Process each control import
				for _, controlImport := range threat.ControlImports {
					control, err := p.resolveControlImport(controlImport, ctx)
					if err != nil {
						return err
					}
					// Add the resolved control to the Controls array
					threat.Controls = append(threat.Controls, control)
				}
			}
		}
	}
	return nil
}

// resolveControlImport resolves a control import reference from the import context
func (p *ThreatmodelParser) resolveControlImport(controlImport string, ctx *hcl.EvalContext) (*Control, error) {
	// Parse the control import (e.g., "import.control.authentication_control" or "import.expanded_control.authentication_control")
	parts := strings.Split(controlImport, ".")
	if len(parts) != 3 || parts[0] != "import" {
		return nil, fmt.Errorf("invalid control import format: %s (expected: import.control.control_name or import.expanded_control.control_name)", controlImport)
	}

	if parts[1] != "control" && parts[1] != "expanded_control" {
		return nil, fmt.Errorf("unsupported control type: %s (only 'control' and 'expanded_control' are supported)", parts[1])
	}

	controlType := parts[1]
	controlName := parts[2]

	// Get the control from the import context
	importVal, exists := ctx.Variables["import"]
	if !exists {
		return nil, fmt.Errorf("no imports available")
	}

	// Get from the appropriate namespace based on the control type specified
	controlsVal := importVal.GetAttr(controlType)
	isEmpty := controlsVal.IsNull() || (controlsVal.Type().IsObjectType() && len(controlsVal.Type().AttributeTypes()) == 0)
	if isEmpty {
		// Backward compatibility: if expanded_control doesn't exist, try control
		if controlType == "expanded_control" {
			controlsVal = importVal.GetAttr("control")
			isEmpty = controlsVal.IsNull() || (controlsVal.Type().IsObjectType() && len(controlsVal.Type().AttributeTypes()) == 0)
			if isEmpty {
				return nil, fmt.Errorf("no %s or control imports available", controlType)
			}
		} else {
			return nil, fmt.Errorf("no %s imports available", controlType)
		}
	}

	controlVal := controlsVal.GetAttr(controlName)
	if controlVal.IsNull() {
		return nil, fmt.Errorf("control '%s' not found in imports", controlName)
	}

	// Extract the control data and create a Control struct
	controlObj := controlVal.AsValueMap()

	control := &Control{
		Name: controlName, // Use the control name as the name
	}

	// Set description
	if descVal, exists := controlObj["description"]; exists && !descVal.IsNull() {
		control.Description = descVal.AsString()
	}

	// Set implemented
	if implVal, exists := controlObj["implemented"]; exists && !implVal.IsNull() {
		control.Implemented = implVal.True()
	}

	// Set implementation_notes
	if notesVal, exists := controlObj["implementation_notes"]; exists && !notesVal.IsNull() {
		control.ImplementationNotes = notesVal.AsString()
	}

	// Set risk_reduction
	if riskVal, exists := controlObj["risk_reduction"]; exists && !riskVal.IsNull() {
		riskInt, _ := riskVal.AsBigFloat().Int64()
		control.RiskReduction = int(riskInt)
	}

	// Set attributes
	if attrVal, exists := controlObj["attribute"]; exists && !attrVal.IsNull() {
		attrMap := attrVal.AsValueMap()
		control.Attributes = make([]*ControlAttribute, 0, len(attrMap))
		for name, value := range attrMap {
			control.Attributes = append(control.Attributes, &ControlAttribute{
				Name:  name,
				Value: value.AsString(),
			})
		}
	}

	return control, nil
}

// ParseFile parses a single Threatmodel file, and will account for either
// JSON or HCL (this is a wrapper sort of for the two different methods)
func (p *ThreatmodelParser) ParseFile(filename string, isChild bool) error {
	var err error
	if filepath.Ext(filename) == ".hcl" {
		err = p.ParseHCLFile(filename, isChild)
		if err != nil {
			return err
		}
	} else if filepath.Ext(filename) == ".json" {
		err = p.ParseJSONFile(filename, isChild)
		if err != nil {
			return err
		}
	} else {
		return fmt.Errorf("file isn't HCL or JSON")
	}

	for i := 0; i < len(p.wrapped.Threatmodels); i++ {
		w := &p.wrapped.Threatmodels[i]
		if w.Including != "" {
			err = w.Include(p.specCfg, filename)
			if err != nil {
				return err
			}
		}
	}

	return err

}

// ParseHCLFile parses a single HCL Threatmodel file
func (p *ThreatmodelParser) ParseHCLFile(filename string, isChild bool) error {
	parser := hclparse.NewParser()
	f, diags := parser.ParseHCLFile(filename)

	if diags.HasErrors() {
		return diags
	}

	return p.parseHCL(f, filename, isChild)
}

// ParseHCLRaw parses a byte slice into HCL Threatmodels
// This is used for piping in STDIN
func (p *ThreatmodelParser) ParseHCLRaw(input []byte) error {
	parser := hclparse.NewParser()
	f, diags := parser.ParseHCL(input, "STDIN")

	if diags.HasErrors() {
		return diags
	}

	return p.parseHCL(f, "STDIN", false)
}

// NamedInput pairs raw HCL content with the name used to attribute
// diagnostics to it — typically the name of the file it came from.
type NamedInput struct {
	Name    string
	Content []byte
}

// ParseHCLRawSet parses multiple named HCL inputs into one parsed set.
// Each input decodes with its own name so diagnostics point at the right
// input, and imports and variables are handled per input, the same way
// ParseHCLFile treats a top-level file. Set-level validation — unique names
// and ids, reserved segments, extends resolution — runs once over the merged
// set, so a model may extend a parent declared in another input regardless
// of input order. Unlike single-input parsing, each input may carry its own
// backend block (at most one per input); all of them are exposed on the
// wrapped result, and any cross-input backend agreement is left to the
// consumer.
func (p *ThreatmodelParser) ParseHCLRawSet(inputs []NamedInput) error {
	parser := hclparse.NewParser()

	var errMap error
	for _, input := range inputs {
		f, diags := parser.ParseHCL(input.Content, input.Name)
		if diags.HasErrors() {
			errMap = multierror.Append(errMap, diags)
			continue
		}

		fileWrapped := &ThreatmodelWrapped{}
		err := p.decodeHCL(f, input.Name, false, fileWrapped)
		if err != nil {
			errMap = multierror.Append(errMap, err)
			continue
		}

		if len(fileWrapped.Backends) > 1 {
			errMap = multierror.Append(errMap, fmt.Errorf(
				"input '%s': only one backend block is allowed per input, found %d",
				input.Name,
				len(fileWrapped.Backends),
			))
		}

		p.wrapped.Threatmodels = append(p.wrapped.Threatmodels, fileWrapped.Threatmodels...)
		p.wrapped.Components = append(p.wrapped.Components, fileWrapped.Components...)
		p.wrapped.Variables = append(p.wrapped.Variables, fileWrapped.Variables...)
		p.wrapped.Backends = append(p.wrapped.Backends, fileWrapped.Backends...)
		if p.wrapped.SpecVersion == "" {
			p.wrapped.SpecVersion = fileWrapped.SpecVersion
		}
	}

	// Set-level validation over a set with undecoded inputs would only
	// produce misleading errors — e.g. an unknown extends target whose
	// parent lives in the input that failed — so per-input errors return
	// on their own.
	if errMap != nil {
		return errMap
	}

	return p.validateTms()
}

// ParseJSONFile parses a single JSON Threatmodel file
func (p *ThreatmodelParser) ParseJSONFile(filename string, isChild bool) error {
	parser := hclparse.NewParser()
	f, diags := parser.ParseJSONFile(filename)

	if diags.HasErrors() {
		return diags
	}

	return p.parseHCL(f, filename, isChild)
}

// ParseJSONRaw parses a byte slice into HCL Threatmodels from JSON
// This is used for piping in STDIN
func (p *ThreatmodelParser) ParseJSONRaw(input []byte) error {
	parser := hclparse.NewParser()
	f, diags := parser.ParseJSON(input, "STDIN")

	if diags.HasErrors() {
		return diags
	}

	return p.parseHCL(f, "STDIN", false)
}
