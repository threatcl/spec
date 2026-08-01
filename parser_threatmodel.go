package spec

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"

	gg "github.com/hashicorp/go-getter"
	"github.com/hashicorp/go-multierror"
)

func (tm *Threatmodel) Include(cfg *ThreatmodelSpecConfig, myfilename string) error {
	if tm.Including == "" {
		return fmt.Errorf("empty including")
	}

	subParser, err := fetchRemoteTm(cfg, tm.Including, myfilename)
	if err != nil {
		return err
	}

	if len(subParser.wrapped.Threatmodels) != 1 {
		return fmt.Errorf("the included threat model file includes an incorrect number of threat models. Expected 1 but got %d", len(subParser.wrapped.Threatmodels))
	}

	subTm := &subParser.wrapped.Threatmodels[0]

	if tm.Description == "" {
		tm.Description = subTm.Description
	}

	if tm.Link == "" {
		tm.Link = subTm.Link
	}

	if tm.DiagramLink == "" {
		tm.DiagramLink = subTm.DiagramLink
	}

	if len(tm.Repository) == 0 {
		tm.Repository = subTm.Repository
	}

	if tm.Attributes == nil {
		tm.Attributes = subTm.Attributes
	}

	for _, ia := range subTm.InformationAssets {
		tm.addInfoIfNotExist(*ia)
	}

	for _, uc := range subTm.UseCases {
		tm.addUcIfNotExist(*uc)
	}

	for _, ex := range subTm.Exclusions {
		tm.addExclIfNotExist(*ex)
	}

	for _, tpd := range subTm.ThirdPartyDependencies {
		tm.addTpdIfNotExist(*tpd)
	}

	for _, dfd := range subTm.DataFlowDiagrams {
		tm.addDfdIfNotExist(*dfd)
	}

	for _, mermaid := range subTm.MermaidDiagrams {
		tm.addMermaidIfNotExist(*mermaid)
	}

	for _, t := range subTm.Threats {
		tm.addTIfNotExist(*t)
	}

	return nil
}

func (tm *Threatmodel) addInfoIfNotExist(newIa InformationAsset) {

	assetFound := false
	for _, ia := range tm.InformationAssets {
		if ia.Name == newIa.Name {
			assetFound = true
		}
	}

	if !assetFound {
		tm.InformationAssets = append(tm.InformationAssets, &newIa)
	}

}

func (tm *Threatmodel) addTpdIfNotExist(newTpd ThirdPartyDependency) {

	tpdFound := false
	for _, tpd := range tm.ThirdPartyDependencies {
		if tpd.Name == newTpd.Name {
			tpdFound = true
		}
	}

	if !tpdFound {
		tm.ThirdPartyDependencies = append(tm.ThirdPartyDependencies, &newTpd)
	}

}

func (tm *Threatmodel) addUcIfNotExist(newUc UseCase) {

	ucFound := false
	for _, uc := range tm.UseCases {
		if newUc.Description == uc.Description {
			ucFound = true
		}
	}

	if !ucFound {
		tm.UseCases = append(tm.UseCases, &newUc)
	}
}

func (tm *Threatmodel) addExclIfNotExist(newExcl Exclusion) {

	exFound := false
	for _, ex := range tm.Exclusions {
		if newExcl.Description == ex.Description {
			exFound = true
		}
	}

	if !exFound {
		tm.Exclusions = append(tm.Exclusions, &newExcl)
	}
}

func (tm *Threatmodel) addTIfNotExist(newT Threat) {

	tFound := false
	for _, t := range tm.Threats {
		if newT.Name == t.Name {
			tFound = true
		}
	}

	if !tFound {
		tm.Threats = append(tm.Threats, &newT)
	}
}

func (tm *Threatmodel) addDfdIfNotExist(newDfd DataFlowDiagram) {

	dfdFound := false
	for _, dfd := range tm.DataFlowDiagrams {
		if newDfd.Name == dfd.Name {
			dfdFound = true
		}
	}

	if !dfdFound {
		tm.DataFlowDiagrams = append(tm.DataFlowDiagrams, &newDfd)
	}
}

func (tm *Threatmodel) addMermaidIfNotExist(newMermaid MermaidDiagram) {

	mermaidFound := false
	for _, mermaid := range tm.MermaidDiagrams {
		if newMermaid.Name == mermaid.Name {
			mermaidFound = true
		}
	}

	if !mermaidFound {
		tm.MermaidDiagrams = append(tm.MermaidDiagrams, &newMermaid)
	}
}

func fetchRemoteTm(cfg *ThreatmodelSpecConfig, source, currentFilename string) (*ThreatmodelParser, error) {
	returnParser := NewThreatmodelParser(cfg)

	absPath, err := filepath.Abs(currentFilename)
	if err != nil {
		return nil, err
	}

	absPath = filepath.Dir(absPath)

	// @TODO The below is a hack to remote URLs
	// We allow an explicit "file" to be referenced after
	// a whole directory (i.e. git repo) is cloned
	// see: https://github.com/hashicorp/go-getter/issues/98

	// for example, the below allows a remote URL to look like
	// github.com/xntrik/hcltm|examples/aws-security-checklist.hcl
	// OR, something more complex, like a private repo
	// git::ssh://git@github.com/xntrik/test|aws-security-checklist.hcl
	splitSource := strings.SplitN(source, "|", 2)

	// Classify the source before fetching anything. Local file includes are
	// always allowed (subject to the containment checks below); remote
	// sources (http, https, git, s3, gcs, ...) are gated behind the
	// allow_remote_imports config flag so that parsing an untrusted model
	// can't be turned into an SSRF or remote-fetch primitive by default.
	remote, err := isRemoteSource(splitSource[0], absPath)
	if err != nil {
		return nil, err
	}

	if remote && !cfg.AllowRemoteImports {
		return nil, fmt.Errorf(
			"remote import of '%s' is disabled; set allow_remote_imports = true in your threatcl config to permit fetching remote sources",
			splitSource[0],
		)
	}

	// For local includes, verify the source resolves to a path inside the
	// directory of the referring file. This blocks file:///etc/passwd and
	// ../ traversal from copying arbitrary host files into the parse.
	if !remote {
		if err := ensureLocalSourceContained(absPath, splitSource[0]); err != nil {
			return nil, err
		}
	}

	tmpDir, err := os.MkdirTemp("", "hcltm")
	if err != nil {
		return nil, err
	}

	// @TODO The below refers to a non-existent folder
	// to cater for https://github.com/hashicorp/go-getter/issues/114
	tmpDir = fmt.Sprintf("%s/nest", tmpDir)

	client := gg.Client{
		Src:     splitSource[0],
		Dst:     tmpDir,
		Pwd:     absPath,
		Mode:    gg.ClientModeAny,
		Getters: importGetters(cfg.AllowRemoteImports),
	}

	err = client.Get()
	if err != nil {
		return nil, err
	}

	includePath := ""

	switch len(splitSource) {
	case 1:
		includePath = filepath.Join(tmpDir, filepath.Base(source))
	case 2:
		includePath = filepath.Join(tmpDir, splitSource[1])
	}

	// Ensure the file handed to the parser is still inside the download
	// directory. This stops the "repo|../../etc/passwd" form from escaping
	// tmpDir to read arbitrary local files.
	if err := ensureWithin(tmpDir, includePath); err != nil {
		return nil, err
	}

	importDiag := returnParser.ParseHCLFile(includePath, false)

	if importDiag != nil {
		return nil, importDiag
	}

	return returnParser, nil
}

// isRemoteSource reports whether a go-getter source string resolves to a
// non-local getter (git, http, https, s3, gcs, hg, ...). Local file includes
// resolve to the "file" getter and return false.
func isRemoteSource(source, pwd string) (bool, error) {
	detected, err := gg.Detect(source, pwd, gg.Detectors)
	if err != nil {
		return false, err
	}

	// go-getter forces a getter with a "<getter>::" prefix, e.g.
	// "git::https://...". When that's absent the URL scheme selects the
	// getter.
	getter := ""
	if before, _, found := strings.Cut(detected, "::"); found {
		getter = before
	} else if u, perr := url.Parse(detected); perr == nil {
		getter = u.Scheme
	}

	return getter != "" && getter != "file", nil
}

// importGetters returns the go-getter getter set used for imports. When remote
// imports are disabled only the local "file" getter is available. When enabled
// the full default set is available, but http/https are served by an
// SSRF-aware client that refuses to connect to loopback/link-local addresses
// (which cover cloud metadata endpoints such as 169.254.169.254).
func importGetters(allowRemote bool) map[string]gg.Getter {
	getters := map[string]gg.Getter{
		"file": new(gg.FileGetter),
	}

	if allowRemote {
		httpGetter := &gg.HttpGetter{
			Netrc:  true,
			Client: ssrfSafeHTTPClient(),
		}
		getters["git"] = new(gg.GitGetter)
		getters["gcs"] = new(gg.GCSGetter)
		getters["hg"] = new(gg.HgGetter)
		getters["s3"] = new(gg.S3Getter)
		getters["http"] = httpGetter
		getters["https"] = httpGetter
	}

	return getters
}

// ssrfSafeHTTPClient returns an http.Client whose dialer resolves the target
// host and refuses to connect to loopback, link-local, or unspecified
// addresses. It dials the resolved IP directly to avoid a DNS-rebinding
// window between the check and the connection.
func ssrfSafeHTTPClient() *http.Client {
	dialer := &net.Dialer{}
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}

			ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
			if err != nil {
				return nil, err
			}

			var lastErr error
			for _, ip := range ips {
				if isBlockedIP(ip.IP) {
					return nil, fmt.Errorf("refusing to connect to disallowed address %s", ip.IP)
				}
			}
			for _, ip := range ips {
				conn, derr := dialer.DialContext(ctx, network, net.JoinHostPort(ip.IP.String(), port))
				if derr == nil {
					return conn, nil
				}
				lastErr = derr
			}
			if lastErr == nil {
				lastErr = fmt.Errorf("no addresses found for %s", host)
			}
			return nil, lastErr
		},
	}

	return &http.Client{Transport: transport}
}

// isBlockedIP reports whether an address is one that imports must never reach:
// loopback (127.0.0.0/8, ::1), link-local (169.254.0.0/16 — the cloud metadata
// range — and fe80::/10), or the unspecified address. Private RFC1918 ranges
// are intentionally allowed, since internal git/http servers are legitimate
// import sources.
func isBlockedIP(ip net.IP) bool {
	return ip.IsLoopback() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsUnspecified()
}

// ensureLocalSourceContained verifies that a local (file) getter source
// resolves to a path inside baseDir. source may be a plain path or a file://
// URL, absolute or relative to baseDir.
func ensureLocalSourceContained(baseDir, source string) error {
	p := source
	if u, err := url.Parse(source); err == nil && u.Scheme == "file" {
		p = u.Path
	}
	if !filepath.IsAbs(p) {
		p = filepath.Join(baseDir, p)
	}

	if err := ensureWithin(baseDir, p); err != nil {
		return fmt.Errorf("local import '%s' resolves outside the directory of the referring file", source)
	}

	return nil
}

// ensureWithin returns an error unless target, once cleaned, is inside base.
func ensureWithin(base, target string) error {
	rel, err := filepath.Rel(filepath.Clean(base), filepath.Clean(target))
	if err != nil {
		return fmt.Errorf("unable to resolve path '%s': %w", target, err)
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return fmt.Errorf("path '%s' escapes the permitted directory", target)
	}
	return nil
}

// resolveInformationAssetRef resolves an information_asset reference — an
// exact name, or an identifier-safe slug (see Slugify) — to the asset's
// canonical name.
func (tm *Threatmodel) resolveInformationAssetRef(asset string) (string, error) {
	candidates := make([]string, 0, len(tm.InformationAssets))
	for _, ia := range tm.InformationAssets {
		candidates = append(candidates, ia.Name)
	}

	resolved, ambiguous := resolveRef(asset, candidates)
	if resolved != "" {
		return resolved, nil
	}

	if len(ambiguous) > 0 {
		return "", fmt.Errorf(
			"ambiguous information_asset reference '%s' (matches: %s)",
			asset,
			strings.Join(ambiguous, ", "),
		)
	}

	return "", fmt.Errorf(
		"trying to refer to non-existent information_asset '%s'",
		asset,
	)
}

func (tm *Threatmodel) shiftLegacyDfd() int {
	if tm.LegacyDfd != nil {
		newDfd := &DataFlowDiagram{
			Name:              "Legacy DFD",
			ShiftedFromLegacy: true,
			Processes:         tm.LegacyDfd.Processes,
			ExternalElements:  tm.LegacyDfd.ExternalElements,
			DataStores:        tm.LegacyDfd.DataStores,
			Flows:             tm.LegacyDfd.Flows,
			TrustZones:        tm.LegacyDfd.TrustZones,
			ImportFile:        tm.LegacyDfd.ImportFile,
		}
		tm.LegacyDfd = nil
		tm.DataFlowDiagrams = append(tm.DataFlowDiagrams, newDfd)

		return 1
	}
	return 0
}

func (tm *Threatmodel) ValidateTm(p *ThreatmodelParser) error {
	var errMap error

	// Normalize threatmodel attributes
	if tm.Attributes != nil {

		// Normalize threatmodel attributes initiative_size
		if tm.Attributes.InitiativeSize != "" {
			tm.Attributes.InitiativeSize = p.normalizeInitiativeSize(tm.Attributes.InitiativeSize)
		}
	}

	// Checking for unique information_assets per threatmodel
	// Also Normalize info classification
	if tm.InformationAssets != nil {
		infoAssets := make(map[string]interface{})
		for _, ia := range tm.InformationAssets {
			if _, ok := infoAssets[ia.Name]; ok {
				errMap = multierror.Append(errMap, fmt.Errorf(
					"TM '%s': duplicate information_asset '%s'",
					tm.Name,
					ia.Name,
				))
			}

			// Normalize InformationClassification
			if ia.InformationClassification != "" {
				ia.InformationClassification = p.normalizeInfoClassification(ia.InformationClassification)
			}

			infoAssets[ia.Name] = nil
		}
	}

	// Validating any DFD data within a threat model
	// if tm.DataFlowDiagram != nil {
	for _, adfd := range tm.DataFlowDiagrams {

		// Checking for unique TrustZones
		zones := make(map[string]interface{})
		if adfd.TrustZones != nil {
			for _, zone := range adfd.TrustZones {
				if _, ok := zones[zone.Name]; ok {
					errMap = multierror.Append(errMap, fmt.Errorf(
						"TM '%s': duplicate trust_zone block found '%s'",
						tm.Name,
						zone.Name,
					))
				}

				zones[zone.Name] = nil
			}
		}

		// Resolve top-level element trust_zone references (exact name, else
		// unique slug match) against the declared trust_zone blocks. Values
		// that match no declared zone are left untouched — a trust_zone
		// attribute may name an implicit zone that has no block of its own.
		zoneNames := make([]string, 0, len(zones))
		for name := range zones {
			zoneNames = append(zoneNames, name)
		}
		sort.Strings(zoneNames)

		resolveZoneRef := func(elemName, ref string) string {
			resolved, ambiguous := resolveRef(ref, zoneNames)
			if resolved != "" {
				return resolved
			}
			if len(ambiguous) > 0 {
				errMap = multierror.Append(errMap, fmt.Errorf(
					"TM '%s': ambiguous trust_zone '%s' on '%s' (matches: %s)",
					tm.Name,
					ref,
					elemName,
					strings.Join(ambiguous, ", "),
				))
			}
			return ref
		}

		for _, process := range adfd.Processes {
			if process.TrustZone != "" {
				process.TrustZone = resolveZoneRef(process.Name, process.TrustZone)
			}
		}

		for _, external_element := range adfd.ExternalElements {
			if external_element.TrustZone != "" {
				external_element.TrustZone = resolveZoneRef(external_element.Name, external_element.TrustZone)
			}
		}

		for _, data_store := range adfd.DataStores {
			if data_store.TrustZone != "" {
				data_store.TrustZone = resolveZoneRef(data_store.Name, data_store.TrustZone)
			}
		}

		// Checking for unique processes/data_store/external_element in data_flow_diagram
		elements := make(map[string]interface{})
		if adfd.Processes != nil {
			for _, process := range adfd.Processes {
				if _, ok := elements[process.Name]; ok {
					errMap = multierror.Append(errMap, fmt.Errorf(
						"TM '%s': duplicate process found in dfd '%s'",
						tm.Name,
						process.Name,
					))
				}

				elements[process.Name] = nil
			}
		}

		// Now check for Processes in trust_zones
		if adfd.TrustZones != nil {
			for _, zone := range adfd.TrustZones {
				if zone.Processes != nil {
					for _, process := range zone.Processes {
						if _, ok := elements[process.Name]; ok {
							errMap = multierror.Append(errMap, fmt.Errorf(
								"TM '%s': duplicate process found in dfd '%s'",
								tm.Name,
								process.Name,
							))
						}

						elements[process.Name] = nil
					}
				}
			}
		}

		if adfd.ExternalElements != nil {
			for _, external_element := range adfd.ExternalElements {
				if _, ok := elements[external_element.Name]; ok {
					errMap = multierror.Append(errMap, fmt.Errorf(
						"TM '%s': duplicate external_element found in dfd '%s'",
						tm.Name,
						external_element.Name,
					))
				}

				elements[external_element.Name] = nil
			}
		}

		// Now check for external_elements in trust_zones
		if adfd.TrustZones != nil {
			for _, zone := range adfd.TrustZones {
				if zone.ExternalElements != nil {
					for _, external_element := range zone.ExternalElements {
						if _, ok := elements[external_element.Name]; ok {
							errMap = multierror.Append(errMap, fmt.Errorf(
								"TM '%s': duplicate external_element found in dfd '%s'",
								tm.Name,
								external_element.Name,
							))
						}

						elements[external_element.Name] = nil
					}
				}
			}
		}

		// Checking for unique data_stores in data_flow_diagram
		if adfd.DataStores != nil {
			for _, data_store := range adfd.DataStores {
				if _, ok := elements[data_store.Name]; ok {
					errMap = multierror.Append(errMap, fmt.Errorf(
						"TM '%s': duplicate data_store found in dfd '%s'",
						tm.Name,
						data_store.Name,
					))
				}

				elements[data_store.Name] = nil

				// While in DataStores, let's check if they have iaRefs, and that they
				// are valid
				if data_store.IaLink != "" {
					resolved, err := tm.resolveInformationAssetRef(data_store.IaLink)
					if err != nil {
						errMap = multierror.Append(errMap, fmt.Errorf(
							"TM '%s' DFD Data Store '%s' %s",
							tm.Name,
							data_store.Name,
							err,
						))
					} else {
						data_store.IaLink = resolved
					}
				}
			}
		}

		// Now check for data_stores in trust_zones
		if adfd.TrustZones != nil {
			for _, zone := range adfd.TrustZones {
				if zone.DataStores != nil {
					for _, data_store := range zone.DataStores {
						if _, ok := elements[data_store.Name]; ok {
							errMap = multierror.Append(errMap, fmt.Errorf(
								"TM '%s': duplicate data_store found in dfd '%s'",
								tm.Name,
								data_store.Name,
							))
						}

						elements[data_store.Name] = nil

						// While in DataStores, let's check if they have iaRefs, and that they
						// are valid
						if data_store.IaLink != "" {
							resolved, err := tm.resolveInformationAssetRef(data_store.IaLink)
							if err != nil {
								errMap = multierror.Append(errMap, fmt.Errorf(
									"TM '%s' DFD Data Store '%s' %s",
									tm.Name,
									data_store.Name,
									err,
								))
							} else {
								data_store.IaLink = resolved
							}
						}
					}
				}
			}
		}

		// Now check for mis-matched trust-zones
		if adfd.TrustZones != nil {
			for _, zone := range adfd.TrustZones {
				if zone.Processes != nil {
					for _, process := range zone.Processes {
						if process.TrustZone != "" && process.TrustZone != zone.Name {
							if slugMatchesName(process.TrustZone, zone.Name) {
								process.TrustZone = zone.Name
							} else {
								errMap = multierror.Append(errMap, fmt.Errorf(
									"TM '%s': process trust_zone mis-match found in '%s'",
									tm.Name,
									process.Name,
								))
							}
						}
					}
				}

				if zone.ExternalElements != nil {
					for _, external_element := range zone.ExternalElements {
						if external_element.TrustZone != "" && external_element.TrustZone != zone.Name {
							if slugMatchesName(external_element.TrustZone, zone.Name) {
								external_element.TrustZone = zone.Name
							} else {
								errMap = multierror.Append(errMap, fmt.Errorf(
									"TM '%s': external_element trust_zone mis-match found in '%s'",
									tm.Name,
									external_element.Name,
								))
							}
						}
					}
				}

				if zone.DataStores != nil {
					for _, data_store := range zone.DataStores {
						if data_store.TrustZone != "" && data_store.TrustZone != zone.Name {
							if slugMatchesName(data_store.TrustZone, zone.Name) {
								data_store.TrustZone = zone.Name
							} else {
								errMap = multierror.Append(errMap, fmt.Errorf(
									"TM '%s': data_store trust_zone mis-match found in '%s'",
									tm.Name,
									data_store.Name,
								))
							}
						}
					}
				}
			}
		}

		// Validate data flows. Multiple flows between the same from→to pair
		// are allowed (e.g. an HTTP request and a separate websocket on the
		// same edge), but each must have a distinct name so authors don't
		// silently double-up an edge through copy/paste.
		flows := make(map[string]interface{})
		if adfd.Flows != nil {
			elementNames := make([]string, 0, len(elements))
			for name := range elements {
				elementNames = append(elementNames, name)
			}
			sort.Strings(elementNames)

			for _, rawflow := range adfd.Flows {
				// Resolve from/to references (exact name, else unique slug
				// match) to canonical element names before any wiring checks,
				// so slug and dot-notation references behave identically to
				// exact names downstream (rendering, exports, duplicate
				// detection).
				fromAmbiguous := false
				if resolved, ambiguous := resolveRef(rawflow.From, elementNames); resolved != "" {
					rawflow.From = resolved
				} else if len(ambiguous) > 0 {
					fromAmbiguous = true
					errMap = multierror.Append(errMap, fmt.Errorf(
						"TM '%s': ambiguous from connection '%s' for flow '%s' (matches: %s)",
						tm.Name,
						rawflow.From,
						rawflow.Name,
						strings.Join(ambiguous, ", "),
					))
				}

				toAmbiguous := false
				if resolved, ambiguous := resolveRef(rawflow.To, elementNames); resolved != "" {
					rawflow.To = resolved
				} else if len(ambiguous) > 0 {
					toAmbiguous = true
					errMap = multierror.Append(errMap, fmt.Errorf(
						"TM '%s': ambiguous to connection '%s' for flow '%s' (matches: %s)",
						tm.Name,
						rawflow.To,
						rawflow.Name,
						strings.Join(ambiguous, ", "),
					))
				}

				flow := fmt.Sprintf("%s:%s", rawflow.From, rawflow.To)
				flowKey := fmt.Sprintf("%s:%s:%s", rawflow.From, rawflow.To, rawflow.Name)

				// check for unique flows (same from, to, AND name)
				if _, ok := flows[flowKey]; ok {
					errMap = multierror.Append(errMap, fmt.Errorf(
						"TM '%s': duplicate flow found in dfd '%s' with name '%s'",
						tm.Name,
						flow,
						rawflow.Name,
					))
				}

				// now check that flows connect to legit processes
				if _, ok := elements[rawflow.From]; !ok && !fromAmbiguous {
					errMap = multierror.Append(errMap, fmt.Errorf(
						"TM '%s': invalid from connection for flow '%s'",
						tm.Name,
						flow,
					))
				}

				if _, ok := elements[rawflow.To]; !ok && !toAmbiguous {
					errMap = multierror.Append(errMap, fmt.Errorf(
						"TM '%s': invalid to connection for flow '%s'",
						tm.Name,
						flow,
					))
				}

				// now check that the flow doesn't connect to itself
				if rawflow.From == rawflow.To {
					errMap = multierror.Append(errMap, fmt.Errorf(
						"TM '%s': flow can't connect to itself '%s'",
						tm.Name,
						flow,
					))
				}

				flows[flowKey] = nil

			}
		}
	} // end of ranging over dataflowdiagrams

	// Normalize threat impacts and stride, and check that threat names are
	// unique per threatmodel and control names unique per threat. Names are
	// the identity key everywhere else in the parser — `extends` and
	// `including` merge threats by name (addTIfNotExist), and threatcl cloud
	// rejects a duplicate at parse and enrichment time — so a repeat is an
	// authoring error rather than two distinct entities.
	if tm.Threats != nil {
		threatNames := make(map[string]interface{})
		for _, tr := range tm.Threats {
			if _, ok := threatNames[tr.Name]; ok {
				errMap = multierror.Append(errMap, fmt.Errorf(
					"TM '%s': duplicate threat '%s'",
					tm.Name,
					tr.Name,
				))
			}

			threatNames[tr.Name] = nil

			// Controls here already include any deprecated expanded_control
			// blocks and resolved control_imports, both of which are merged
			// into Controls during decoding (see processControlImports), so an
			// imported control colliding with a declared one is caught too.
			controlNames := make(map[string]interface{})
			for _, control := range tr.Controls {
				if _, ok := controlNames[control.Name]; ok {
					errMap = multierror.Append(errMap, fmt.Errorf(
						"TM '%s' / Threat '%s': duplicate control '%s'",
						tm.Name,
						tr.Name,
						control.Name,
					))
				}

				controlNames[control.Name] = nil
			}

			normalized := []string{}
			for _, impact := range tr.ImpactType {
				normalized = append(normalized, p.normalizeImpactType(impact))
			}
			tr.ImpactType = normalized

			normalizedStride := []string{}
			for _, stride := range tr.Stride {
				normalizedStride = append(normalizedStride, p.normalizeStride(stride))
			}
			tr.Stride = normalizedStride

			// Resolving InformationAssetRefs (exact name, else unique slug
			// match) to canonical asset names, validating them along the way
			for i, iaRef := range tr.InformationAssetRefs {
				resolved, err := tm.resolveInformationAssetRef(iaRef)
				if err != nil {
					errMap = multierror.Append(errMap,
						fmt.Errorf("TM '%s' / Threat '%s': %s", tm.Name, tr.Description, err),
					)
					continue
				}
				tr.InformationAssetRefs[i] = resolved
			}

			// Normalize and validate the optional risk block. likelihood and
			// impact presence is enforced by HCL (they're required attrs); here
			// we check they're valid enums and canonicalise them, plus validate
			// any severity override.
			if tr.Risk != nil {
				if norm := p.normalizeRiskLevel(tr.Risk.Likelihood); norm != "" {
					tr.Risk.Likelihood = norm
				} else {
					errMap = multierror.Append(errMap, fmt.Errorf(
						"TM '%s' / Threat '%s': invalid risk likelihood '%s' (expected one of: %s)",
						tm.Name, tr.Description, tr.Risk.Likelihood, strings.Join(RiskLevels, ", "),
					))
				}

				if norm := p.normalizeRiskLevel(tr.Risk.Impact); norm != "" {
					tr.Risk.Impact = norm
				} else {
					errMap = multierror.Append(errMap, fmt.Errorf(
						"TM '%s' / Threat '%s': invalid risk impact '%s' (expected one of: %s)",
						tm.Name, tr.Description, tr.Risk.Impact, strings.Join(RiskLevels, ", "),
					))
				}

				if tr.Risk.SeverityOverride != "" {
					if norm := p.normalizeSeverity(tr.Risk.SeverityOverride); norm != "" {
						tr.Risk.SeverityOverride = norm
					} else {
						errMap = multierror.Append(errMap, fmt.Errorf(
							"TM '%s' / Threat '%s': invalid risk severity '%s' (expected one of: %s)",
							tm.Name, tr.Description, tr.Risk.SeverityOverride, strings.Join(SeverityLevels, ", "),
						))
					}
				}
			}
		}
	}

	// Normalize third party deps - uptime dep classification
	if tm.ThirdPartyDependencies != nil {
		for _, tpd := range tm.ThirdPartyDependencies {
			tpd.UptimeDependency = p.normalizeUptimeDepClassification(string(tpd.UptimeDependency))
		}
	}

	if errMap != nil {
		return errMap
	}

	return nil

}
