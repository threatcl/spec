package spec

import (
	"strings"

	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

func (p *ThreatmodelParser) normalizeInitiativeSize(in string) string {
	// if p.initiativeSizeOptions[strings.Title(strings.ToLower(in))] {
	// 	return strings.Title(strings.ToLower(in))
	// }
	if p.initiativeSizeOptions[cases.Title(language.English).String(strings.ToLower(in))] {
		return cases.Title(language.English).String(strings.ToLower(in))
	}

	return p.defaultInitiativeSize
}

func (p *ThreatmodelParser) normalizeInfoClassification(in string) string {
	// if p.infoClassifications[strings.Title(strings.ToLower(in))] {
	// 	return strings.Title(strings.ToLower(in))
	// }
	if p.infoClassifications[cases.Title(language.English).String(strings.ToLower(in))] {
		return cases.Title(language.English).String(strings.ToLower(in))
	}
	return p.defaultInfoClassification
}

func (p *ThreatmodelParser) normalizeImpactType(in string) string {
	// if p.impactTypes[strings.Title(strings.ToLower(in))] {
	// 	return strings.Title(strings.ToLower(in))
	// }
	if p.impactTypes[cases.Title(language.English).String(strings.ToLower(in))] {
		return cases.Title(language.English).String(strings.ToLower(in))
	}
	return ""
}

func (p *ThreatmodelParser) normalizeStride(in string) string {
	// if p.strideElements[strings.Title(strings.ToLower(in))] {
	// 	return strings.Title(strings.ToLower(in))
	// }
	if p.strideElements[cases.Title(language.English).String(strings.ToLower(in))] {
		return cases.Title(language.English).String(strings.ToLower(in))
	}
	return ""
}

// normalizeRiskLevel canonicalises a likelihood/impact enum (case-, space- and
// hyphen-insensitive). Returns the canonical token (e.g. "very_high") if valid,
// or "" if it isn't a known risk level.
func (p *ThreatmodelParser) normalizeRiskLevel(in string) string {
	token := canonicalRiskToken(in)
	if p.riskLevels[token] {
		return token
	}
	return ""
}

// normalizeSeverity canonicalises a severity band override. Returns the
// canonical band (e.g. "critical") if valid, or "" if it isn't a known band.
func (p *ThreatmodelParser) normalizeSeverity(in string) string {
	token := canonicalRiskToken(in)
	if p.severityLevels[token] {
		return token
	}
	return ""
}

func (p *ThreatmodelParser) normalizeUptimeDepClassification(in string) UptimeDependencyClassification {
	if p.uptimeDepClassification[strings.ToLower(in)] {
		return UptimeDependencyClassification(strings.ToLower(in))
	}
	return p.defaultUptimeDepClassification
}
