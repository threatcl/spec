package spec

func (p *ThreatmodelParser) populateInitiativeSizeOptions() {

	for _, cfgInitiativeSizeOption := range p.specCfg.InitiativeSizes {
		p.initiativeSizeOptions[cfgInitiativeSizeOption] = true
	}
	p.defaultInitiativeSize = p.specCfg.DefaultInitiativeSize
}

func (p *ThreatmodelParser) populateInfoClassifications() {

	for _, cfgInfoClassification := range p.specCfg.InfoClassifications {
		p.infoClassifications[cfgInfoClassification] = true
	}
	p.defaultInfoClassification = p.specCfg.DefaultInfoClassification
}

func (p *ThreatmodelParser) populateImpactTypes() {
	for _, cfgImpactType := range p.specCfg.ImpactTypes {
		p.impactTypes[cfgImpactType] = true
	}
}

func (p *ThreatmodelParser) populateStrideElements() {
	for _, cfgStride := range p.specCfg.STRIDE {
		p.strideElements[cfgStride] = true
	}
}

// populateRiskLevels seeds the valid likelihood/impact enums. These come from
// the built-in risk model today; this is the seam where a future hcltmrc/config
// override would feed a custom set (mirroring populateStrideElements).
func (p *ThreatmodelParser) populateRiskLevels() {
	for _, level := range RiskLevels {
		p.riskLevels[level] = true
	}
}

// populateSeverityLevels seeds the valid severity bands an author may use as a
// `severity` override.
func (p *ThreatmodelParser) populateSeverityLevels() {
	for _, band := range SeverityLevels {
		p.severityLevels[band] = true
	}
}

func (p *ThreatmodelParser) populateUptimeDepClassifications() {
	for _, cfgUptimeDep := range p.specCfg.UptimeDepClassifications {
		p.uptimeDepClassification[cfgUptimeDep] = true
	}
	p.defaultUptimeDepClassification = UptimeDependencyClassification(p.specCfg.DefaultUptimeDepClassification)
}
