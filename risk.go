package spec

import (
	"math"
	"strings"
)

// Risk levels (ordinal likelihood/impact enums) in canonical form.
const (
	RiskLevelVeryLow  = "very_low"
	RiskLevelLow      = "low"
	RiskLevelMedium   = "medium"
	RiskLevelHigh     = "high"
	RiskLevelVeryHigh = "very_high"
)

// Severity bands, ordered info < low < medium < high < critical.
const (
	SeverityInfo     = "info"
	SeverityLow      = "low"
	SeverityMedium   = "medium"
	SeverityHigh     = "high"
	SeverityCritical = "critical"
)

// RiskLevels is the ordered set of valid likelihood/impact enums.
var RiskLevels = []string{
	RiskLevelVeryLow,
	RiskLevelLow,
	RiskLevelMedium,
	RiskLevelHigh,
	RiskLevelVeryHigh,
}

// SeverityLevels is the ordered set of valid severity bands.
var SeverityLevels = []string{
	SeverityInfo,
	SeverityLow,
	SeverityMedium,
	SeverityHigh,
	SeverityCritical,
}

// severityThreshold pairs a minimum inherent/residual score with the band a
// score at-or-above it maps to. Ordered high→low so the first match wins.
type severityThreshold struct {
	min  float64
	band string
}

// RiskModel bundles the tunable pieces of the risk scoring scheme: the ordinal
// and OTM (0–100) mappings for likelihood/impact, the likelihood×impact →
// severity matrix, and the score→band thresholds used for residual severity.
//
// A single built-in defaultRiskModel ships with the spec so a solo CLI user
// gets ratings with zero config. It is deliberately the only place these
// numbers live, so a future per-repo (hcltmrc) or org-wide (Cloud) override can
// swap the model without touching the Risk/Threat methods below.
type RiskModel struct {
	// Ordinals maps each risk level to its 1–5 ordinal.
	Ordinals map[string]int
	// OtmValues maps each risk level to its OTM 0–100 value.
	OtmValues map[string]int
	// Matrix maps [likelihood][impact] to a severity band.
	Matrix map[string]map[string]string
	// Thresholds maps a numeric score to a severity band (residual view),
	// ordered high→low.
	Thresholds []severityThreshold
}

// defaultRiskModel is the built-in scoring scheme. See the package docs and the
// design proposal for the rationale behind these (deliberately tunable) values.
var defaultRiskModel = &RiskModel{
	Ordinals: map[string]int{
		RiskLevelVeryLow:  1,
		RiskLevelLow:      2,
		RiskLevelMedium:   3,
		RiskLevelHigh:     4,
		RiskLevelVeryHigh: 5,
	},
	OtmValues: map[string]int{
		RiskLevelVeryLow:  10,
		RiskLevelLow:      30,
		RiskLevelMedium:   50,
		RiskLevelHigh:     75,
		RiskLevelVeryHigh: 95,
	},
	// [likelihood][impact] → severity
	Matrix: map[string]map[string]string{
		RiskLevelVeryHigh: {
			RiskLevelVeryLow:  SeverityLow,
			RiskLevelLow:      SeverityMedium,
			RiskLevelMedium:   SeverityHigh,
			RiskLevelHigh:     SeverityCritical,
			RiskLevelVeryHigh: SeverityCritical,
		},
		RiskLevelHigh: {
			RiskLevelVeryLow:  SeverityLow,
			RiskLevelLow:      SeverityMedium,
			RiskLevelMedium:   SeverityHigh,
			RiskLevelHigh:     SeverityHigh,
			RiskLevelVeryHigh: SeverityCritical,
		},
		RiskLevelMedium: {
			RiskLevelVeryLow:  SeverityLow,
			RiskLevelLow:      SeverityLow,
			RiskLevelMedium:   SeverityMedium,
			RiskLevelHigh:     SeverityHigh,
			RiskLevelVeryHigh: SeverityHigh,
		},
		RiskLevelLow: {
			RiskLevelVeryLow:  SeverityInfo,
			RiskLevelLow:      SeverityLow,
			RiskLevelMedium:   SeverityLow,
			RiskLevelHigh:     SeverityMedium,
			RiskLevelVeryHigh: SeverityHigh,
		},
		RiskLevelVeryLow: {
			RiskLevelVeryLow:  SeverityInfo,
			RiskLevelLow:      SeverityInfo,
			RiskLevelMedium:   SeverityLow,
			RiskLevelHigh:     SeverityLow,
			RiskLevelVeryHigh: SeverityMedium,
		},
	},
	Thresholds: []severityThreshold{
		{75, SeverityCritical},
		{50, SeverityHigh},
		{25, SeverityMedium},
		{10, SeverityLow},
		{0, SeverityInfo},
	},
}

// DefaultRiskModel returns the built-in risk scoring scheme.
func DefaultRiskModel() *RiskModel {
	return defaultRiskModel
}

// score returns the 0–100 risk score for a likelihood/impact pair, defined as
// (otm(likelihood)/100) × (otm(impact)/100) × 100, rounded to one decimal. It
// returns 0 if either level is unknown.
func (m *RiskModel) score(likelihood, impact string) float64 {
	l, lok := m.OtmValues[likelihood]
	i, iok := m.OtmValues[impact]
	if !lok || !iok {
		return 0
	}
	return round1((float64(l) / 100) * (float64(i) / 100) * 100)
}

// severity returns the matrix severity band for a likelihood/impact pair, or
// "" if either level is unknown.
func (m *RiskModel) severity(likelihood, impact string) string {
	if row, ok := m.Matrix[likelihood]; ok {
		return row[impact]
	}
	return ""
}

// bandForScore maps a numeric score onto a severity band via the thresholds.
func (m *RiskModel) bandForScore(score float64) string {
	for _, t := range m.Thresholds {
		if score >= t.min {
			return t.band
		}
	}
	return SeverityInfo
}

// Severity returns the threat's inherent severity band. If the author set an
// explicit Severity override it is returned verbatim; otherwise it is computed
// from the likelihood×impact matrix. Returns "" if the levels are unknown and
// no override is set.
func (r *Risk) Severity() string {
	if r == nil {
		return ""
	}
	if r.SeverityOverride != "" {
		return r.SeverityOverride
	}
	return defaultRiskModel.severity(r.Likelihood, r.Impact)
}

// InherentScore returns the threat's inherent (pre-control) risk score on a
// 0–100 scale.
func (r *Risk) InherentScore() float64 {
	if r == nil {
		return 0
	}
	return defaultRiskModel.score(r.Likelihood, r.Impact)
}

// residualFactor returns the multiplier left after applying the risk_reduction
// of every implemented control via diminishing returns: Π(1 − rᵢ/100). With no
// implemented controls it returns 1 (no reduction).
func (t *Threat) residualFactor() float64 {
	factor := 1.0
	for _, c := range t.Controls {
		if c == nil || !c.Implemented {
			continue
		}
		r := float64(c.RiskReduction)
		if r <= 0 {
			continue
		}
		if r > 100 {
			r = 100
		}
		factor *= 1 - (r / 100)
	}
	return factor
}

// ResidualScore returns the residual (post-control) risk score: the inherent
// score reduced by the aggregate risk_reduction of implemented controls. It
// returns 0 if the threat has no risk block.
func (t *Threat) ResidualScore() float64 {
	if t.Risk == nil {
		return 0
	}
	return round1(t.Risk.InherentScore() * t.residualFactor())
}

// ResidualSeverity returns the severity band for the residual score. Note this
// is the coarse score-band view (see RiskModel.Thresholds) used for the
// "inherent → residual" narrative; the authoritative inherent band comes from
// Risk.Severity. Returns "" if the threat has no risk block.
func (t *Threat) ResidualSeverity() string {
	if t.Risk == nil {
		return ""
	}
	return defaultRiskModel.bandForScore(t.ResidualScore())
}

// ResidualRiskReduction returns the aggregate percentage by which implemented
// controls reduce the inherent risk, i.e. (1 − Π(1 − rᵢ/100)) × 100.
func (t *Threat) ResidualRiskReduction() float64 {
	return round1((1 - t.residualFactor()) * 100)
}

// round1 rounds to one decimal place.
func round1(f float64) float64 {
	return math.Round(f*10) / 10
}

// canonicalRiskToken lowercases input and collapses spaces/hyphens to single
// underscores so "Very High", "very-high" and "VERY_HIGH" all normalize to
// "very_high".
func canonicalRiskToken(in string) string {
	s := strings.ToLower(strings.TrimSpace(in))
	s = strings.ReplaceAll(s, "-", "_")
	s = strings.ReplaceAll(s, " ", "_")
	for strings.Contains(s, "__") {
		s = strings.ReplaceAll(s, "__", "_")
	}
	return s
}
