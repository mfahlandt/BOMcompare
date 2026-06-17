package compare

// Category weights mirror the manual kubelb comparison's scorecard. Higher
// weight categories dominate the composite score.
const (
	wCritical = 3.0
	wHigh     = 2.5
	wMedium   = 1.5
	wLow      = 1.0
)

// buildScorecard assembles the per-category star rows used by the summary and
// markdown renderers.
func buildScorecard(r *Report) []ScoreRow {
	rows := []ScoreRow{
		{
			Category: "Completeness",
			Weight:   "High",
			weight:   wHigh,
			StarsA:   r.Completeness.StarsA,
			StarsB:   r.Completeness.StarsB,
			Note:     completenessNote(r),
		},
		{
			Category: "Version Accuracy",
			Weight:   "High",
			weight:   wHigh,
			StarsA:   r.Versions.StarsA,
			StarsB:   r.Versions.StarsB,
			Note:     versionNote(r),
		},
		{
			Category: "License Coverage",
			Weight:   "Critical (CRA)",
			weight:   wCritical,
			StarsA:   r.Licenses.StarsA,
			StarsB:   r.Licenses.StarsB,
			Note:     licenseNote(r),
		},
		{
			Category: "Dependency Graph",
			Weight:   "Medium",
			weight:   wMedium,
			StarsA:   r.Deps.StarsA,
			StarsB:   r.Deps.StarsB,
			Note:     depNote(r),
		},
		{
			Category: "Supplier Attribution",
			Weight:   "Medium",
			weight:   wMedium,
			StarsA:   r.Suppliers.StarsA,
			StarsB:   r.Suppliers.StarsB,
			Note:     supplierNote(r),
		},
		{
			Category: "Checksum Coverage",
			Weight:   "Medium",
			weight:   wMedium,
			StarsA:   r.Checksums.StarsA,
			StarsB:   r.Checksums.StarsB,
			Note:     checksumNote(r),
		},
		{
			Category: "PURL Quality",
			Weight:   "Medium",
			weight:   wMedium,
			StarsA:   r.PURLs.StarsA,
			StarsB:   r.PURLs.StarsB,
			Note:     purlNote(r),
		},
		{
			Category: "CPE Coverage",
			Weight:   "Low",
			weight:   wLow,
			StarsA:   r.CPEs.StarsA,
			StarsB:   r.CPEs.StarsB,
			Note:     cpeNote(r),
		},
		{
			Category: "Annotations/Transparency",
			Weight:   "Low",
			weight:   wLow,
			StarsA:   r.Annotations.StarsA,
			StarsB:   r.Annotations.StarsB,
			Note:     annotationNote(r),
		},
	}
	return rows
}

// computeOverall produces the weighted composite scores and CI signals.
func computeOverall(r *Report, s *Sets, opts Options) Overall {
	var sumA, sumB, sumW float64
	for _, row := range r.Scorecard {
		sumA += float64(row.StarsA) * row.weight
		sumB += float64(row.StarsB) * row.weight
		sumW += row.weight
	}
	o := Overall{}
	if sumW > 0 {
		o.ScoreA = round1(sumA / sumW)
		o.ScoreB = round1(sumB / sumW)
	}
	switch {
	case o.ScoreA > o.ScoreB+0.05:
		o.Winner = r.LabelA
	case o.ScoreB > o.ScoreA+0.05:
		o.Winner = r.LabelB
	default:
		o.Winner = "tie"
	}

	// Diff signals.
	o.HasDiff = len(s.OnlyA) > 0 || len(s.OnlyB) > 0 ||
		r.Versions.Mismatch > 0 || r.Licenses.Differing > 0

	// "Significant" excludes test-scoped uniques and context-explained omissions.
	runtimeUniqueA := len(s.OnlyA) - r.Completeness.OnlyATestScoped
	runtimeUniqueB := len(s.OnlyB) - r.Completeness.OnlyBTestScoped
	if runtimeUniqueA < 0 {
		runtimeUniqueA = 0
	}
	if runtimeUniqueB < 0 {
		runtimeUniqueB = 0
	}
	uniqueRuntime := runtimeUniqueA + runtimeUniqueB
	o.Significant = r.Versions.Mismatch > 0 ||
		uniqueRuntime >= opts.SignificantThreshold
	// If the two SBOMs are explicitly different scopes (source vs binary), the
	// large package delta is expected: only version mismatches gate CI.
	if r.ContextNote != "" {
		o.Significant = r.Versions.Mismatch > 0
	}
	return o
}

func round1(f float64) float64 {
	return float64(int(f*10+0.5)) / 10
}
