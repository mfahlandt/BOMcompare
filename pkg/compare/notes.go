package compare

import "fmt"

// These helpers generate the short comparative note shown per scorecard row.
// They favor the same phrasing style as the manual kubelb comparison.

func completenessNote(r *Report) string {
	c := r.Completeness
	diff := c.TotalA - c.TotalB
	switch {
	case diff > 0:
		return fmt.Sprintf("%s lists %d more packages (+%s)", r.LabelA, diff, pctStr(diff, c.TotalB))
	case diff < 0:
		return fmt.Sprintf("%s lists %d more packages (+%s)", r.LabelB, -diff, pctStr(-diff, c.TotalA))
	default:
		return "both list the same number of packages"
	}
}

func versionNote(r *Report) string {
	v := r.Versions
	if v.CommonChecked == 0 {
		return "no overlapping packages to compare versions"
	}
	if v.Mismatch == 0 {
		return fmt.Sprintf("100%% version agreement across %d common packages", v.CommonChecked)
	}
	return fmt.Sprintf("%d/%d version mismatches on the overlap", v.Mismatch, v.CommonChecked)
}

func licenseNote(r *Report) string {
	l := r.Licenses
	return fmt.Sprintf("effective license coverage %.1f%% vs %.1f%%; declared %.1f%%/%.1f%%, concluded %.1f%%/%.1f%%",
		l.EffectiveRateA, l.EffectiveRateB, l.DeclaredRateA, l.DeclaredRateB, l.ConcludedRateA, l.ConcludedRateB)
}

func depNote(r *Report) string {
	d := r.Deps
	note := fmt.Sprintf("%d vs %d relationship edges", d.TotalA, d.TotalB)
	switch {
	case d.HasTestLabelingA && !d.HasTestLabelingB:
		note += fmt.Sprintf("; %s labels test deps", r.LabelA)
	case d.HasTestLabelingB && !d.HasTestLabelingA:
		note += fmt.Sprintf("; %s labels test deps", r.LabelB)
	}
	return note
}

func supplierNote(r *Report) string {
	s := r.Suppliers
	return fmt.Sprintf("supplier coverage %.1f%% vs %.1f%%", s.RateA, s.RateB)
}

func checksumNote(r *Report) string {
	c := r.Checksums
	return fmt.Sprintf("SHA256 coverage %.1f%% vs %.1f%%", c.RateA, c.RateB)
}

func purlNote(r *Report) string {
	q := r.PURLs
	if q.MainPURLNote != "" {
		return "main module purl specificity differs"
	}
	return fmt.Sprintf("purl coverage %.1f%% vs %.1f%%", q.PURLRateA, q.PURLRateB)
}

func cpeNote(r *Report) string {
	c := r.CPEs
	return fmt.Sprintf("CPE on %.1f%% vs %.1f%% of packages (avg %.1f vs %.1f per pkg)",
		c.PkgCPERateA, c.PkgCPERateB, c.AvgPerPkgA, c.AvgPerPkgB)
}

func annotationNote(r *Report) string {
	a := r.Annotations
	return fmt.Sprintf("%d/%d doc-level, %d vs %d packages annotated",
		a.DocLevelA, a.DocLevelB, a.PkgWithAnnA, a.PkgWithAnnB)
}

func pctStr(num, denom int) string {
	if denom == 0 {
		return "n/a"
	}
	return fmt.Sprintf("%.0f%%", float64(num)/float64(denom)*100)
}
