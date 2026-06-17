package report

import (
	"encoding/json"

	"github.com/mfahlandt/sbom-comparison/pkg/compare"
)

// RenderJSON serializes the full structured report as indented JSON.
func RenderJSON(r *compare.Report) (string, error) {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return "", err
	}
	return string(b), nil
}
