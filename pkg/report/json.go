package report

import (
	"encoding/json"

	"github.com/seebom-labs/BOMHort/BOMcompare/pkg/compare"
)

// RenderJSON serializes the full structured report as indented JSON.
func RenderJSON(r *compare.Report) (string, error) {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return "", err
	}
	return string(b), nil
}
