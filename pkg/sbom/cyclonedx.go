// Package sbom: CycloneDX JSON/XML document types.
//
// Only the fields relevant to SBOM quality comparison are modeled. CycloneDX
// v1.4 and v1.5 share enough structure that a single set of permissive types
// covers both; version-specific shapes (e.g. cpe/licenses that may be string or
// array) are decoded via json.RawMessage and resolved during normalization.
package sbom

import (
	"encoding/json"
	"strings"
)

// CycloneDXDocument is the root of a CycloneDX JSON BOM.
type CycloneDXDocument struct {
	BOMFormat    string           `json:"bomFormat" xml:"-"`
	SpecVersion  string           `json:"specVersion" xml:"-"`
	SerialNumber string           `json:"serialNumber" xml:"serialNumber,attr"`
	Version      int              `json:"version" xml:"version,attr"`
	Metadata     *CDXMetadata     `json:"metadata" xml:"metadata"`
	Components   []CDXComponent   `json:"components" xml:"components>component"`
	Dependencies []CDXDependency  `json:"dependencies" xml:"dependencies>dependency"`
	Annotations  []CDXAnnotation  `json:"annotations" xml:"annotations>annotation"`
	Compositions []CDXComposition `json:"compositions" xml:"compositions>composition"`
}

// CDXMetadata holds BOM-level provenance and the primary component.
type CDXMetadata struct {
	Timestamp string        `json:"timestamp" xml:"timestamp"`
	Tools     CDXToolsField `json:"tools" xml:"tools"`
	Component *CDXComponent `json:"component" xml:"component"`
	Supplier  *CDXOrg       `json:"supplier" xml:"supplier"`
}

// CDXToolsField tolerates both CycloneDX shapes for `tools`:
//   - v1.4 / early v1.5: an array of {vendor,name,version}
//   - v1.5+: an object {components:[...], services:[...]}
type CDXToolsField struct {
	Tools      []CDXTool      `json:"-" xml:"tool"`
	Components []CDXComponent `json:"-" xml:"-"`
}

// UnmarshalJSON handles the array-or-object ambiguity of metadata.tools.
func (t *CDXToolsField) UnmarshalJSON(data []byte) error {
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" || trimmed == "null" {
		return nil
	}
	switch trimmed[0] {
	case '[':
		var arr []CDXTool
		if err := json.Unmarshal(data, &arr); err != nil {
			return err
		}
		t.Tools = arr
	case '{':
		var obj struct {
			Components []CDXComponent `json:"components"`
		}
		if err := json.Unmarshal(data, &obj); err != nil {
			return err
		}
		t.Components = obj.Components
	}
	return nil
}

// CDXTool is a generating tool in the legacy array form.
type CDXTool struct {
	Vendor  string `json:"vendor" xml:"vendor"`
	Name    string `json:"name" xml:"name"`
	Version string `json:"version" xml:"version"`
}

// CDXComponent is a CycloneDX component (the analog of an SPDX package).
type CDXComponent struct {
	Type       string          `json:"type" xml:"type,attr"`
	BOMRef     string          `json:"bom-ref" xml:"bom-ref,attr"`
	Name       string          `json:"name" xml:"name"`
	Version    string          `json:"version" xml:"version"`
	Group      string          `json:"group" xml:"group"`
	PURL       string          `json:"purl" xml:"purl"`
	CPE        json.RawMessage `json:"cpe" xml:"-"`
	CPEXML     string          `json:"-" xml:"cpe"`
	Scope      string          `json:"scope" xml:"scope"`
	Supplier   *CDXOrg         `json:"supplier" xml:"supplier"`
	Publisher  string          `json:"publisher" xml:"publisher"`
	Author     string          `json:"author" xml:"author"`
	Hashes     []CDXHash       `json:"hashes" xml:"hashes>hash"`
	Licenses   []CDXLicense    `json:"licenses" xml:"licenses>license"`
	Evidence   *CDXEvidence    `json:"evidence" xml:"evidence"`
	Properties []CDXProperty   `json:"properties" xml:"properties>property"`
	Components []CDXComponent  `json:"components" xml:"components>component"`
}

// CDXOrg is an organizational reference (supplier/manufacturer).
type CDXOrg struct {
	Name string `json:"name" xml:"name"`
	URL  any    `json:"url" xml:"url"`
}

// CDXHash is a content hash with an algorithm label (e.g. "SHA-256").
type CDXHash struct {
	Alg     string `json:"alg" xml:"alg,attr"`
	Content string `json:"content" xml:",chardata"`
}

// CDXLicense is one entry of a component's licenses array. CycloneDX nests the
// SPDX id/name under a `license` object, but also allows an `expression` form.
type CDXLicense struct {
	License    *CDXLicenseChoice `json:"license" xml:"license"`
	Expression string            `json:"expression" xml:"expression"`
}

// CDXLicenseChoice carries either an SPDX id or a free-text name.
type CDXLicenseChoice struct {
	ID   string `json:"id" xml:"id"`
	Name string `json:"name" xml:"name"`
}

// CDXEvidence holds identity/quality evidence. The `identity` field may be a
// single object (v1.5) or an array (v1.6), so it is decoded permissively.
type CDXEvidence struct {
	Identity json.RawMessage `json:"identity" xml:"-"`
}

// CDXProperty is a name/value pair used for tool-specific metadata.
type CDXProperty struct {
	Name  string `json:"name" xml:"name,attr"`
	Value string `json:"value" xml:",chardata"`
}

// CDXDependency is one node of the dependency graph. `dependsOn` is a list of
// bom-refs the ref depends on.
type CDXDependency struct {
	Ref       string   `json:"ref" xml:"ref,attr"`
	DependsOn []string `json:"dependsOn" xml:"dependency>ref,attr"`
}

// CDXAnnotation is a BOM-level annotation.
type CDXAnnotation struct {
	Subjects  []string `json:"subjects" xml:"subjects>subject"`
	Annotator *CDXOrg  `json:"annotator" xml:"annotator"`
	Timestamp string   `json:"timestamp" xml:"timestamp"`
	Text      string   `json:"text" xml:"text"`
}

// CDXComposition describes aggregate completeness (e.g. "complete").
type CDXComposition struct {
	Aggregate    string   `json:"aggregate" xml:"aggregate"`
	Dependencies []string `json:"dependencies" xml:"dependencies>dependency"`
}

// cdxResolveCPE returns the component CPE regardless of JSON shape (string in
// practice; tolerated as array first element if a producer emits one).
func (c *CDXComponent) cdxResolveCPE() []string {
	if c.CPEXML != "" {
		return []string{c.CPEXML}
	}
	if len(c.CPE) == 0 {
		return nil
	}
	trimmed := strings.TrimSpace(string(c.CPE))
	if trimmed == "" || trimmed == "null" {
		return nil
	}
	switch trimmed[0] {
	case '"':
		var s string
		if json.Unmarshal(c.CPE, &s) == nil && s != "" {
			return []string{s}
		}
	case '[':
		var arr []string
		if json.Unmarshal(c.CPE, &arr) == nil {
			out := make([]string, 0, len(arr))
			for _, s := range arr {
				if s != "" {
					out = append(out, s)
				}
			}
			return out
		}
	}
	return nil
}

// cdxLicenseExpr resolves the first usable license expression from a component.
func cdxLicenseExpr(lics []CDXLicense) string {
	for _, l := range lics {
		if l.Expression != "" {
			return l.Expression
		}
		if l.License != nil {
			if l.License.ID != "" {
				return l.License.ID
			}
			if l.License.Name != "" {
				return l.License.Name
			}
		}
	}
	return ""
}

// cdxSupplierName resolves a display supplier from supplier/publisher/author.
func cdxSupplierName(c *CDXComponent) string {
	if c.Supplier != nil && c.Supplier.Name != "" {
		return c.Supplier.Name
	}
	if c.Publisher != "" {
		return c.Publisher
	}
	if c.Author != "" {
		return c.Author
	}
	return ""
}
