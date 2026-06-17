package sbom

import (
	"encoding/xml"
	"fmt"
	"strings"
)

// CycloneDX XML uses a different shape than JSON for several collections
// (dependencies nest <dependency ref=...> children; tools live under
// <tools><tool>). Rather than overload the JSON structs with fragile xml tags,
// we decode XML into dedicated types and convert to the shared CycloneDXDocument.

type cdxXMLBOM struct {
	XMLName      xml.Name            `xml:"bom"`
	SerialNumber string              `xml:"serialNumber,attr"`
	Version      int                 `xml:"version,attr"`
	Metadata     cdxXMLMetadata      `xml:"metadata"`
	Components   []cdxXMLComponent   `xml:"components>component"`
	Dependencies []cdxXMLDependency  `xml:"dependencies>dependency"`
	Compositions []cdxXMLComposition `xml:"compositions>composition"`
	Annotations  []cdxXMLAnnotation  `xml:"annotations>annotation"`
}

type cdxXMLMetadata struct {
	Timestamp string            `xml:"timestamp"`
	Tools     []cdxXMLTool      `xml:"tools>tool"`
	ToolComps []cdxXMLComponent `xml:"tools>components>component"`
	Component *cdxXMLComponent  `xml:"component"`
}

type cdxXMLTool struct {
	Vendor  string `xml:"vendor"`
	Name    string `xml:"name"`
	Version string `xml:"version"`
}

type cdxXMLComponent struct {
	Type        string            `xml:"type,attr"`
	BOMRef      string            `xml:"bom-ref,attr"`
	Name        string            `xml:"name"`
	Version     string            `xml:"version"`
	Group       string            `xml:"group"`
	PURL        string            `xml:"purl"`
	CPE         string            `xml:"cpe"`
	Scope       string            `xml:"scope"`
	Publisher   string            `xml:"publisher"`
	Author      string            `xml:"author"`
	Supplier    *cdxXMLOrg        `xml:"supplier"`
	Hashes      []cdxXMLHash      `xml:"hashes>hash"`
	Licenses    []cdxXMLLicense   `xml:"licenses>license"`
	LicenseExpr []string          `xml:"licenses>expression"`
	Properties  []cdxXMLProperty  `xml:"properties>property"`
	Components  []cdxXMLComponent `xml:"components>component"`
}

type cdxXMLOrg struct {
	Name string `xml:"name"`
}

type cdxXMLHash struct {
	Alg     string `xml:"alg,attr"`
	Content string `xml:",chardata"`
}

type cdxXMLLicense struct {
	ID   string `xml:"id"`
	Name string `xml:"name"`
}

type cdxXMLProperty struct {
	Name  string `xml:"name,attr"`
	Value string `xml:",chardata"`
}

type cdxXMLDependency struct {
	Ref       string             `xml:"ref,attr"`
	DependsOn []cdxXMLDependency `xml:"dependency"`
}

type cdxXMLComposition struct {
	Aggregate string `xml:"aggregate"`
}

type cdxXMLAnnotation struct {
	Text string `xml:"text"`
}

// parseCycloneDXXML decodes CycloneDX XML and converts it to the shared
// CycloneDXDocument type used by NormalizeCycloneDX.
func parseCycloneDXXML(data []byte) (*CycloneDXDocument, error) {
	var bom cdxXMLBOM
	if err := xml.Unmarshal(data, &bom); err != nil {
		return nil, fmt.Errorf("parse CycloneDX XML: %w", err)
	}
	if bom.XMLName.Local != "bom" {
		return nil, fmt.Errorf("not a CycloneDX XML document (root <%s>)", bom.XMLName.Local)
	}

	doc := &CycloneDXDocument{
		BOMFormat:    "CycloneDX",
		SerialNumber: bom.SerialNumber,
		Version:      bom.Version,
	}

	meta := &CDXMetadata{Timestamp: bom.Metadata.Timestamp}
	for _, t := range bom.Metadata.Tools {
		meta.Tools.Tools = append(meta.Tools.Tools, CDXTool{
			Vendor: t.Vendor, Name: t.Name, Version: t.Version,
		})
	}
	for _, c := range bom.Metadata.ToolComps {
		meta.Tools.Components = append(meta.Tools.Components, convertXMLComponent(&c))
	}
	if bom.Metadata.Component != nil {
		mc := convertXMLComponent(bom.Metadata.Component)
		meta.Component = &mc
	}
	doc.Metadata = meta

	for i := range bom.Components {
		doc.Components = append(doc.Components, convertXMLComponent(&bom.Components[i]))
	}

	for _, d := range bom.Dependencies {
		dep := CDXDependency{Ref: d.Ref}
		for _, on := range d.DependsOn {
			dep.DependsOn = append(dep.DependsOn, on.Ref)
		}
		doc.Dependencies = append(doc.Dependencies, dep)
	}

	for _, comp := range bom.Compositions {
		doc.Compositions = append(doc.Compositions, CDXComposition{Aggregate: comp.Aggregate})
	}
	for _, a := range bom.Annotations {
		doc.Annotations = append(doc.Annotations, CDXAnnotation{Text: a.Text})
	}
	return doc, nil
}

func convertXMLComponent(x *cdxXMLComponent) CDXComponent {
	c := CDXComponent{
		Type:      x.Type,
		BOMRef:    x.BOMRef,
		Name:      x.Name,
		Version:   x.Version,
		Group:     x.Group,
		PURL:      x.PURL,
		CPEXML:    x.CPE,
		Scope:     x.Scope,
		Publisher: x.Publisher,
		Author:    x.Author,
	}
	if x.Supplier != nil {
		c.Supplier = &CDXOrg{Name: x.Supplier.Name}
	}
	for _, h := range x.Hashes {
		c.Hashes = append(c.Hashes, CDXHash{Alg: h.Alg, Content: strings.TrimSpace(h.Content)})
	}
	for _, l := range x.Licenses {
		c.Licenses = append(c.Licenses, CDXLicense{
			License: &CDXLicenseChoice{ID: l.ID, Name: l.Name},
		})
	}
	for _, e := range x.LicenseExpr {
		if strings.TrimSpace(e) != "" {
			c.Licenses = append(c.Licenses, CDXLicense{Expression: strings.TrimSpace(e)})
		}
	}
	for _, prop := range x.Properties {
		c.Properties = append(c.Properties, CDXProperty{
			Name: prop.Name, Value: strings.TrimSpace(prop.Value),
		})
	}
	for i := range x.Components {
		c.Components = append(c.Components, convertXMLComponent(&x.Components[i]))
	}
	return c
}
