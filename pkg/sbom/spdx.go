// Package sbom contains SPDX 2.3 JSON document types and parsing/normalization
// helpers used by the comparison engine.
package sbom

import "encoding/json"

// Document is the root of an SPDX 2.3 JSON document. Only the fields relevant to
// SBOM quality comparison are modeled; unknown fields are ignored by the JSON
// decoder.
type Document struct {
	SPDXVersion       string         `json:"spdxVersion"`
	DataLicense       string         `json:"dataLicense"`
	SPDXID            string         `json:"SPDXID"`
	Name              string         `json:"name"`
	DocumentNamespace string         `json:"documentNamespace"`
	CreationInfo      CreationInfo   `json:"creationInfo"`
	Packages          []Package      `json:"packages"`
	Files             []File         `json:"files"`
	Relationships     []Relationship `json:"relationships"`
	Annotations       []Annotation   `json:"annotations"`
	DocumentDescribes []string       `json:"documentDescribes"`
}

// CreationInfo holds document provenance, most importantly the list of creators
// (tools and organizations) used to label each SBOM in the report.
type CreationInfo struct {
	Created            string   `json:"created"`
	Creators           []string `json:"creators"`
	LicenseListVersion string   `json:"licenseListVersion"`
	Comment            string   `json:"comment"`
}

// Package is an SPDX package entry. License fields are typed as json.RawMessage
// upstream in some tools (object vs string); here SPDX 2.3 mandates strings, so
// we keep them as strings but tolerate NOASSERTION/NONE sentinels.
type Package struct {
	SPDXID           string        `json:"SPDXID"`
	Name             string        `json:"name"`
	VersionInfo      string        `json:"versionInfo"`
	Supplier         string        `json:"supplier"`
	Originator       string        `json:"originator"`
	DownloadLocation string        `json:"downloadLocation"`
	FilesAnalyzed    bool          `json:"filesAnalyzed"`
	SourceInfo       string        `json:"sourceInfo"`
	LicenseConcluded string        `json:"licenseConcluded"`
	LicenseDeclared  string        `json:"licenseDeclared"`
	CopyrightText    string        `json:"copyrightText"`
	Checksums        []Checksum    `json:"checksums"`
	ExternalRefs     []ExternalRef `json:"externalRefs"`
	Annotations      []Annotation  `json:"annotations"`
	PrimaryPurpose   string        `json:"primaryPackagePurpose"`
}

// File is an SPDX file entry. Only modeled so the decoder can round-trip; not
// used heavily by the comparison.
type File struct {
	SPDXID            string     `json:"SPDXID"`
	FileName          string     `json:"fileName"`
	Checksums         []Checksum `json:"checksums"`
	LicenseConcluded  string     `json:"licenseConcluded"`
	LicenseInfoInFile []string   `json:"licenseInfoInFiles"`
}

// Checksum is an algorithm/value pair (SHA256, SHA1, MD5, ...).
type Checksum struct {
	Algorithm     string `json:"algorithm"`
	ChecksumValue string `json:"checksumValue"`
}

// ExternalRef models PURL and CPE references via referenceType.
type ExternalRef struct {
	ReferenceCategory string `json:"referenceCategory"`
	ReferenceType     string `json:"referenceType"`
	ReferenceLocator  string `json:"referenceLocator"`
	Comment           string `json:"comment"`
}

// Relationship is a typed edge in the dependency graph.
type Relationship struct {
	SPDXElementID      string `json:"spdxElementId"`
	RelatedSPDXElement string `json:"relatedSpdxElement"`
	RelationshipType   string `json:"relationshipType"`
}

// Annotation is a free-form note attached to the document or a package. mikebom
// encodes structured metadata as JSON inside Comment.
type Annotation struct {
	Annotator      string `json:"annotator"`
	AnnotationDate string `json:"annotationDate"`
	AnnotationType string `json:"annotationType"`
	Comment        string `json:"comment"`
}

// AnnotationPayload is the structured JSON some tools embed inside an
// annotation's Comment field (e.g. mikebom-annotation/v1).
type AnnotationPayload struct {
	Schema string          `json:"schema"`
	Field  string          `json:"field"`
	Value  json.RawMessage `json:"value"`
}
