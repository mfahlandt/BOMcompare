package sbom

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strings"
)

// Sentinel license/field values used across SPDX.
const (
	NoAssertion = "NOASSERTION"
	None        = "NONE"
)

// Parsed is a normalized, comparison-friendly view of an SPDX document. It is
// derived once from a Document so the comparison engine never has to re-walk raw
// SPDX structures.
type Parsed struct {
	// Source identification.
	FilePath  string
	ToolLabel string // e.g. "mikebom v0.1.0-alpha.47" or "syft v1.42.3"
	ToolName  string // e.g. "mikebom"
	Context   string // "source", "binary", or "unknown"

	// Normalized package set, keyed by SPDXID for relationship resolution.
	Packages []NormalizedPackage
	BySPDXID map[string]*NormalizedPackage

	// Raw graph + document annotations.
	Relationships  []Relationship
	DocAnnotations []Annotation

	// Format identifies the source serialization: "spdx-json",
	// "spdx-tagvalue", "spdx3-jsonld", "cyclonedx-json" or "cyclonedx-xml".
	Format string

	// Meta holds document-level metadata (author, tools, timestamp, lifecycle)
	// used for minimum-elements compliance checks.
	Meta DocMeta

	// Exactly one of Raw / CycloneDX is set, depending on Format. SPDX 3
	// documents are converted to the SPDX 2-shaped Raw document.
	Raw       *Document
	CycloneDX *CycloneDXDocument
}

// DocMeta is format-independent document metadata, mapped onto the SBOM
// document fields named by the CISA 2026 Minimum Elements.
type DocMeta struct {
	// SpecVersion is the data format version, e.g. "SPDX-2.3", "SPDX-3.0.1" or
	// "CycloneDX-1.6". Empty if the document does not state it.
	SpecVersion string `json:"specVersion"`
	// Created is the document timestamp as written in the SBOM.
	Created string `json:"created"`
	// Authors are the non-tool creators (organizations / persons).
	Authors []string `json:"authors,omitempty"`
	// Tools are the generating tools; ToolVersions the subset that carry a
	// version.
	Tools        []string `json:"tools,omitempty"`
	ToolVersions []string `json:"toolVersions,omitempty"`
	// Lifecycle is the explicitly declared generation context (CycloneDX
	// metadata.lifecycles phase, SPDX 3 software_sbomType, or a tool
	// annotation), e.g. "pre-build", "post-build", "source", "analyzed".
	Lifecycle string `json:"lifecycle,omitempty"`
	// DocVersion identifies this revision of the SBOM (CycloneDX
	// serialNumber/version, SPDX documentNamespace / SpdxDocument id).
	DocVersion string `json:"docVersion,omitempty"`
	// DependencyDeclared lists element IDs whose dependency set was stated
	// explicitly even when empty (CycloneDX dependencies[].ref with no
	// dependsOn). Used for dependency-relationship coverage.
	DependencyDeclared map[string]bool `json:"-"`
	// Signed reports an enveloped in-document signature (CycloneDX JSF or
	// XML-DSig). Detached signatures and attestations are not visible here.
	Signed bool `json:"signed,omitempty"`
}

// Format identifiers returned by DetectFormat and stored on Parsed.Format.
const (
	FormatSPDXJSON      = "spdx-json"
	FormatSPDXTagValue  = "spdx-tagvalue"
	FormatSPDX3JSONLD   = "spdx3-jsonld"
	FormatCycloneDXJSON = "cyclonedx-json"
	FormatCycloneDXXML  = "cyclonedx-xml"
	FormatUnknown       = "unknown"
)

// NormalizedPackage flattens the SPDX fields that matter for quality comparison.
type NormalizedPackage struct {
	SPDXID  string
	Name    string
	Version string

	// Identity.
	PURL       string   // primary purl (first PACKAGE-MANAGER purl ref)
	PURLType   string   // e.g. "golang", "generic", "npm"
	ModulePath string   // best-effort module path for cross-type matching
	CPEs       []string // all CPE 2.3 locators
	// OtherIDs are additional identifiers (SWID, OmniBOR gitoid, SWHID).
	OtherIDs []string

	// License.
	LicenseDeclared  string
	LicenseConcluded string

	// Attribution / integrity.
	Supplier    string
	Originator  string // SPDX originator / CycloneDX manufacturer or authors
	HasSHA256   bool
	ChecksumNum int

	// Scope.
	IsTestScoped bool // detected via TEST_DEPENDENCY_OF or lifecycle annotation

	// Transparency.
	Annotations []Annotation

	// Flags.
	IsMainModule bool
	IsStdlib     bool
}

// Load reads a file, auto-detects its SBOM format and returns a normalized
// Parsed view. Supported formats: SPDX JSON, SPDX tag-value, CycloneDX JSON and
// CycloneDX XML.
func Load(path string) (*Parsed, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	format := DetectFormat(data)
	p, err := loadFormat(format, data, path)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	p.Format = format
	p.FilePath = path
	return p, nil
}

// loadFormat dispatches to the correct parser/normalizer for a detected format.
func loadFormat(format string, data []byte, path string) (*Parsed, error) {
	switch format {
	case FormatSPDXJSON:
		doc := &Document{}
		if err := json.Unmarshal(data, doc); err != nil {
			return nil, fmt.Errorf("parse as SPDX JSON: %w", err)
		}
		if doc.SPDXVersion == "" {
			return nil, fmt.Errorf("missing spdxVersion (not an SPDX document?)")
		}
		return Normalize(doc), nil
	case FormatSPDXTagValue:
		doc, err := parseSPDXTagValue(data)
		if err != nil {
			return nil, err
		}
		return Normalize(doc), nil
	case FormatSPDX3JSONLD:
		return parseSPDX3(data)
	case FormatCycloneDXJSON:
		doc, err := parseCycloneDXJSON(data)
		if err != nil {
			return nil, err
		}
		return NormalizeCycloneDX(doc), nil
	case FormatCycloneDXXML:
		doc, err := parseCycloneDXXML(data)
		if err != nil {
			return nil, err
		}
		return NormalizeCycloneDX(doc), nil
	default:
		return nil, fmt.Errorf("unrecognized SBOM format (not SPDX 2 JSON/tag-value, SPDX 3 JSON-LD or CycloneDX JSON/XML)")
	}
}

// LoadSPDX3 parses a file as SPDX 3 JSON-LD regardless of detection.
func LoadSPDX3(path string) (*Parsed, error) {
	return loadExplicit(FormatSPDX3JSONLD, path)
}

// LoadSPDXJSON parses bytes as SPDX JSON regardless of detection.
func LoadSPDXJSON(path string) (*Parsed, error) {
	return loadExplicit(FormatSPDXJSON, path)
}

// LoadSPDXTagValue parses a file as SPDX tag-value regardless of detection.
func LoadSPDXTagValue(path string) (*Parsed, error) {
	return loadExplicit(FormatSPDXTagValue, path)
}

// LoadCycloneDX parses a file as CycloneDX, auto-selecting JSON vs XML by
// sniffing the first non-whitespace byte.
func LoadCycloneDX(path string) (*Parsed, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	format := FormatCycloneDXJSON
	if b := firstNonSpace(data); b == '<' {
		format = FormatCycloneDXXML
	}
	p, err := loadFormat(format, data, path)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	p.Format = format
	p.FilePath = path
	return p, nil
}

func loadExplicit(format, path string) (*Parsed, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	p, err := loadFormat(format, data, path)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	p.Format = format
	p.FilePath = path
	return p, nil
}

// DetectFormat sniffs SBOM bytes and returns one of the Format* constants.
//
// Heuristics (in order):
//   - leading '<' (after optional BOM / xml prolog) → CycloneDX XML
//   - leading '{' or '[' → JSON; distinguished by "spdxVersion" (SPDX 2),
//     an SPDX 3 JSON-LD "@context" / "@graph" (SPDX 3) or
//     "bomFormat"/"specVersion" (CycloneDX)
//   - presence of "SPDXVersion:" / "PackageName:" lines → SPDX tag-value
func DetectFormat(data []byte) string {
	b := firstNonSpace(data)
	switch b {
	case '<':
		return FormatCycloneDXXML
	case '{', '[':
		// JSON: decide SPDX vs CycloneDX by key presence. Use a cheap substring
		// probe on the head to avoid decoding huge files twice.
		head := data
		if len(head) > 4096 {
			head = head[:4096]
		}
		if f := detectJSONMarkers(string(head)); f != FormatUnknown {
			return f
		}
		// Fall back to a full scan of the whole document for the markers.
		return detectJSONMarkers(string(data))
	case 0:
		return FormatUnknown
	default:
		// Likely tag-value text. Confirm by looking for an SPDX tag.
		probe := data
		if len(probe) > 8192 {
			probe = probe[:8192]
		}
		ps := string(probe)
		if strings.Contains(ps, "SPDXVersion:") || strings.Contains(ps, "PackageName:") ||
			strings.Contains(ps, "SPDXID:") || strings.Contains(ps, "DocumentName:") {
			return FormatSPDXTagValue
		}
		return FormatUnknown
	}
}

// detectJSONMarkers classifies a JSON SBOM by its distinguishing keys. SPDX 3
// is checked before CycloneDX because SPDX 3 CreationInfo also carries a
// "specVersion" key.
func detectJSONMarkers(s string) string {
	switch {
	case strings.Contains(s, "\"spdxVersion\""):
		return FormatSPDXJSON
	case isSPDX3JSONLD(s):
		return FormatSPDX3JSONLD
	case strings.Contains(s, "\"bomFormat\"") || strings.Contains(s, "\"specVersion\""):
		return FormatCycloneDXJSON
	}
	return FormatUnknown
}

// isSPDX3JSONLD reports whether JSON text looks like an SPDX 3 JSON-LD
// serialization: an SPDX RDF context, or an @graph of SPDX-typed elements.
func isSPDX3JSONLD(s string) bool {
	if strings.Contains(s, "spdx.org/rdf/3") {
		return true
	}
	return strings.Contains(s, "\"@graph\"") &&
		(strings.Contains(s, "\"SpdxDocument\"") || strings.Contains(s, "\"software_Package\"") ||
			strings.Contains(s, "\"spdxId\""))
}

// firstNonSpace returns the first non-whitespace byte, skipping a UTF-8 BOM and
// an optional XML prolog whitespace. Returns 0 if the input is empty/space-only.
func firstNonSpace(data []byte) byte {
	// Skip UTF-8 BOM.
	if len(data) >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF {
		data = data[3:]
	}
	for _, c := range data {
		switch c {
		case ' ', '\t', '\r', '\n':
			continue
		default:
			return c
		}
	}
	return 0
}

// Normalize converts a raw SPDX Document into a Parsed view. Callers that use
// Load get Format set for them; when Normalize is called directly the format
// defaults to SPDX JSON (the only serialization that decodes into Document via
// JSON).
func Normalize(doc *Document) *Parsed {
	p := &Parsed{
		Raw:            doc,
		Format:         FormatSPDXJSON,
		Relationships:  doc.Relationships,
		DocAnnotations: doc.Annotations,
		BySPDXID:       make(map[string]*NormalizedPackage, len(doc.Packages)),
	}
	p.ToolLabel, p.ToolName = toolLabel(doc.CreationInfo.Creators)

	// First pass: normalize package fields.
	for i := range doc.Packages {
		np := normalizePackage(&doc.Packages[i])
		p.Packages = append(p.Packages, np)
	}
	// Index by SPDXID (pointer into slice; slice is now stable).
	for i := range p.Packages {
		p.BySPDXID[p.Packages[i].SPDXID] = &p.Packages[i]
	}

	// Second pass: apply graph-derived scope (TEST_DEPENDENCY_OF) and main-module
	// detection from DESCRIBES/documentDescribes.
	applyScopeFromGraph(p, doc)
	applyMainModule(p, doc)

	p.Meta = spdxDocMeta(doc, p)
	p.Context = detectContext(doc, p)
	return p
}

// spdxDocMeta extracts document metadata from an SPDX 2 creationInfo block.
func spdxDocMeta(doc *Document, p *Parsed) DocMeta {
	m := DocMeta{
		SpecVersion: doc.SPDXVersion,
		Created:     doc.CreationInfo.Created,
		DocVersion:  doc.DocumentNamespace,
	}
	for _, c := range doc.CreationInfo.Creators {
		c = strings.TrimSpace(c)
		switch {
		case strings.HasPrefix(c, "Tool:"):
			rest := strings.TrimSpace(strings.TrimPrefix(c, "Tool:"))
			if idx := strings.Index(rest, " source:"); idx >= 0 {
				rest = strings.TrimSpace(rest[:idx])
			}
			if rest == "" || containsStr(m.Tools, rest) {
				continue
			}
			m.Tools = append(m.Tools, rest)
			if _, v := splitToolVersion(rest); v != "" {
				m.ToolVersions = append(m.ToolVersions, rest)
			}
		case strings.HasPrefix(c, "Organization:"), strings.HasPrefix(c, "Person:"):
			if name := strings.TrimSpace(c[strings.IndexByte(c, ':')+1:]); name != "" {
				m.Authors = append(m.Authors, name)
			}
		}
	}
	m.Lifecycle = annotatedLifecycle(p.DocAnnotations)
	return m
}

// annotatedLifecycle returns an explicitly annotated generation context
// (e.g. mikebom's "sbom-tier" annotation), if any.
func annotatedLifecycle(anns []Annotation) string {
	for _, a := range anns {
		var payload AnnotationPayload
		if json.Unmarshal([]byte(a.Comment), &payload) != nil {
			continue
		}
		f := strings.ToLower(payload.Field)
		if !strings.HasSuffix(f, "sbom-tier") && !strings.HasSuffix(f, "lifecycle") &&
			!strings.HasSuffix(f, "sbom-type") {
			continue
		}
		var v string
		if json.Unmarshal(payload.Value, &v) == nil && v != "" {
			return v
		}
	}
	return ""
}

func containsStr(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// toolLabel returns a human label ("syft v1.42.3") and a short name ("syft")
// from the SPDX creators list. Tool creators look like "Tool: <name>-<version>"
// or "Tool: <name> <version>".
func toolLabel(creators []string) (label, name string) {
	for _, c := range creators {
		c = strings.TrimSpace(c)
		if !strings.HasPrefix(c, "Tool:") {
			continue
		}
		rest := strings.TrimSpace(strings.TrimPrefix(c, "Tool:"))
		// Drop any trailing " source: ..." provenance appended by some tools.
		if idx := strings.Index(rest, " source:"); idx >= 0 {
			rest = strings.TrimSpace(rest[:idx])
		}
		if rest == "" {
			continue
		}
		n, v := splitToolVersion(rest)
		if v != "" {
			return n + " v" + strings.TrimPrefix(v, "v"), n
		}
		return n, n
	}
	// Fall back to first creator or a generic label.
	if len(creators) > 0 {
		return creators[0], creators[0]
	}
	return "unknown-tool", "unknown"
}

// splitToolVersion splits "syft-1.42.3", "syft 1.42.3" or "mikebom-0.1.0-alpha.47"
// into name and version. A space-separated trailing token is only treated as a
// version when it looks like one, so multi-word tool names ("Source Auditor
// Open Source Console") stay intact.
func splitToolVersion(s string) (name, version string) {
	s = strings.TrimSpace(s)
	if i := strings.LastIndexByte(s, ' '); i >= 0 && looksLikeVersion(s[i+1:]) {
		return strings.TrimSpace(s[:i]), s[i+1:]
	}
	// Otherwise split on the first '-' that is followed by a digit.
	for i := 0; i < len(s)-1; i++ {
		if s[i] == '-' && s[i+1] >= '0' && s[i+1] <= '9' {
			return s[:i], s[i+1:]
		}
	}
	return s, ""
}

// looksLikeVersion reports whether a token starts with a digit, optionally
// prefixed by "v" (e.g. "1.42.3", "v0.1.0-alpha.47").
func looksLikeVersion(tok string) bool {
	tok = strings.TrimPrefix(strings.TrimPrefix(tok, "v"), "V")
	return tok != "" && tok[0] >= '0' && tok[0] <= '9'
}

func normalizePackage(pkg *Package) NormalizedPackage {
	np := NormalizedPackage{
		SPDXID:           pkg.SPDXID,
		Name:             pkg.Name,
		Version:          pkg.VersionInfo,
		LicenseDeclared:  pkg.LicenseDeclared,
		LicenseConcluded: pkg.LicenseConcluded,
		Supplier:         pkg.Supplier,
		Originator:       pkg.Originator,
		Annotations:      pkg.Annotations,
	}

	// Identity from external refs.
	for _, ref := range pkg.ExternalRefs {
		switch ref.ReferenceType {
		case "purl":
			if np.PURL == "" {
				np.PURL = ref.ReferenceLocator
			}
		case "cpe23Type", "cpe23", "cpe", "cpe22Type":
			if ref.ReferenceLocator != "" {
				np.CPEs = append(np.CPEs, ref.ReferenceLocator)
			}
		case "swid", "gitoid", "swh":
			if ref.ReferenceLocator != "" {
				np.OtherIDs = append(np.OtherIDs, ref.ReferenceLocator)
			}
		}
	}
	np.PURLType, np.ModulePath = parsePURL(np.PURL, np.Name)

	// Checksums.
	np.ChecksumNum = len(pkg.Checksums)
	for _, c := range pkg.Checksums {
		if strings.EqualFold(c.Algorithm, "SHA256") && c.ChecksumValue != "" {
			np.HasSHA256 = true
		}
	}

	// Scope from package-level lifecycle annotations (e.g. mikebom).
	if hasTestLifecycleAnnotation(pkg.Annotations) {
		np.IsTestScoped = true
	}

	// Stdlib heuristic.
	if isStdlib(np.Name, np.PURL) {
		np.IsStdlib = true
	}
	return np
}

// parsePURL extracts the purl type and a best-effort module path. For
// pkg:golang/<module>@<v> the module path is the namespace+name. For
// pkg:generic/<name>@<v> there is no module path, so we fall back to the package
// name to allow cross-type matching of the main module.
func parsePURL(purl, fallbackName string) (purlType, modulePath string) {
	if purl == "" {
		return "", strings.ToLower(fallbackName)
	}
	rest := strings.TrimPrefix(purl, "pkg:")
	// type is up to the first '/'.
	slash := strings.IndexByte(rest, '/')
	if slash < 0 {
		// e.g. "pkg:golang" with no path — unusual.
		return strings.SplitN(rest, "@", 2)[0], strings.ToLower(fallbackName)
	}
	purlType = strings.ToLower(rest[:slash])
	pathAndVer := rest[slash+1:]
	// Strip qualifiers (?...) and subpath (#...), then the version (@...).
	if i := strings.IndexAny(pathAndVer, "?#"); i >= 0 {
		pathAndVer = pathAndVer[:i]
	}
	if at := versionAt(pathAndVer); at >= 0 {
		pathAndVer = pathAndVer[:at]
	}
	// purl components are percent-encoded (e.g. npm scopes "%40angular").
	modulePath = strings.ToLower(purlUnescape(strings.Trim(pathAndVer, "/")))
	if modulePath == "" {
		modulePath = strings.ToLower(fallbackName)
	}
	return purlType, modulePath
}

// purlUnescape percent-decodes a purl component, returning it unchanged if it
// is not validly encoded.
func purlUnescape(s string) string {
	if !strings.Contains(s, "%") {
		return s
	}
	if u, err := url.PathUnescape(s); err == nil {
		return u
	}
	return s
}

// PURLVersion extracts the @version portion of a purl, if present.
func PURLVersion(purl string) string {
	// Only the part before qualifiers/subpath can carry the version; an '@'
	// inside a qualifier value (e.g. repository_url) must not be mistaken for it.
	if i := strings.IndexAny(purl, "?#"); i >= 0 {
		purl = purl[:i]
	}
	at := versionAt(purl)
	if at < 0 {
		return ""
	}
	return purlUnescape(purl[at+1:])
}

// versionAt returns the index of the '@' that separates the purl version, or
// -1. An '@' that starts a path segment (an unencoded npm scope such as
// "@angular/core") is part of the name, not a version separator.
func versionAt(s string) int {
	at := strings.LastIndexByte(s, '@')
	if at <= 0 || s[at-1] == '/' || strings.Contains(s[at+1:], "/") {
		return -1
	}
	return at
}

// PURLHasQualifiers reports whether the purl carries ?key=value qualifiers.
func PURLHasQualifiers(purl string) bool {
	return strings.Contains(purl, "?")
}

func hasTestLifecycleAnnotation(anns []Annotation) bool {
	for _, a := range anns {
		c := a.Comment
		if !strings.Contains(c, "lifecycle-scope") {
			continue
		}
		var payload AnnotationPayload
		if json.Unmarshal([]byte(c), &payload) == nil {
			var v string
			if json.Unmarshal(payload.Value, &v) == nil && strings.EqualFold(v, "test") {
				return true
			}
		}
		// Fallback to substring match if not structured.
		if strings.Contains(c, "\"test\"") || strings.Contains(c, ":test") {
			return true
		}
	}
	return false
}

func isStdlib(name, purl string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	if n == "stdlib" || n == "go-stdlib" {
		return true
	}
	return strings.Contains(strings.ToLower(purl), "pkg:golang/std")
}

// applyScopeFromGraph marks packages as test-scoped when they are the SUBJECT of
// a TEST_DEPENDENCY_OF relationship (i.e. "X is a test dependency of Y" marks X,
// not Y). Marking the target Y would incorrectly flag the main module as test.
func applyScopeFromGraph(p *Parsed, doc *Document) {
	for _, r := range doc.Relationships {
		if !strings.EqualFold(r.RelationshipType, "TEST_DEPENDENCY_OF") {
			continue
		}
		if np := p.BySPDXID[r.SPDXElementID]; np != nil {
			np.IsTestScoped = true
		}
	}
}

// applyMainModule flags the package(s) the document DESCRIBES. Some tools (e.g.
// syft) describe a synthetic "DocumentRoot-*" wrapper rather than the real
// artifact; only for such wrappers (or described elements that are not
// packages) do we resolve one hop via DESCRIBES/CONTAINS/GENERATED_FROM to find
// the real main package. Hopping from a real package would wrongly flag every
// dependency it CONTAINS as a main module.
func applyMainModule(p *Parsed, doc *Document) {
	described := map[string]bool{}
	wrappers := map[string]bool{}
	mark := func(id string) {
		np := p.BySPDXID[id]
		if np == nil || isDocumentRootWrapper(np.SPDXID, np.Name) {
			wrappers[id] = true
			return
		}
		described[id] = true
	}
	for _, r := range doc.Relationships {
		if strings.EqualFold(r.RelationshipType, "DESCRIBES") {
			mark(r.RelatedSPDXElement)
		}
	}
	for _, id := range doc.DocumentDescribes {
		mark(id)
	}
	// One hop from wrapper roots to find the real main package.
	for _, r := range doc.Relationships {
		if !wrappers[r.SPDXElementID] {
			continue
		}
		if strings.EqualFold(r.RelationshipType, "DESCRIBES") ||
			strings.EqualFold(r.RelationshipType, "CONTAINS") ||
			strings.EqualFold(r.RelationshipType, "GENERATED_FROM") {
			if np := p.BySPDXID[r.RelatedSPDXElement]; np != nil {
				described[np.SPDXID] = true
			}
		}
	}
	// Fall back to the wrapper itself when it is a package with nothing beneath.
	if len(described) == 0 {
		for id := range wrappers {
			described[id] = true
		}
	}
	for id := range described {
		if np := p.BySPDXID[id]; np != nil {
			np.IsMainModule = true
		}
	}
}

// isDocumentRootWrapper recognizes synthetic root elements that wrap the real
// subject of the SBOM (syft's "SPDXRef-DocumentRoot-Directory-..." etc.).
func isDocumentRootWrapper(id, name string) bool {
	return strings.Contains(id, "DocumentRoot") || strings.HasPrefix(name, "DocumentRoot")
}

// detectContext infers whether the SBOM describes source or a built binary,
// using creators provenance, sourceInfo and annotations as signals.
func detectContext(doc *Document, p *Parsed) string {
	joined := strings.ToLower(strings.Join(doc.CreationInfo.Creators, " "))
	// Tool provenance hints.
	if strings.Contains(joined, "go.sum") || strings.Contains(joined, "repo:") ||
		strings.Contains(joined, "git:") || strings.Contains(joined, "filesystem") {
		return "source"
	}
	// Document/package annotations (e.g. mikebom:sbom-tier=source, source-files).
	tierSource, tierBinary := scanTierAnnotations(p)
	if tierSource && !tierBinary {
		return "source"
	}
	if tierBinary && !tierSource {
		return "binary"
	}
	// Binary signals: a stdlib component or sourceInfo referencing a binary.
	for i := range p.Packages {
		if p.Packages[i].IsStdlib {
			return "binary"
		}
	}
	for _, pkg := range doc.Packages {
		si := strings.ToLower(pkg.SourceInfo)
		if strings.Contains(si, "binary") || strings.Contains(si, ".tar.gz") ||
			strings.Contains(si, "acquired package info from") {
			return "binary"
		}
	}
	return "unknown"
}

func scanTierAnnotations(p *Parsed) (source, binary bool) {
	check := func(anns []Annotation) {
		for _, a := range anns {
			c := strings.ToLower(a.Comment)
			if !strings.Contains(c, "sbom-tier") && !strings.Contains(c, "source-files") {
				continue
			}
			if strings.Contains(c, "source-files") || strings.Contains(c, "\"source\"") {
				source = true
			}
			if strings.Contains(c, "\"binary\"") {
				binary = true
			}
		}
	}
	check(p.DocAnnotations)
	for i := range p.Packages {
		check(p.Packages[i].Annotations)
	}
	return source, binary
}

// SortedPackages returns packages sorted by name then version for deterministic
// output.
func (p *Parsed) SortedPackages() []NormalizedPackage {
	out := make([]NormalizedPackage, len(p.Packages))
	copy(out, p.Packages)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name == out[j].Name {
			return out[i].Version < out[j].Version
		}
		return out[i].Name < out[j].Name
	})
	return out
}
