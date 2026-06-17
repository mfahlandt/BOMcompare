package sbom

import (
	"bufio"
	"fmt"
	"strings"
)

// SPDX Tag-Value parser.
//
// The tag-value format is a flat sequence of "Tag: value" lines. Packages,
// files and relationships are delimited implicitly: a new PackageName/FileName
// starts a new entity, and subsequent property lines apply to it until the next
// entity begins. We assemble a *Document so the existing Normalize() path is
// reused unchanged.
//
// Supported (quality-relevant) tags:
//
//	Document : SPDXVersion, DataLicense, SPDXID, DocumentName, DocumentNamespace,
//	           Creator, Created, LicenseListVersion
//	Package  : PackageName, SPDXID, PackageVersion, PackageSupplier,
//	           PackageOriginator, PackageDownloadLocation, FilesAnalyzed,
//	           PackageSourceInfo, PackageLicenseConcluded, PackageLicenseDeclared,
//	           PackageCopyrightText, PackageChecksum, ExternalRef,
//	           PrimaryPackagePurpose
//	Graph    : Relationship
//
// Multi-line <text>...</text> values are joined into a single line.

// parseSPDXTagValue parses tag-value bytes into a Document.
func parseSPDXTagValue(data []byte) (*Document, error) {
	doc := &Document{}
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	sc.Buffer(make([]byte, 0, 1024*1024), 16*1024*1024)

	var (
		curPkg     *Package
		inText     bool
		textTag    string
		textBuf    strings.Builder
		sawVersion bool
	)

	flushPkg := func() {
		if curPkg != nil {
			doc.Packages = append(doc.Packages, *curPkg)
			curPkg = nil
		}
	}

	apply := func(tag, val string) {
		switch tag {
		// ---- document ----
		case "SPDXVersion":
			doc.SPDXVersion = val
			sawVersion = true
		case "DataLicense":
			doc.DataLicense = val
		case "DocumentName":
			doc.Name = val
		case "DocumentNamespace":
			doc.DocumentNamespace = val
		case "Creator":
			doc.CreationInfo.Creators = append(doc.CreationInfo.Creators, val)
		case "Created":
			doc.CreationInfo.Created = val
		case "LicenseListVersion":
			doc.CreationInfo.LicenseListVersion = val

		// ---- package start ----
		case "PackageName":
			flushPkg()
			curPkg = &Package{Name: val}

		// ---- package fields ----
		case "SPDXID":
			if curPkg != nil {
				curPkg.SPDXID = val
			} else {
				doc.SPDXID = val
			}
		case "PackageVersion":
			if curPkg != nil {
				curPkg.VersionInfo = val
			}
		case "PackageSupplier":
			if curPkg != nil {
				curPkg.Supplier = val
			}
		case "PackageOriginator":
			if curPkg != nil {
				curPkg.Originator = val
			}
		case "PackageDownloadLocation":
			if curPkg != nil {
				curPkg.DownloadLocation = val
			}
		case "FilesAnalyzed":
			if curPkg != nil {
				curPkg.FilesAnalyzed = strings.EqualFold(strings.TrimSpace(val), "true")
			}
		case "PackageSourceInfo":
			if curPkg != nil {
				curPkg.SourceInfo = val
			}
		case "PackageLicenseConcluded":
			if curPkg != nil {
				curPkg.LicenseConcluded = val
			}
		case "PackageLicenseDeclared":
			if curPkg != nil {
				curPkg.LicenseDeclared = val
			}
		case "PackageCopyrightText":
			if curPkg != nil {
				curPkg.CopyrightText = val
			}
		case "PrimaryPackagePurpose":
			if curPkg != nil {
				curPkg.PrimaryPurpose = val
			}
		case "PackageChecksum":
			if curPkg != nil {
				if cs, ok := parseTagChecksum(val); ok {
					curPkg.Checksums = append(curPkg.Checksums, cs)
				}
			}
		case "ExternalRef":
			if curPkg != nil {
				if ref, ok := parseTagExternalRef(val); ok {
					curPkg.ExternalRefs = append(curPkg.ExternalRefs, ref)
				}
			}

		// ---- relationships ----
		case "Relationship":
			if rel, ok := parseTagRelationship(val); ok {
				doc.Relationships = append(doc.Relationships, rel)
			}

		// ---- file start: end current package context ----
		case "FileName":
			flushPkg()
			doc.Files = append(doc.Files, File{FileName: val})
		}
	}

	for sc.Scan() {
		line := sc.Text()

		// Continue accumulating a multi-line <text> value.
		if inText {
			if idx := strings.Index(line, "</text>"); idx >= 0 {
				textBuf.WriteString(line[:idx])
				inText = false
				apply(textTag, textBuf.String())
				textBuf.Reset()
				continue
			}
			textBuf.WriteString(line)
			textBuf.WriteByte('\n')
			continue
		}

		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		colon := strings.Index(trimmed, ":")
		if colon < 0 {
			continue
		}
		tag := strings.TrimSpace(trimmed[:colon])
		val := strings.TrimSpace(trimmed[colon+1:])

		// Detect start of a multi-line <text> block.
		if strings.HasPrefix(val, "<text>") {
			rest := strings.TrimPrefix(val, "<text>")
			if end := strings.Index(rest, "</text>"); end >= 0 {
				apply(tag, rest[:end])
				continue
			}
			inText = true
			textTag = tag
			textBuf.Reset()
			textBuf.WriteString(rest)
			textBuf.WriteByte('\n')
			continue
		}

		apply(tag, val)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("scan SPDX tag-value: %w", err)
	}
	flushPkg()

	if !sawVersion {
		return nil, fmt.Errorf("not an SPDX tag-value document (missing SPDXVersion)")
	}
	return doc, nil
}

// parseTagChecksum parses "SHA256: abc123" into a Checksum.
func parseTagChecksum(val string) (Checksum, bool) {
	parts := strings.SplitN(val, ":", 2)
	if len(parts) != 2 {
		// Some emitters use a space: "SHA256 abc123".
		fields := strings.Fields(val)
		if len(fields) == 2 {
			return Checksum{Algorithm: fields[0], ChecksumValue: fields[1]}, true
		}
		return Checksum{}, false
	}
	return Checksum{
		Algorithm:     strings.TrimSpace(parts[0]),
		ChecksumValue: strings.TrimSpace(parts[1]),
	}, true
}

// parseTagExternalRef parses "PACKAGE-MANAGER purl pkg:rpm/..." into ExternalRef.
func parseTagExternalRef(val string) (ExternalRef, bool) {
	fields := strings.Fields(val)
	if len(fields) < 3 {
		return ExternalRef{}, false
	}
	return ExternalRef{
		ReferenceCategory: fields[0],
		ReferenceType:     fields[1],
		ReferenceLocator:  strings.Join(fields[2:], " "),
	}, true
}

// parseTagRelationship parses "SPDXRef-A DEPENDS_ON SPDXRef-B" into Relationship.
func parseTagRelationship(val string) (Relationship, bool) {
	fields := strings.Fields(val)
	if len(fields) != 3 {
		return Relationship{}, false
	}
	return Relationship{
		SPDXElementID:      fields[0],
		RelationshipType:   fields[1],
		RelatedSPDXElement: fields[2],
	}, true
}
