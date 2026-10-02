# BOMcompare

> Part of **[BOMHort](https://github.com/seebom-labs/BOMHort)** — this tool lives
> in the BOMHort monorepo under [`BOMcompare`](https://github.com/seebom-labs/BOMHort/tree/main/BOMcompare),
> which is its upstream. Module path: `github.com/seebom-labs/BOMHort/BOMcompare`.

A single-binary Go CLI that compares two SBOMs — **SPDX** (2.x JSON or
tag-value, 3.0 JSON-LD) or **CycloneDX** (JSON or XML, 1.4–1.7) — and produces a
structured quality diff report: package coverage, version accuracy, license
resolution, PURL/CPE quality, dependency-graph depth, supplier/checksum coverage,
annotation richness, a weighted composite score and an informational check
against the **CISA 2026 Minimum Elements for an SBOM**.

The two inputs may be in **different formats** (e.g. compare a CycloneDX SBOM
from one tool against an SPDX SBOM from another) — every format is normalized to
a common internal model before comparison.

It turns the kind of manual, ad-hoc SBOM comparison you might do by hand into a
reusable, CI-friendly tool. The methodology is inspired by
[mlieberman85's SBOM quality benchmark](https://gist.github.com/mlieberman85/cb0ed7b600efb211dce0633e2c392626).

## Supported formats

The input format is **auto-detected** per file (by content, not extension), so
you can mix and match:

| Format | Detection | Notes |
|--------|-----------|-------|
| **SPDX JSON** | `{ "spdxVersion": ... }` | SPDX 2.2 / 2.3 |
| **SPDX tag-value** | `SPDXVersion:` / `PackageName:` lines | the `.spdx` text format, incl. multi-line `<text>` blocks |
| **SPDX 3.0 JSON-LD** | `@context` `https://spdx.org/rdf/3.*` or an `@graph` of SPDX elements | SPDX 3.0 / 3.0.1 (Core, Software, SimpleLicensing, ExpandedLicensing) |
| **CycloneDX JSON** | `{ "bomFormat"/"specVersion": ... }` | v1.4 – v1.7 (tools as array *or* `{components}`) |
| **CycloneDX XML** | leading `<bom ...>` | v1.4 – v1.7 (spec version read from the namespace) |

Because SPDX and CycloneDX model some things differently, the tool normalizes:

- SPDX 3 `@graph` elements (`software_Package`, `Relationship`,
  `LifecycleScopedRelationship`, agents, annotations; inline or referenced by
  `spdxId`) → the same model as SPDX 2:
  - `software_packageUrl` / `externalIdentifier` (`packageUrl`, `cpe23`,
    `cpe22`, `swid`, `gitoid`, `swhid`) → identity; `verifiedUsing` → checksums;
    `suppliedBy` / `originatedBy` → supplier / originator.
  - `hasDeclaredLicense` / `hasConcludedLicense` → `licenseDeclared` /
    `licenseConcluded` (simple expressions, expanded license sets/operators,
    `NoAssertionLicense` / `NoneLicense`).
  - camelCase relationship types → SPDX 2 names (`dependsOn` → `DEPENDS_ON`);
    `dependsOn` scoped `test` / `development` / `build` → `TEST_` / `DEV_` /
    `BUILD_DEPENDENCY_OF`.
  - `software_Sbom.rootElement` → the main module; `software_sbomType` → the
    generation context.
- CycloneDX `components[]` → packages; `metadata.component` → the main module.
- CycloneDX `purl` / `cpe` (string or array), `omniborId`, `swhid` → package
  identity.
- CycloneDX `licenses[]` (`license.id` / `license.name` / `expression`) → split
  by the 1.6+ `acknowledgement` (`declared` / `concluded`); licenses without it
  are mapped to `licenseConcluded`.
- CycloneDX component `supplier` → supplier; 1.6+ `manufacturer` / `authors` →
  originator.
- CycloneDX `metadata.lifecycles[].phase` → generation context (`design`,
  `pre-build` → source; `post-build`, `operations` → binary).
- CycloneDX `hashes[]` (`alg: "SHA-256"`) → checksum coverage.
- CycloneDX `scope: optional|excluded` → treated as non-runtime (test-scoped).
- CycloneDX `dependencies[]` (`ref` / `dependsOn`) → SPDX-style `DEPENDS_ON`
  relationships, so the dependency-graph analysis is identical across formats.
- CycloneDX `evidence.identity` and `properties[]` → surfaced as annotations so
  transparency scoring credits producers that ship them.

> **Note on cross-format license scoring:** SPDX separates `licenseDeclared`
> from `licenseConcluded`; CycloneDX only does so via the 1.6+ `acknowledgement`
> field, which many generators do not emit yet. When comparing
> an SPDX SBOM (data often in `licenseDeclared`) against a CycloneDX one (mapped
> to `licenseConcluded`), read the per-field rates in the License section rather
> than a single headline number.

## Why

Different SBOM generators disagree — sometimes dramatically — about what is in
the same artifact. A **source SBOM** (scanned from `go.sum` / a lockfile) lists
the full transitive and test dependency tree; a **binary SBOM** (scanned from a
compiled artifact) lists only what is linked in. Tools also disagree on *where*
they put data (e.g. `licenseDeclared` vs `licenseConcluded`), how they format
PURLs, and whether they attribute suppliers at all.

`sbom-comparison` makes those differences explicit and classifies them using the
Lieberman finding framework, so you can:

- diff two tools on the same target ("mikebom vs syft"),
- diff two releases of the same SBOM in CI (gate on real regressions),
- understand whether a difference is a **defect** or just a **source-vs-binary
  scope choice**.

## Install

```bash
go install github.com/seebom-labs/BOMHort/BOMcompare@latest
```

This installs a `BOMcompare` binary. Or build from source:

```bash
git clone https://github.com/seebom-labs/BOMHort
cd BOMHort/BOMcompare
go build -o sbom-comparison .
```

Requires Go 1.23+. No dependencies beyond the standard library.

## Usage

```bash
sbom-comparison [flags] <sbom-a> <sbom-b>
```

Inputs can be any supported format (SPDX JSON/tag-value/3.0 JSON-LD, CycloneDX JSON/XML) and
the two files need not be the same format.

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-a <file>` | — | First SBOM (SPDX or CycloneDX; or first positional arg) |
| `-b <file>` | — | Second SBOM (SPDX or CycloneDX; or second positional arg) |
| `--format <fmt>` | `markdown` | Output format: `markdown`, `json`, or `summary` |
| `-o <file>` | stdout | Write the report to a file |
| `--exit-on-diff` | `false` | Exit with code **2** if **significant** differences are found (CI gate) |
| `--diff-threshold <n>` | `1` | Minimum number of runtime-unique packages that counts as significant |
| `--version` | — | Print version and exit |

### Output formats

- **`markdown`** (default) — a full human-readable report with an executive
  summary, ten numbered category sections, a findings table, a star scorecard,
  a CISA 2026 minimum-elements table and actionable recommendations.
- **`json`** — the complete structured result, for piping into other tools.
- **`summary`** — just the scorecard table, the composite score and the CISA
  minimum-elements tally (great for terminals and CI logs).

### Examples

```bash
# Full markdown report (same format)
sbom-comparison mikebom.spdx.json syft.spdx.json

# Cross-format: CycloneDX vs SPDX
sbom-comparison syft.cdx.json mikebom.spdx.json

# SPDX tag-value vs CycloneDX XML
sbom-comparison app.spdx app.cdx.xml

# Just the scorecard
sbom-comparison --format summary mikebom.spdx.json syft.spdx.json

# Machine-readable output to a file
sbom-comparison --format json -o report.json a.spdx.json b.cdx.json

# CI gate: fail the build on a significant regression
sbom-comparison --exit-on-diff old-release.spdx.json new-release.spdx.json
```

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | Success (no significant differences, or `--exit-on-diff` not set) |
| `1` | Error (bad arguments, unreadable or unrecognized SBOM) |
| `2` | Significant differences found **and** `--exit-on-diff` was set |

A version mismatch on a common package is *always* significant. A large
package-count delta that is explained by a **source-vs-binary** scope difference
is *not* treated as significant on its own.

## What it compares

Each category produces a report section plus a 1–5 star score per SBOM:

1. **Completeness** — total / common / unique packages, with a test-scoped
   breakdown (via `TEST_DEPENDENCY_OF` relationships or lifecycle annotations).
2. **Version Accuracy** — version agreement across common packages.
3. **License Coverage** — `licenseDeclared` and `licenseConcluded` resolution
   rates per SBOM, plus a cross-comparison of license expressions on the
   overlap. Reports the common "data is in `declared` but consumers read
   `concluded`" gap.
4. **PURL Quality** — purl type distribution, main-module purl specificity
   (e.g. `pkg:generic` vs `pkg:golang`), zero-version purls, qualifiers.
5. **CPE Coverage** — packages with CPEs, average CPEs per package, and how many
   are well-formed (NVD-style `cpe:2.3:a:vendor:product:version`).
6. **Dependency Graph** — relationship count, type distribution, max chain depth
   and whether test dependencies are labeled.
7. **Supplier Attribution** — supplier/originator coverage.
8. **Checksum Coverage** — SHA256 coverage per package.
9. **Annotations** — document- and package-level annotation richness and the set
   of distinct annotation fields.
10. **Overall Score** — a weighted composite (license is weighted highest,
    annotations/CPE lowest), with a per-SBOM 1.0–5.0 score and a winner.
11. **CISA 2026 Minimum Elements** — an informational compliance table (not part
    of the score) per SBOM:
    - Document level: author, signature, data format name and version,
      generation context (lifecycle), timestamp, tool name and version, SBOM
      version.
    - Component level: producer, name, version, software identifiers (purl, CPE,
      SWID, gitoid/OmniBOR, SWHID), hash, license and dependency relationship,
      with coverage rates.
    - `warn` marks fields covered only by an explicit SPDX `NOASSERTION`
      (a declared unknown).
    - `unverified` marks a signature the tool cannot judge from the document
      alone (only enveloped CycloneDX JSF / XML-DSig signatures are detected).

### Finding classification

Findings are bucketed per the benchmark framework:

| Finding | Meaning |
|---------|---------|
| `MISSING_COMPONENT` | Package present in one SBOM but not the other |
| `PHANTOM_COMPONENT` | Package with no purl, checksum or version — likely spurious |
| `VERSION_MISMATCH` | Same package identity, different version |
| `PURL_MISMATCH` | Same package, different purl type/format |
| `FALSE_POSITIVE` | Package whose name and purl identity disagree |
| `LICENSE_GAP` | Common package with no resolvable license in a given SBOM |

## Package matching

- Packages are matched by **purl first**, falling back to **name + version**.
- Every fallback candidate must be identity-compatible: two ecosystem purls of
  different types (`pkg:npm/debug` vs `pkg:pypi/debug`) or different module
  paths (`github.com/pkg/errors` vs `github.com/go-errors/errors`) never match.
  Distro packages (`deb`, `rpm`, `apk`, …) may match across namespaces.
- purls are parsed per the purl spec (percent-decoding, unencoded npm scopes
  like `@angular/core`, `@` inside qualifiers).
- For Go modules, `pkg:golang/<module>` and `pkg:generic/<name>` are matched on
  the **module path / last path segment** so a tool that emits a generic purl
  for the main module still lines up with one that emits an ecosystem purl
  (this surfaces as a `PURL_MISMATCH` rather than a phantom "missing component").
- A version-independent identity match is used as a last resort so a
  same-package/different-version pair is reported as a **version mismatch**, not
  as two missing components.

## Source vs binary detection

The tool labels each SBOM by its generating tool (from
`creationInfo.creators`, e.g. `mikebom v0.1.0-alpha.47` vs `syft v1.42.3`) and
infers whether it describes **source** or a **built binary** from creator
provenance, `sourceInfo`, the presence of a `stdlib` component, and tool
annotations. An explicitly declared generation context — CycloneDX
`metadata.lifecycles` or SPDX 3 `software_sbomType` — takes precedence over
these heuristics. When the two SBOMs differ in scope, the report leads with a "Source
SBOM vs Binary SBOM" note explaining that the package delta is expected.

## Development

```bash
go build ./...   # build
go vet ./...     # static checks
go test ./...    # run tests
gofmt -l .       # formatting (should print nothing)
```

### Golden tests

`pkg/report` ships golden tests that pin the full rendered output (markdown,
JSON and summary) for representative SBOM pairs. When you intentionally change a
renderer or a scoring heuristic, review the diff and regenerate the fixtures:

```bash
go test ./pkg/report -run TestGolden -update
```

The golden files live in `pkg/report/testdata/*.golden`. The volatile
"Generated <date>" line is normalized before comparison, so the goldens stay
stable across days.


Test fixtures live in `testdata/`:

- `source.spdx.json` — a mikebom-style source SBOM (suppliers, annotations,
  `licenseDeclared`, test labeling, a `pkg:generic` main module).
- `binary.spdx.json` — a syft-style binary SBOM (`licenseConcluded`, `stdlib`,
  no suppliers/annotations, a `pkg:golang` main module).
- `source-version-mismatch.spdx.json` — `source` with one package version bumped,
  to exercise `VERSION_MISMATCH` and CI gating.
- `binary.spdx` — the same binary SBOM in **SPDX tag-value** form (multi-line
  `<text>`, `PackageChecksum`/`ExternalRef`/`Relationship` lines).
- `binary.cdx.json` — a **CycloneDX JSON** (v1.5) SBOM of the same binary
  (scoped components, hashes, `dependencies[]`, evidence).
- `binary.cdx.xml` — the **CycloneDX XML** equivalent.
- `source.spdx3.json` — `source.spdx.json` expressed as **SPDX 3.0.1 JSON-LD**
  (inline agents, `externalIdentifier`, expanded license sets,
  `LifecycleScopedRelationship`, `software_sbomType`). Tests assert it yields
  the same analysis as its SPDX 2 counterpart.

## Project layout

```
BOMcompare/                 # subproject of github.com/seebom-labs/BOMHort
├── main.go                 # CLI entry point, flags, exit codes
├── pkg/
│   ├── sbom/               # format detection + parse/normalize
│   │   ├── spdx.go             # SPDX 2.3 JSON types
│   │   ├── spdx_tagvalue.go    # SPDX tag-value parser
│   │   ├── spdx3.go            # SPDX 3.0 JSON-LD → shared model
│   │   ├── cyclonedx.go        # CycloneDX JSON types
│   │   ├── cyclonedx_xml.go    # CycloneDX XML parser
│   │   ├── cyclonedx_normalize.go  # CycloneDX → shared model
│   │   └── parse.go            # Load(), DetectFormat(), normalization
│   ├── compare/            # comparison engine, finding classification,
│   │                       #   CISA minimum elements (minimum.go)
│   └── report/             # markdown / json / summary renderers (+ golden tests)
└── testdata/               # SPDX + CycloneDX fixtures used by tests
```

## License

Apache-2.0. See [LICENSE](LICENSE).
