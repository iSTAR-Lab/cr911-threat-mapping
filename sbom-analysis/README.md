# SBOM Vulnerability Analysis

Part of the **CyRECS911 Threat-Mapping Workflow**. This pipeline operationalizes
the `SBOM` mitigation called out in the
[`supply_chain_component`](../playbooks/supply_chain_component.md) playbook: it
turns a component's Software Bill of Materials into a concrete, cross-checked
list of known vulnerabilities, giving analysts empirical supply-chain risk data
for the third-party and vendor components that emergency-communications systems
(PSAPs, ESInet, NGCS, LIS, …) depend on.

It runs an SBOM through four vulnerability scanners, merges their findings into a
single table, and checks every reported vulnerability id against an authoritative
source. The idea is that no single scanner catches everything, so cross-checking
them gives a fuller and more trustworthy picture of a component's known issues.

For each SBOM the pipeline:

1. scans it with **bomber**, **grype**, **osv-scanner**, and **trivy**;
2. normalises each scanner's output to a common CSV (`CVE, Severity, Source, Explanation`);
3. combines the four CSVs and deduplicates by vulnerability id; and
4. validates the ids against the MITRE CVE API (for `CVE-*`) and OSV.dev (for `GHSA-`, `CGA-`, `BIT-*`, …).

## Prerequisites

- **Python 3.9+**
- The four scanners, on your `PATH`. They are separate binaries, not Python
  packages. The exact commands the pipeline runs are shown so you can confirm
  your install works:

  | Scanner | Install | Command used |
  |---------|---------|--------------|
  | bomber | https://github.com/devops-kung-fu/bomber | `bomber scan --output json <sbom>` |
  | grype | https://github.com/anchore/grype | `grype <sbom> -o json` |
  | osv-scanner | https://github.com/google/osv-scanner | `osv-scanner scan --sbom <sbom> --format json` |
  | trivy | https://github.com/aquasecurity/trivy | `trivy sbom <sbom> --format json` |

A scanner that isn't installed is reported and skipped, so you can still run the
others. Tested with grype 0.114, trivy 0.71, bomber 0.5, and osv-scanner 2.3.

## Install

Run these from the `sbom-analysis/` directory:

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## Usage

Put your SBOM files in `SBOMs/`, then run:

```bash
python scripts/main.py
```

Only files named `*.spdx.json` (SPDX) or `*.cyclonedx.json` (CycloneDX) are
picked up; anything else in `SBOMs/` is ignored. Paths are anchored to the
script location, so the pipeline works whether you run it from `sbom-analysis/`
or the repository root. Results are written to `Outputs/`, which is created
automatically; it is gitignored and regenerated on every run, so scan results
are not tracked in version control.

The `SBOMs/` folder ships empty (it holds only a `.gitkeep`); add your own SBOM
files there before running the pipeline.

## Output

```
Outputs/
├── <sbom>/
│   ├── bomber/   <sbom>_raw.json   <sbom>_filtered.csv
│   ├── grype/    <sbom>_raw.json   <sbom>_filtered.csv
│   ├── osv/      <sbom>_raw.json   <sbom>_filtered.csv
│   ├── trivy/    <sbom>_raw.json   <sbom>_filtered.csv
│   └── <sbom>_combined.csv         # deduplicated across all four scanners
└── scan_report.json                # per-SBOM summary and validation counts
```

Each `*_filtered.csv` has the columns `CVE, Severity, Source, Explanation`. In
the combined file, `Source` lists every scanner that reported the id, while
`Severity` and `Explanation` are taken from one of them.

## Other scripts

- `scripts/combine_csvs.py` — run on its own to rebuild the combined CSVs from
  output that's already on disk.
- `scripts/deps.py` — a small helper that dumps the package names from each SPDX
  SBOM to `Outputs/<name>_deps.csv`.

## Notes and limitations

- ID validation needs network access. Lookups that fail (rate limit, server
  error, no connection) are counted as `unverified` rather than `invalid`, so a
  transient failure isn't mistaken for a non-existent vulnerability.
- Deduplication is by vulnerability id. When scanners report the same flaw under
  different ids (a CVE in one, its GHSA alias in another), it can still appear as
  more than one row.
- Severity is whatever each scanner reports, so its format varies (a CVSS score
  from grype/trivy, a qualitative label from bomber/osv).
