"""Scan every SBOM in ../SBOMs with four vulnerability scanners and summarise them.

For each SBOM the pipeline runs bomber, grype, osv-scanner and trivy, normalises
their findings to a common CSV schema, combines and deduplicates them, and
validates the resulting vulnerability ids. Results are written under ../Outputs
and a summary lands in ../Outputs/scan_report.json.

Run it as ``python scripts/main.py`` from the sbom-analysis/ folder (or
``python main.py`` from within scripts/). Paths are anchored to this file, so
the working directory does not matter.
"""
import json
import os
import subprocess
import tempfile
from datetime import datetime
from pathlib import Path

import pandas as pd

import combine_csvs
import mitre_cc

# Paths are anchored to this file so the script runs from any working directory.
BASE_DIR = Path(__file__).resolve().parent.parent
SBOM_DIR = BASE_DIR / "SBOMs"
OUTPUT_DIR = BASE_DIR / "Outputs"

# Shared schema for every scanner's filtered CSV.
COLUMNS = ["CVE", "Severity", "Source", "Explanation"]

# Give up on a scanner that hasn't finished within this many seconds.
SCANNER_TIMEOUT = 600


def run_scanner(command, label):
    """Run an external scanner and return its parsed JSON output.

    Returns an empty dict when the tool is missing, times out, or emits
    something that isn't JSON, so one unavailable scanner never aborts the run.
    """
    try:
        # Decode as UTF-8 rather than the platform default; scanners emit UTF-8
        # and the Windows locale codec (cp1252) chokes on it otherwise.
        result = subprocess.run(
            command, capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=SCANNER_TIMEOUT,
        )
    except FileNotFoundError:
        print(f"  {label}: not installed, skipping (see the README prerequisites).")
        return {}
    except subprocess.TimeoutExpired:
        print(f"  {label}: timed out after {SCANNER_TIMEOUT}s, skipping.")
        return {}

    if not result.stdout:
        # osv-scanner and friends exit non-zero when findings exist, so only a
        # non-zero exit *with no output* is genuinely a failure worth reporting.
        if result.returncode != 0:
            print(f"  {label}: exited with code {result.returncode}.\n{result.stderr.strip()}")
        return {}

    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        print(f"  {label}: could not parse JSON output ({exc}).")
        return {}


def _save(scanner_dir, out_name, raw, rows):
    """Write a scanner's raw JSON and normalised CSV, returning the CSV frame."""
    scanner_dir.mkdir(parents=True, exist_ok=True)
    (scanner_dir / f"{out_name}_raw.json").write_text(json.dumps(raw, indent=4))
    df = pd.DataFrame(rows, columns=COLUMNS)
    df.to_csv(scanner_dir / f"{out_name}_filtered.csv", index=False)
    return df


def bomber(sbom_path, out_dir, out_name):
    """Scan with bomber. Each package carries its own vulnerabilities; the CVE
    may be a comma-separated list or the literal 'NOT PROVIDED', in which case
    the scanner's own id is used instead."""
    raw = run_scanner(["bomber", "scan", "--output", "json", str(sbom_path)], "bomber")
    rows = []
    for package in raw.get("packages", []):
        for vuln in package.get("vulnerabilities", []):
            cve = str(vuln.get("cve", "")).split(",")[0]
            if cve in ("", "NOT PROVIDED"):
                cve = vuln.get("id", "")
            rows.append({
                "CVE": cve,
                "Severity": vuln.get("severity", ""),
                "Source": "Bomber",
                "Explanation": (vuln.get("description") or vuln.get("title", "")).replace("\n", " "),
            })
    return _save(out_dir / "bomber", out_name, raw, rows)


def grype(sbom_path, out_dir, out_name):
    """Scan with grype. The id comes from the EPSS block when present (a CVE),
    otherwise grype's own id (often a GHSA); severity is the CVSS base score."""
    raw = run_scanner(["grype", str(sbom_path), "-o", "json"], "grype")
    rows = []
    for match in raw.get("matches", []):
        vuln = match.get("vulnerability", {})
        epss = vuln.get("epss") or []
        cve = (epss[0].get("cve") if epss else None) or vuln.get("id", "")
        cvss = vuln.get("cvss") or []
        try:
            severity = cvss[0]["metrics"]["baseScore"]
        except (KeyError, IndexError, TypeError):
            severity = "Not given"
        rows.append({
            "CVE": cve,
            "Severity": severity,
            "Source": "Grype",
            "Explanation": vuln.get("description", ""),
        })
    return _save(out_dir / "grype", out_name, raw, rows)


def osv(sbom_path, out_dir, out_name):
    """Scan with osv-scanner. The first alias is preferred as the id (usually a
    CVE), falling back to the OSV id."""
    sbom_path = Path(sbom_path)
    rows = []
    with tempfile.TemporaryDirectory() as tmp:
        # osv-scanner infers the format from the file extension and only accepts
        # *.spdx.json or *.cdx.json, so give CycloneDX files (named
        # *.cyclonedx.json here) a copy under a name it recognises.
        if sbom_path.name.endswith(".cyclonedx.json"):
            target = Path(tmp) / f"{out_name}.cdx.json"
            target.write_bytes(sbom_path.read_bytes())
        else:
            target = sbom_path
        raw = run_scanner(["osv-scanner", "scan", "--sbom", str(target), "--format", "json"], "osv-scanner")
    for result in raw.get("results", []):
        for package in result.get("packages", []):
            for vuln in package.get("vulnerabilities", []):
                aliases = vuln.get("aliases") or []
                cve = aliases[0] if aliases else vuln.get("id", "")
                severity = vuln.get("database_specific", {}).get("severity", "Not listed")
                rows.append({
                    "CVE": cve,
                    "Severity": severity,
                    "Source": "OSV",
                    "Explanation": vuln.get("details", "").replace("\n", " "),
                })
    return _save(out_dir / "osv", out_name, raw, rows)


def trivy(sbom_path, out_dir, out_name):
    """Scan with trivy. Results hold one entry per target, so iterate them all
    rather than assuming a single result block."""
    raw = run_scanner(["trivy", "sbom", str(sbom_path), "--format", "json"], "trivy")
    rows = []
    for result in raw.get("Results", []):
        for vuln in result.get("Vulnerabilities") or []:
            try:
                severity = vuln["CVSS"]["ghsa"]["V3Score"]
            except (KeyError, TypeError):
                severity = "Not given"
            rows.append({
                "CVE": vuln.get("VulnerabilityID", ""),
                "Severity": severity,
                "Source": "Trivy",
                "Explanation": vuln.get("Description", "").replace("\n", " "),
            })
    return _save(out_dir / "trivy", out_name, raw, rows)


def scan_sbom(sbom_path, out_dir, out_name):
    """Run all four scanners on one SBOM and return a {scanner: dataframe} map."""
    print(f"Scanning {sbom_path.name} with bomber, grype, osv-scanner and trivy...")
    results = {
        "bomber": bomber(sbom_path, out_dir, out_name),
        "grype": grype(sbom_path, out_dir, out_name),
        "osv": osv(sbom_path, out_dir, out_name),
        "trivy": trivy(sbom_path, out_dir, out_name),
    }
    for name, df in results.items():
        print(f"  {name}: {len(df)} findings")
    return results


def main():
    if not SBOM_DIR.is_dir():
        print(f"No SBOMs directory at {SBOM_DIR}. Create it and add SBOM files first.")
        return

    sbom_files = sorted(
        f for f in os.listdir(SBOM_DIR) if f.endswith((".spdx.json", ".cyclonedx.json"))
    )
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    report = {
        "timestamp": datetime.now().isoformat(),
        "total_sboms": len(sbom_files),
        "sboms": {},
    }

    for sbom_file in sbom_files:
        sbom_name = sbom_file.removesuffix(".spdx.json").removesuffix(".cyclonedx.json")
        sbom_out_dir = OUTPUT_DIR / sbom_name

        print(f"\n{'=' * 60}\nProcessing SBOM: {sbom_name}\n{'=' * 60}")
        scanner_dfs = scan_sbom(SBOM_DIR / sbom_file, sbom_out_dir, sbom_name)

        entry = {
            "sbom_file": sbom_file,
            "scanner_results": {name: len(df) for name, df in scanner_dfs.items()},
            "combined_vulnerabilities": {},
            "validation_results": {},
        }

        combined_df = combine_csvs.combine_vulnerabilities(sbom_out_dir)
        if combined_df is not None:
            combined_path = sbom_out_dir / f"{sbom_name}_combined.csv"
            combined_df.to_csv(combined_path, index=False)
            entry["combined_vulnerabilities"] = {
                "total_unique_vulnerabilities": len(combined_df),
                "output_file": str(combined_path.relative_to(OUTPUT_DIR)),
            }

            print(f"\nValidating vulnerability ids for {sbom_name}...")
            entry["validation_results"] = mitre_cc.validate_cve_ids(combined_df)

        report["sboms"][sbom_name] = entry
        print(f"Completed {sbom_name}")

    report_path = OUTPUT_DIR / "scan_report.json"
    report_path.write_text(json.dumps(report, indent=2))
    print(f"\n{'=' * 60}\nScan report saved to {report_path}\n{'=' * 60}")


if __name__ == "__main__":
    main()
