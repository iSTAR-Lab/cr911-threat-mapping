"""Combine the per-scanner CSVs produced for a single SBOM into one table."""
from pathlib import Path

import pandas as pd


def combine_vulnerabilities(scan_dir):
    """Merge the *_filtered.csv files written by each scanner under scan_dir.

    scan_dir is one SBOM's output folder, containing a subfolder per scanner
    (bomber/, grype/, osv/, trivy/) each holding a *_filtered.csv. Rows are
    deduplicated by vulnerability id, and the Source column lists every scanner
    that reported it. Inputs are read in sorted order so the result is stable
    across runs. Returns the combined frame, or None when no CSVs are found.
    """
    scan_dir = Path(scan_dir)
    csv_files = [
        csv
        for subfolder in sorted(scan_dir.iterdir())
        if subfolder.is_dir()
        for csv in sorted(subfolder.glob("*_filtered.csv"))
    ]
    if not csv_files:
        print(f"No *_filtered.csv files found under {scan_dir}")
        return None

    frames = []
    for csv in csv_files:
        print(f"Reading {csv}...")
        frames.append(pd.read_csv(csv))
    combined = pd.concat(frames, ignore_index=True)

    # Collapse rows that share an id; Severity/Explanation come from the first
    # scanner alphabetically, and Source records every scanner that found it.
    combined = combined.sort_values("Source").groupby("CVE", as_index=False, dropna=False).agg(
        Severity=("Severity", "first"),
        Source=("Source", lambda s: ", ".join(sorted(set(s)))),
        Explanation=("Explanation", "first"),
    )

    print(f"Combined {len(csv_files)} files into {len(combined)} unique findings")
    return combined


if __name__ == "__main__":
    # Re-combine every SBOM already scanned under Outputs/.
    outputs_dir = Path(__file__).resolve().parent.parent / "Outputs"
    for sbom_dir in sorted(p for p in outputs_dir.iterdir() if p.is_dir()):
        combined_df = combine_vulnerabilities(sbom_dir)
        if combined_df is not None:
            output_file = sbom_dir / f"{sbom_dir.name}_combined.csv"
            combined_df.to_csv(output_file, index=False)
            print(f"Wrote {output_file}")
