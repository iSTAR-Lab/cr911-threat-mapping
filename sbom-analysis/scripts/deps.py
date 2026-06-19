"""Extract package names from SPDX SBOMs into CSV files.

A small standalone helper, separate from the scan pipeline. It reads every
*.spdx.json in ../SBOMs and writes a comma-separated list of package names to
../Outputs/<name>_deps.csv. CycloneDX SBOMs use a different structure
('components' rather than 'packages') and are not handled here.
"""
import json
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
SBOM_DIR = BASE_DIR / "SBOMs"
OUTPUT_DIR = BASE_DIR / "Outputs"


def extract_package_names(sbom_path, output_path):
    with open(sbom_path) as f:
        data = json.load(f)

    names = [pkg["name"] for pkg in data.get("packages", []) if pkg.get("name")]
    output_path.write_text(",".join(names))
    print(f"Extracted {len(names)} package names to {output_path}")


def main():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    for sbom_path in sorted(SBOM_DIR.glob("*.spdx.json")):
        name = sbom_path.name.removesuffix(".spdx.json")
        extract_package_names(sbom_path, OUTPUT_DIR / f"{name}_deps.csv")


if __name__ == "__main__":
    main()
