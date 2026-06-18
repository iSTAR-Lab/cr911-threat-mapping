# CyRECS911 Threat-Mapping Workflow
### *Cyber Resilient Emergency Communication Systems*
A structured approach for mapping threats across emergency-service operations.

This repository provides an editable, modular threat-mapping workflow tailored for emergency-communications environments (PSAPs, ESInets, CAD, SBCs, radio systems, location infrastructures, etc.).
CyRECS911 enables analysts, engineers, and responders to visualize, classify, and document cyber threats across operational layers with consistency and repeatability.

## Repository Structure

```
playbooks/           # Atomic threat playbooks describing cyber scenarios
schema/              # JSON schema for CI validation of playbooks
ci/validate_schema   # CI workflow for ensuring playbook correctness
sbom-analysis/       # SBOM-driven supply-chain vulnerability scanning pipeline
view.html            # Rendered matrix / UI view of the threat landscape
```

## Playbooks

Each playbook captures:

- Scenario description
- Assets/components affected
- Attack steps
- Detection opportunities
- Mitigation strategies
- Operational impact (PSAP, call flow, ESInet routing, radio, CAD, etc.)

Your existing playbooks will continue to render automatically in `view.html` when validated through the schema.

## Validation

All playbooks adhere to `schema/mapping.schema.json`.
Use the existing CI workflow or run the validator locally:

```bash
python ci/validate_schema.py playbooks/
```

## SBOM Vulnerability Analysis

The [`sbom-analysis/`](sbom-analysis/) folder adds a supply-chain analysis
pipeline that operationalizes the `SBOM` mitigation from the
[`supply_chain_component`](playbooks/supply_chain_component.md) playbook. Given a
component's Software Bill of Materials (SPDX or CycloneDX), it runs four
independent vulnerability scanners (bomber, grype, osv-scanner, trivy), merges
and deduplicates their findings into a single CSV, and validates every reported
vulnerability id against the MITRE CVE API and OSV.dev.

This produces empirical, cross-checked vulnerability data for the third-party and
vendor components that ESInet/NG911 systems depend on, feeding the supply-chain
threat pathways the playbooks describe.

```bash
cd sbom-analysis
pip install -r requirements.txt
# add your SBOM files (*.spdx.json / *.cyclonedx.json) to sbom-analysis/SBOMs/
python scripts/main.py
```

See [`sbom-analysis/README.md`](sbom-analysis/README.md) for scanner install
steps, the output layout, and known limitations.

## Purpose of CyRECS911

CyRECS911 provides a unified methodology for:

- Threat mapping across multi-agency emergency services
- Identifying mission-impact pathways
- Standardizing cybersecurity documentation for ESInet/NG911 ecosystems
- Supporting training, exercises, and tabletop scenarios
- Integrating cyber resilience into call-handling and dispatch workflows

**Funding & Acknowledgment:**  
This project is funded by the U.S. Department of Homeland Security (DHS) and implemented by the iSTAR Lab at Texas A&M University.
