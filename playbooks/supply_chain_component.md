# Playbook: Compromised vendor firmware/software (supply_chain_component)

## Tactic
Initial Access

## Description
Compromised vendor firmware/software

## Affected Functional Elements
ESInet, NGCS, LIS, ESRP

## Mitigations (from framework)
SBOM, vendor-security-checks, version_lifecycle_monitoring, code_signing

## Detection & Telemetry
- Log sources: ESInet service logs (BCF/ESRP/LIS/LVF/ECRF), PSAP app logs, OS logs, network flow, TLS termination metrics.
- Suggested signals:
  - New processes, persistence keys, or suspicious parent-child chains on PSAP hosts
  - EDR alerts for ransomware TTPs (mass file open/rename, shadow copy deletion)
  - Unauthorized config changes; privileged actions outside change windows
  - New binaries or updates from unapproved vendor paths

## Triage
- Scope: identify impacted functional elements and dependent paths.
- Timeframe: examine past 24h (burst) and past 7 days (trend).
- Validate evidence: correlate certificate fingerprints, endpoint identities, rate anomalies, and schema violations.

## Containment
- Block or rate-limit offending sources at BCF/edge.
- Quarantine affected service nodes; failover to redundant peers if available.
- Disable compromised credentials/tokens, rotate keys where applicable.

## Eradication
- Patch or reconfigure affected components.
- Rebuild compromised hosts/services if integrity cannot be assured.
- Restore validated GIS/LVF datasets when tampering detected.

## Recovery
- Gradually reintroduce traffic under heightened monitoring.
- Verify end-to-end i3 call flows (origination → BCF → ESRP → ECRF/LVF → PSAP).
- Conduct post-incident review and update runbooks.

## Metrics / KPIs
- Mean Time to Detect (MTTD), Mean Time to Contain (MTTC), and Mean Time to Recover (MTTR).
- False positive rate for the associated detections.
- % of endpoints with mTLS/STIR-SHAKEN correctly enforced.
- Success rate of LVF queries and correct routing decisions.

## References
- Evidence: fileciteturn2file14L43-L56
- MiTRE-CR911: mapping.json → initial_access.supply_chain_component
