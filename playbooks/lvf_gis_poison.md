# Playbook: LVF / GIS data tampering (poisoning) (lvf_gis_poison)

## Tactic
Tampering / Data Manipulation

## Description
LVF / GIS data tampering (poisoning)

## Affected Functional Elements
LVF, ECRF, PRF

## Mitigations (from framework)
version_management, integrity_checks, access_control, auditing, data_signing

## Detection & Telemetry
- Log sources: ESInet service logs (BCF/ESRP/LIS/LVF/ECRF), PSAP app logs, OS logs, network flow, TLS termination metrics.
- Suggested signals:
  - LVF validation failures increasing after data updates
  - Hash/version drift between production and golden GIS snapshots
  - Unauthorized write events to LVF/GIS repositories

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
- Evidence: fileciteturn2file12L15-L19
- MiTRE-CR911: mapping.json → tampering.lvf_gis_poison
