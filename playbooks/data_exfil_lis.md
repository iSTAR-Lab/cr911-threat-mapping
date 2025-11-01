# Playbook: Exfiltrate caller location or call logs (data_exfil_lis)

## Tactic
Collection / Exfiltration

## Description
Exfiltrate caller location or call logs

## Affected Functional Elements
LIS, PSAP_BACKEND, LOGGING_SERVICE

## Mitigations (from framework)
encryption_at_rest, rbac, audit_logging, anomaly_detection

## Detection & Telemetry
- Log sources: ESInet service logs (BCF/ESRP/LIS/LVF/ECRF), PSAP app logs, OS logs, network flow, TLS termination metrics.
- Suggested signals:
  - Certificate or signer mismatch for PIDF-LO/location tokens
  - Unusual LVF query failures or revalidations for same call
  - Sudden change in location-by-value vs location-by-reference
  - Spikes in LIS queries from atypical clients

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
- Evidence: fileciteturn2file8L13-L16
- MiTRE-CR911: mapping.json → exfiltration.data_exfil_lis
