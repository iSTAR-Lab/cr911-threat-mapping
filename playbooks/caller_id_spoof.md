# Playbook: Caller ID / SIP identity spoofing (SIP INVITE manipulation) (caller_id_spoof)

## Tactic
Spoofing / Identity Deception

## Description
Caller ID / SIP identity spoofing (SIP INVITE manipulation)

## Affected Functional Elements
BCF, ESRP, BCF(Egress), PSAP

## Mitigations (from framework)
STIR_SHAKEN, BCF_ingress_validation, SIP_HEADER_VALIDATION, rate_limiting

## Detection & Telemetry
- Log sources: ESInet service logs (BCF/ESRP/LIS/LVF/ECRF), PSAP app logs, OS logs, network flow, TLS termination metrics.
- Suggested signals:
  - Sharp increase in SIP INVITEs or OPTIONS from few source IPs/ASNs
  - Queue depth/abandonment spikes at PSAP; ESRP 4xx/5xx surge
  - Rate-limit counters triggering at BCF/edge
  - Repeated invalid/unsigned/failed STIR/SHAKEN attestations

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
- Evidence: fileciteturn2file9L27-L33
- MiTRE-CR911: mapping.json → spoofing.caller_id_spoof
