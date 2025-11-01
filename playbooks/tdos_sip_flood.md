# Playbook: Telephone Denial of Service (TDoS) / SIP flood (tdos_sip_flood)

## Tactic
Denial / Disruption

## Description
Telephone Denial of Service (TDoS) / SIP flood

## Affected Functional Elements
BCF, ESRP, BCF(ingress), PSAP, LPG

## Mitigations (from framework)
rate_limiting, upstream_filtering, call_filtering_tools, scrubbing_services, capacity_planning

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
- Evidence: fileciteturn2file5L41-L46
- MiTRE-CR911: mapping.json → denial.tdos_sip_flood
