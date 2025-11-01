# Playbook: Legacy traffic injection via LNG (legacy_protocol_injection)

## Tactic
Protocol / Interop Abuse

## Description
Legacy traffic injection via LNG

## Affected Functional Elements
LNG, LPG, ESInet

## Mitigations (from framework)
protocol_conformance_checks, input_validation, endpoint_whitelist, STIR_SHAKEN_where_applicable

## Detection & Telemetry
- Log sources: ESInet service logs (BCF/ESRP/LIS/LVF/ECRF), PSAP app logs, OS logs, network flow, TLS termination metrics.
- Suggested signals:
  - Protocol conformance violations at LNG/LPG
  - RTP/SRTP negotiation anomalies; media path without SRTP
  - Unexpected codec/SDP attributes or malformed frames

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
- Evidence: fileciteturn2file13L25-L37
- MiTRE-CR911: mapping.json → protocol_interop.legacy_protocol_injection
