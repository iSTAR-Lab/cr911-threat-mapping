# Playbook: Exploit software bug in ESRP / ECRF / LIS (sw_bugs_esrp)

## Tactic
Vulnerability Exploitation

## Description
Exploit software bug in ESRP / ECRF / LIS

## Affected Functional Elements
ESRP, ECRF, LIS, LVF

## Mitigations (from framework)
patch_management, secure_code_review, vuln_scanning, runtime_monitoring

## Detection & Telemetry
- Log sources: ESInet service logs (BCF/ESRP/LIS/LVF/ECRF), PSAP app logs, OS logs, network flow, TLS termination metrics.
- Suggested signals:
  - Crashes/restarts or exception spikes in ESRP/ECRF/LIS services
  - TLS version/cipher downgrade attempts; handshake failures
  - WAF/IDS signatures for known CVEs on NG components

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
- Evidence: fileciteturn2file10L19-L29
- MiTRE-CR911: mapping.json → vuln_exploit.sw_bugs_esrp
