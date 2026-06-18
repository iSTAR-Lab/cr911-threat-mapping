"""Validate vulnerability identifiers against their authoritative source.

CVE ids are looked up in the MITRE CVE Services API; GHSA, CGA, BIT and other
OSV-style ids are looked up in OSV.dev. Each id resolves to one of three states:

    valid       the record exists
    invalid     the source returned 404 (the id does not exist)
    unverified  the lookup failed (network error, rate limit, server error)

Keeping "unverified" separate from "invalid" means a transient failure is never
mistaken for a non-existent vulnerability.
"""
import time

import requests

MITRE_CVE_API = "https://cveawg.mitre.org/api/cve/{}"
OSV_API = "https://api.osv.dev/v1/vulns/{}"
REQUEST_TIMEOUT = 5

# Prefixes for ids that live in OSV.dev rather than the CVE list.
OSV_PREFIXES = ("GHSA-", "CGA-", "BIT-", "PYSEC-", "GO-", "RUSTSEC-", "OSV-")


def validate_cve_ids(dataframe):
    """Validate every unique id in the dataframe's 'CVE' column.

    Returns a dict with counts (valid, invalid, unverified, skipped) and the
    lists of invalid and unverified ids.
    """
    ids = [str(v).strip() for v in dataframe["CVE"].dropna().unique()]
    ids = [i for i in ids if i]

    counts = {"valid": 0, "invalid": 0, "unverified": 0, "skipped": 0}
    invalid_ids, unverified_ids = [], []

    for position, vuln_id in enumerate(ids, start=1):
        if vuln_id.startswith("CVE-"):
            status = check_cve_in_mitre(vuln_id)
        elif vuln_id[0].isdigit() and "-" in vuln_id:
            # Bare "2021-12345" form -> normalise to a CVE id before lookup.
            status = check_cve_in_mitre(f"CVE-{vuln_id}")
        elif vuln_id.startswith(OSV_PREFIXES):
            status = check_id_in_osv(vuln_id)
        else:
            print(f"  skipping {vuln_id} (unrecognised id type)")
            counts["skipped"] += 1
            continue

        if status is True:
            counts["valid"] += 1
        elif status is False:
            counts["invalid"] += 1
            invalid_ids.append(vuln_id)
        else:
            counts["unverified"] += 1
            unverified_ids.append(vuln_id)

        if position % 10 == 0:
            print(f"  {position}/{len(ids)} ids checked")
        time.sleep(0.1)  # light pacing for the public APIs

    print(f"Validation: {counts['valid']} valid, {counts['invalid']} invalid, "
          f"{counts['unverified']} unverified, {counts['skipped']} skipped")

    return {**counts, "invalid_ids": invalid_ids, "unverified_ids": unverified_ids}


def check_cve_in_mitre(cve_id):
    """True if the CVE exists, False on 404, None if the lookup failed."""
    return _lookup(MITRE_CVE_API.format(cve_id), cve_id,
                   lambda data: "cveMetadata" in data or "containers" in data)


def check_id_in_osv(vuln_id):
    """True if the id exists in OSV.dev, False on 404, None if the lookup failed.

    Covers GHSA, CGA, BIT and other OSV-style ids, which all share one endpoint.
    """
    return _lookup(OSV_API.format(vuln_id), vuln_id, lambda data: "id" in data)


def _lookup(url, vuln_id, exists):
    """Query an id endpoint and map the response to True / False / None."""
    try:
        response = requests.get(url, timeout=REQUEST_TIMEOUT)
    except requests.RequestException as exc:
        print(f"  could not verify {vuln_id}: {exc}")
        return None

    if response.status_code == 404:
        return False
    if response.status_code != 200:
        return None
    try:
        return exists(response.json())
    except ValueError:
        return None
