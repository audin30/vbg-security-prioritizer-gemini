# Workflow: Security Prioritizer

Triggered when the user asks to prioritize findings, generate a risk report, identify top vulnerabilities, or similar.

## Data Sources (via PostgreSQL MCP)

- `public.tenable_findings` + `public.tenable_assets` — internal VM findings
- `public.tenable_asm_assets` — external attack surface
- `public.wiz_vulnerabilities` + `public.wiz_inventory` — cloud findings
- `public.cisa_kev` — actively exploited CVEs
- `public.phpipam_assets` — subnet/gateway context
- `public.vt_results` — VirusTotal enrichment cache (columns: `target`, `malicious`)

## Scoring Model

| Criteria | Points |
|---|---|
| Base CVSS score | 0–10 |
| CISA KEV | +100 |
| External visibility (ASM) | +50 |
| VirusTotal malicious (≥5 vendors) | +50 |
| Management/OOB subnet (phpIPAM) | +30 |
| Gateway device (phpIPAM) | +20 |
| Cross-tool confirmation (Tenable AND Wiz) | +20 |

## Step 1: Run the prioritization query

Use the PostgreSQL MCP tool to execute:

```sql
WITH
    all_vulns AS (
        SELECT
            tf.cve as cve_id,
            ta.hostname,
            ta.ipv4 as ip_address,
            'Tenable' as source,
            tf.cvss_score
        FROM public.tenable_findings tf
        JOIN public.tenable_assets ta ON tf.asset_id = ta.id

        UNION ALL

        SELECT
            wv.cve_id,
            wi.name as hostname,
            NULL as ip_address,
            'Wiz' as source,
            wv.cvss_score
        FROM public.wiz_vulnerabilities wv
        JOIN public.wiz_inventory wi ON wv.resource_id = wi.id
    ),
    prioritized_findings AS (
        SELECT
            v.cve_id,
            v.hostname,
            v.ip_address,
            MAX(v.cvss_score) as max_cvss,
            STRING_AGG(DISTINCT v.source, ', ') as sources,
            EXISTS (SELECT 1 FROM public.cisa_kev ck WHERE ck.cve_id = v.cve_id) as in_cisa_kev,
            EXISTS (SELECT 1 FROM public.tenable_asm_assets asm WHERE asm.hostname = v.hostname OR asm.ip_address = v.ip_address) as in_asm,
            EXISTS (SELECT 1 FROM public.phpipam_assets ipam WHERE (ipam.hostname = v.hostname OR ipam.ip_address = v.ip_address) AND (ipam.subnet_description ILIKE '%MGMT%' OR ipam.subnet_description ILIKE '%OOB%')) as in_mgmt_subnet,
            EXISTS (SELECT 1 FROM public.phpipam_assets ipam WHERE (ipam.hostname = v.hostname OR ipam.ip_address = v.ip_address) AND ipam.is_gateway = true) as is_gateway,
            EXISTS (SELECT 1 FROM public.vt_results vt WHERE (vt.target = v.hostname OR vt.target = v.ip_address) AND vt.malicious >= 5) as is_vt_malicious
        FROM all_vulns v
        GROUP BY v.cve_id, v.hostname, v.ip_address
    )
SELECT
    p.cve_id,
    ck.vulnerability_name,
    p.hostname,
    p.ip_address,
    p.sources,
    p.max_cvss,
    p.in_cisa_kev,
    p.in_asm,
    p.in_mgmt_subnet,
    p.is_gateway,
    p.is_vt_malicious,
    (
        COALESCE(p.max_cvss, 0) +
        (CASE WHEN p.in_cisa_kev THEN 100 ELSE 0 END) +
        (CASE WHEN p.in_asm THEN 50 ELSE 0 END) +
        (CASE WHEN p.in_mgmt_subnet THEN 30 ELSE 0 END) +
        (CASE WHEN p.is_gateway THEN 20 ELSE 0 END) +
        (CASE WHEN p.is_vt_malicious THEN 50 ELSE 0 END) +
        (CASE WHEN p.sources LIKE '%Tenable%' AND p.sources LIKE '%Wiz%' THEN 20 ELSE 0 END)
    ) as priority_score
FROM prioritized_findings p
LEFT JOIN public.cisa_kev ck ON p.cve_id = ck.cve_id
ORDER BY priority_score DESC
LIMIT 20;
```

## Step 2: Present results

For each finding, explain **why** it scored high. Example callouts:
- "In CISA KEV and externally visible — patch immediately"
- "Confirmed by both Tenable and Wiz, on a management subnet"
- "Flagged malicious by VirusTotal — active exploitation likely"

Default to top 20. If the user specifies a filter (e.g. "only CISA KEV", "only external", "only cloud"), add a `WHERE` clause before the final `ORDER BY`.
