# Prioritization Logic Reference

This document defines the SQL and logic used to correlate and prioritize security findings across Tenable, Wiz, CISA KEV, and phpIPAM.

## Database Schema Highlights

- `public.tenable_findings`: Vulnerability data from Tenable.
- `public.tenable_assets`: Asset data from Tenable (Internal).
- `public.tenable_asm_assets`: Asset data from Tenable ASM (External).
- `public.wiz_vulnerabilities`: Vulnerability data from Wiz.
- `public.wiz_inventory`: Asset data from Wiz.
- `public.cisa_kev`: Known Exploited Vulnerabilities catalog.
- `public.phpipam_assets`: Internal IPAM records for subnet and ownership context.

## Prioritization Scoring System

- **Base Score**: `MAX(CVSS Score)` (0-10)
- **CISA KEV Bonus**: `+100` if the CVE is in the CISA KEV list.
- **External Visibility Bonus**: `+50` if the asset is found in Tenable ASM.
- **Management/OOB Subnet Bonus**: `+30` if the asset is in a Management or OOB subnet (from phpIPAM).
- **Gateway Bonus**: `+20` if the asset is marked as a Gateway in phpIPAM.
- **VirusTotal Malicious Bonus**: `+50` if the asset is flagged by 5+ security vendors in VirusTotal.
- **Cross-Tool Confirmation Bonus**: `+20` if the vulnerability is detected by both Tenable and Wiz.

## Standard Prioritization Query

```sql
WITH 
    all_vulns AS (
        -- Tenable Findings
        SELECT 
            tf.cve as cve_id,
            ta.hostname,
            ta.ipv4 as ip_address,
            'Tenable' as source,
            tf.cvss_score
        FROM public.tenable_findings tf
        JOIN public.tenable_assets ta ON tf.asset_id = ta.id
        
        UNION ALL
        
        -- Wiz Findings
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
            -- Check for CISA KEV
            EXISTS (SELECT 1 FROM public.cisa_kev ck WHERE ck.cve_id = v.cve_id) as in_cisa_kev,
            -- Check for ASM (External)
            EXISTS (SELECT 1 FROM public.tenable_asm_assets asm WHERE asm.hostname = v.hostname OR asm.ip_address = v.ip_address) as in_asm,
            -- Check phpIPAM context
            EXISTS (SELECT 1 FROM public.phpipam_assets ipam WHERE (ipam.hostname = v.hostname OR ipam.ip_address = v.ip_address) AND (ipam.subnet_description ILIKE '%MGMT%' OR ipam.subnet_description ILIKE '%OOB%')) as in_mgmt_subnet,
            EXISTS (SELECT 1 FROM public.phpipam_assets ipam WHERE (ipam.hostname = v.hostname OR ipam.ip_address = v.ip_address) AND ipam.is_gateway = true) as is_gateway,
            -- Check VirusTotal Reputation (Placeholder logic - assuming vt_results table)
            EXISTS (SELECT 1 FROM public.vt_results vt WHERE (vt.target = v.hostname OR vt.target = v.ip_address) AND vt.malicious >= 5) as is_vt_malicious
        FROM all_vulns v
        GROUP BY v.cve_id, v.hostname, v.ip_address
    )
SELECT 
    p.cve_id,
    ck.vulnerability_name,
    p.hostname,
    p.sources,
    p.max_cvss,
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
ORDER BY priority_score DESC;
```
