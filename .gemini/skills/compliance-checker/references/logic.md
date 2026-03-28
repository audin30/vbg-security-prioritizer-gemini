# Compliance Checker Logic Reference

This document defines the SQL and logic used to identify compliance violations across resources, primarily leveraging data from Wiz.

## Database Schema Highlights

- `public.wiz_issues`: Contains misconfigurations and compliance violations detected by Wiz.
- `public.wiz_inventory`: Contains metadata for the assets being checked.

## Compliance Violation Detection Logic

A finding is considered a compliance violation if:
1.  The `status` is 'OPEN'.
2.  The `name` or `description` contains compliance-related keywords (e.g., 'CIS', 'NIST', 'SOC2', 'HIPAA', 'PCI', 'GDPR', 'Compliance').

## Scoring & Prioritization

Violations are prioritized by severity:
- **CRITICAL**: Action required immediately.
- **HIGH**: Priority fix.
- **MEDIUM**: Remediation required.
- **LOW**: Informational/Best practice.

## Standard Compliance Query

```sql
SELECT 
    i.name as violation_name,
    i.severity,
    inv.name as resource_name,
    inv.type as resource_type,
    i.description,
    i.status
FROM public.wiz_issues i
JOIN public.wiz_inventory inv ON i.resource_id = inv.id
WHERE i.status = 'OPEN'
AND (
    i.name ILIKE '%compliance%' OR 
    i.name ILIKE '%CIS%' OR 
    i.name ILIKE '%NIST%' OR 
    i.name ILIKE '%SOC2%' OR 
    i.name ILIKE '%HIPAA%' OR 
    i.name ILIKE '%PCI%' OR 
    i.name ILIKE '%GDPR%' OR
    i.description ILIKE '%compliance%' OR 
    i.description ILIKE '%CIS%' OR 
    i.description ILIKE '%NIST%' OR 
    i.description ILIKE '%SOC2%' OR 
    i.description ILIKE '%HIPAA%' OR 
    i.description ILIKE '%PCI%' OR 
    i.description ILIKE '%GDPR%'
)
ORDER BY 
    CASE i.severity
        WHEN 'CRITICAL' THEN 1
        WHEN 'HIGH' THEN 2
        WHEN 'MEDIUM' THEN 3
        WHEN 'LOW' THEN 4
        ELSE 5
    END ASC;
```
