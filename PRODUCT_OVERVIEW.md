# Domain Security Platform — Product Overview

Protect your brand, email deliverability, and customer trust.

## Executive Summary

Organizations lose millions due to phishing, spoofing, and poor email hygiene. Our Domain Security Platform delivers an end-to-end way to assess, score, and strengthen your domain’s email security posture. It validates SPF, DKIM, DMARC, BIMI, MTA-STS, TLS-RPT, MX, and DNSSEC, correlates results with WHOIS, geolocation, and blacklist intelligence, and provides actionable recommendations — through a clean API designed for rapid frontend integration and automation.

## The Problem

- Email spoofing and phishing remain the top initial access vectors.
- Misconfigured SPF/DKIM/DMARC records cause reputation damage and deliverability losses.
- Fragmented tools and manual audits waste time and introduce inconsistency.
- Security teams lack a unified, explainable score and simple remediation guidance.

## Our Solution

A FastAPI-powered backend that:
- Performs comprehensive domain security scans across core email protocols.
- Produces an industry-aligned 100-point score with transparent breakdowns and risk levels.
- Generates ready-to-publish DNS records (SPF, DKIM, DMARC, MTA-STS, TLS-RPT).
- Enriches results with WHOIS, geolocation, and blacklist intelligence.
- Exposes a modern REST API with Swagger for easy productization and UI integrations.

## Key Capabilities

- Core protocol validation: SPF, DKIM (multi-selector), DMARC
- Advanced features: BIMI, MTA-STS, TLS-RPT, DNSSEC, MX analysis
- Threat intelligence: 15+ blacklists, consolidated reputation view
- Intelligence: WHOIS records, IP geolocation, ISP and ASN context
- Generators: SPF, DKIM key pair + record, DMARC, MTA-STS, TLS-RPT
- Guides: Provider-specific DNS setup documentation (e.g., Cloudflare, GoDaddy, Route53)
- Transparent scoring: Industry-standard 100-point model with risk classification
- Actionable insights: Prioritized recommendations and remediation steps

## How It Works

1) Input a domain via the API.
2) Resolve DNS for all relevant records and perform protocol-specific analysis.
3) Aggregate threat, WHOIS, and geolocation signals.
4) Calculate score and risk tier with a full breakdown.
5) Return a structured response with recommendations and next steps.

## Architecture (High-Level)

- FastAPI application (Python)
- DNS resolution via dnspython
- Data validation via Pydantic
- Cryptographic operations for DKIM key generation
- External enrichments (optional): IPInfo, VirusTotal, Spamhaus
- OpenAPI/Swagger documentation for all endpoints

## What Makes This Powerful

- Industry alignment: Score design mirrors professional tools (e.g., Easy DMARC) for credibility and comparability.
- Breadth + depth: From core auth (SPF/DKIM/DMARC) to advanced controls (MTA-STS/TLS-RPT/BIMI) and DNSSEC.
- Time-to-value: One API call yields a full audit, score, and to-do list for remediation.
- Developer-first: Clean, well-documented REST endpoints ready for frontend apps, CLIs, or automation.
- Extensible: Clear roadmap for TLS analysis depth, phishing link detection, subdomain security, and monitoring.

## Feature Detail

- SPF: Syntax, mechanism hygiene, include chains, multiple-record checks
- DKIM: Multi-selector probing, key strength and algorithm checks
- DMARC: Policy, alignment, reporting URIs, pct and subdomain policy
- MX: Presence, priority, security red flags (open relay risk indicators)
- BIMI: Logo/VMC presence and accessibility checks
- MTA-STS: Policy presence and basic validation
- TLS-RPT: Reporting configuration
- DNSSEC: Presence and basic validation
- Threat Intelligence: Consolidated blacklist status and risk scoring
- WHOIS & Geolocation: Registrar, dates, DNSSEC, IP-to-geo, ISP
- Record Generators: Opinionated, copy-paste-ready TXT records with instructions

## Scoring & Risk

- 100-point score
  - Core Protocols (70): SPF (25), DKIM (25), DMARC (20)
  - Policy Enforcement (20): DMARC policy (15), SPF hygiene (5)
  - Advanced Features (10): MTA-STS (4), TLS-RPT (3), BIMI (3)
- Risk levels: Low (90–100), Medium (70–89), High (0–69)
- Special handling for real-world DNS timeouts to avoid unfair penalties

## API Surface (Selected)

- Security
  - GET `/api/v1/security/scan/{domain}`
  - GET `/api/v1/security/spf/{domain}`
  - GET `/api/v1/security/dkim/{domain}`
  - GET `/api/v1/security/dmarc/{domain}`
  - GET `/api/v1/security/bimi/{domain}`
  - GET `/api/v1/security/mtasts/{domain}`
  - GET `/api/v1/security/tlsrpt/{domain}`
  - GET `/api/v1/security/mx/{domain}`
  - GET `/api/v1/security/dnssec/{domain}`
- Generators
  - POST `/api/v1/generate/spf`
  - POST `/api/v1/generate/dkim`
  - POST `/api/v1/generate/dmarc`
  - POST `/api/v1/generate/mtasts`
  - POST `/api/v1/generate/tlsrpt`
- Intelligence
  - GET `/api/v1/intelligence/whois/{domain}`
  - GET `/api/v1/intelligence/geolocation/{domain}`
  - GET `/api/v1/intelligence/threat/{domain}`
  - GET `/api/v1/intelligence/dns/{domain}`
- Guides
  - GET `/api/v1/guides/providers`
  - GET `/api/v1/guides/{provider}`

Full reference available via Swagger at `/docs` when the API is running.

## Value to Your Company

- Reduce risk: Prevent spoofing/phishing incidents and protect brand reputation.
- Improve deliverability: Correct misconfigurations that impact mailbox placement and revenue.
- Accelerate audits: Standardize security reviews with repeatable, API-driven checks.
- Empower non-experts: Clear scoring, risk tiers, and prescriptive remediation.
- Integrate everywhere: Embed into portals, CI/CD, or MSP workflows with minimal effort.

## Primary Use Cases

- Security posture assessments for owned and subsidiary domains
- Pre- and post-deployment email/DNS configuration validation
- Vendor risk and M&A domain audits
- MSP/MSSP domain onboarding and continuous checks
- Marketing deliverability optimization and monitoring

## Differentiation

- One-stop breadth across authentication, policy, branding, transport, and DNS integrity
- Explainable scoring with transparent category breakdowns
- Built-in record generators and provider guides to shorten remediation time
- Extensible roadmap for phishing, TLS depth, subdomains, and monitoring

## Roadmap Highlights

- Enhanced TLS/SSL: Certificate chain, versions, ciphers, HSTS, CT logs
- Email Header Analysis: Parse Authentication-Results, delivery path, reputation hints
- Phishing Link Detection: URL reputation, short URL expansion, ML signals
- Subdomain Security: Enumeration, takeover risk, wildcard and auth checks
- Advanced DNS Security: DoH, cache poisoning, amplification, CNAME chain analysis
- Deliverability Testing: Inbox placement, bounces, ISP reputation, scoring
- Compliance & Reporting: GDPR/HIPAA/PCI mapping, executive summaries, trends
- Real-time Monitoring: DNS change alerts, SLA-based uptime, historical posture


## KPIs to Track

- Security
  - % domains with Low Risk score (≥90)
  - Mean time to remediate (MTTR) critical findings
  - Reduction in phishing/spoofing incidents
- Deliverability
  - Increase in inbox placement rate
  - Decrease in bounce and spam complaint rates
- Operations
  - Scan volume per day/week
  - Average scan latency
  - Recommendation closure rate

