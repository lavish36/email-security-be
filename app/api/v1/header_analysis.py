from fastapi import APIRouter, HTTPException, Request
from app.config import settings
from app.models.responses import SuccessResponse
from pydantic import BaseModel, Field
from typing import Dict, Any, Optional, List
import re
import email
from email.utils import parseaddr, getaddresses
from email.header import decode_header, make_header
from email.utils import parsedate_to_datetime
import asyncio
import imaplib
import ssl
import time
from datetime import datetime, timedelta
try:
  import certifi  # optional
except Exception:
  certifi = None

router = APIRouter(prefix="/api/v1/intelligence", tags=["Intelligence"])

class HeaderAnalysisRequest(BaseModel):
    """Request model for analyzing raw email headers."""
    headers: str = Field(..., description="Raw email headers as plain text")


class IMAPHeaderRequest(BaseModel):
    """Request model for retrieving headers via IMAP."""
    host: str = Field(..., description="IMAP server hostname")
    username: str = Field(..., description="IMAP username/email")
    password: str = Field(..., description="IMAP password")
    port: int = Field(993, description="IMAP port, default 993")
    mailbox: str = Field("INBOX", description="Mailbox to select")
    use_ssl: bool = Field(True, description="Use SSL for IMAP connection")
    uid: Optional[str] = Field(None, description="Fetch by UID (preferred)")
    message_id: Optional[str] = Field(None, description="Fetch by Message-ID header")
    search: Optional[str] = Field(None, description="IMAP SEARCH criteria, e.g., SUBJECT \"keyword\" or FROM \"user@domain\"")
    search_queries: Optional[List[str]] = Field(None, description="Multiple IMAP SEARCH queries to try in order")
    latest: bool = Field(True, description="When multiple results, fetch the latest one")


class EmailHeaderFetchRequest(BaseModel):
  """Request model for fetching the latest sent email and analyzing its headers.

  Intended flow: user sends an email to the configured testing inbox, then clicks a
  button to trigger this endpoint. We will poll the inbox briefly and fetch the
  matching message headers for analysis.
  """
  from_address: Optional[str] = Field(None, description="Filter by sender email address")
  subject: Optional[str] = Field(None, description="Filter by subject contains")
  recipient_address: Optional[str] = Field(None, description="Filter by recipient (To/Delivered-To)")
  message_id: Optional[str] = Field(None, description="Exact Message-ID to match (optional)")
  unseen_only: bool = Field(True, description="Limit search to UNSEEN messages")
  since_minutes: int = Field(60, description="Search only messages received in the last N minutes")
  wait_seconds: int = Field(30, description="How long to wait for the email to arrive")
  latest: bool = Field(True, description="When multiple results, fetch the latest one")


def _build_imap_search_queries(req: EmailHeaderFetchRequest) -> List[str]:
  base: List[str] = []
  if req.unseen_only:
    base.append("UNSEEN")
  if req.from_address:
    base.append(f'FROM "{req.from_address}"')
  if req.subject:
    base.append(f'SUBJECT "{req.subject}"')
  if req.since_minutes and req.since_minutes > 0:
    since_dt = datetime.utcnow() - timedelta(minutes=req.since_minutes)
    base.append(f'SINCE {since_dt.strftime("%d-%b-%Y")}')

  base_query = " ".join(base) if base else "ALL"

  # If recipient specified, try Delivered-To first (common in Gmail), then TO
  queries: List[str] = []
  if req.recipient_address:
    addr = req.recipient_address
    queries.append(f'{base_query} HEADER "Delivered-To" "{addr}"')
    queries.append(f'{base_query} TO "{addr}"')
  else:
    queries.append(base_query)
  return queries


@router.post("/email-header-analysis", response_model=SuccessResponse)
async def email_header_analysis(req: EmailHeaderFetchRequest):
  """Poll the configured IMAP inbox for a recently received email and analyze its headers.

  This supports the UX flow where the user sends an email to our testing inbox, then
  clicks a button to analyze that email's headers.
  """
  # Ensure IMAP is configured on the server
  if not settings.imap_host or not settings.imap_username or not settings.imap_password:
    raise HTTPException(status_code=422, detail="IMAP settings are not configured on the server")

  # Hardcode recipient to target plus-address
  req.recipient_address = "lavishfroiden+emailsecurity@gmail.com"

  # Prefer direct Message-ID match if provided; otherwise build SEARCH queries
  search_queries = None if req.message_id else _build_imap_search_queries(req)

  # Polling window
  wait_seconds = max(0, int(req.wait_seconds or 0))
  deadline = time.time() + wait_seconds
  poll_interval = 2

  last_error: Optional[Exception] = None
  while True:
    try:
      hdr_req = IMAPHeaderRequest(
        host=settings.imap_host,
        username=settings.imap_username,
        password=settings.imap_password,
        port=settings.imap_port,
        mailbox=settings.imap_mailbox,
        use_ssl=settings.imap_use_ssl,
        uid=None,
        message_id=req.message_id,
        search=None,
        search_queries=search_queries,
        latest=req.latest,
      )
      raw = await asyncio.to_thread(_imap_connect_and_fetch, hdr_req)
      analysis = await _analyze_headers_core(raw)
      # Add recipient match info if requested
      if req.recipient_address and isinstance(analysis.data, dict):
        identities = analysis.data.get("identities") or {}
        delivered_to = identities.get("delivered_to") or []
        to_list = identities.get("to") or []
        candidate_values = []
        if isinstance(delivered_to, list):
          candidate_values.extend([str(v).lower() for v in delivered_to])
        if isinstance(to_list, list):
          candidate_values.extend([str(v).lower() for v in to_list])
        match = str(req.recipient_address).lower() in candidate_values
        identities["selected_recipient"] = req.recipient_address
        identities["recipient_match"] = match
        analysis.data["identities"] = identities
      return analysis
    except HTTPException as he:
      # Not found yet; keep polling until deadline
      if he.status_code == 404:
        if time.time() < deadline:
          await asyncio.sleep(poll_interval)
          continue
        # Deadline reached without finding a matching email
        raise HTTPException(status_code=404, detail="No email sent to this email")
      raise
    except Exception as e:
      last_error = e
      if time.time() < deadline:
        await asyncio.sleep(poll_interval)
        continue
      raise HTTPException(status_code=500, detail=f"Error polling inbox: {str(last_error)}")
    finally:
      if time.time() >= deadline:
        break

  # Timed out without finding a matching email
  raise HTTPException(status_code=404, detail="No email sent to this email")

def _decode_mime_header(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    try:
        decoded = str(make_header(decode_header(value)))
        return decoded
    except Exception:
        return value


def _extract_first_public_ip_from_received(received_headers: Optional[List[str]]):
    """Extract the earliest public IP address from the Received chain."""
    from app.utils.validation_utils import DomainValidator
    if not received_headers:
        return None
    ipv4_pattern = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    # Loose IPv6 matcher (sequence of hex blocks with colons, optional ::)
    ipv6_pattern = re.compile(r"\b(?:[A-Fa-f0-9]{1,4}:){1,7}[A-Fa-f0-9:]{1,4}\b")
    # Iterate from bottom-most (earliest) to top
    for header in reversed(received_headers):
        if not header:
            continue
        # Prefer bracketed [ip] candidates first
        bracketed = re.findall(r"\[([^\]]+)\]", header)
        candidates = []
        candidates.extend(bracketed)
        candidates.extend(ipv4_pattern.findall(header))
        candidates.extend(ipv6_pattern.findall(header))
        for ip in candidates:
            try:
                if DomainValidator.is_valid_ip(ip) and not DomainValidator.is_private_ip(ip):
                    return ip
            except Exception:
                continue
    return None


def _parse_authentication_results(headers: Optional[List[str] or str]) -> Dict[str, Any]:
  """Parse one or more Authentication-Results headers into a consolidated summary.

  Consolidates multiple lines, preferring 'pass' when any line indicates pass.
  Extracts identities: smtp.mailfrom, header.from, and DKIM header.d domains.
  """
  result: Dict[str, Any] = {
    "raw": headers,
    "spf": None,
    "dkim": None,
    "dmarc": None,
    "smtp_mailfrom": None,
    "header_from": None,
    "dkim_domains": []
  }
  if not headers:
    return result
  try:
    lines = headers if isinstance(headers, list) else [headers]
    spf_status, dkim_status, dmarc_status = None, None, None
    smtp_mailfrom_val, header_from_val = None, None
    dkim_domains: List[str] = []
    for line in lines:
      compact = " ".join(str(line).split())
      m = re.search(r"spf=(pass|fail|softfail|neutral|temperror|permerror|none)", compact, re.IGNORECASE)
      if m:
        spf_status = spf_status or m.group(1).lower()
        if m.group(1).lower() == 'pass':
          spf_status = 'pass'
      m = re.search(r"dkim=(pass|fail|softfail|neutral|temperror|permerror|none)", compact, re.IGNORECASE)
      if m:
        dkim_status = dkim_status or m.group(1).lower()
        if m.group(1).lower() == 'pass':
          dkim_status = 'pass'
      m = re.search(r"dmarc=(pass|fail|softfail|neutral|temperror|permerror|none)", compact, re.IGNORECASE)
      if m:
        dmarc_status = dmarc_status or m.group(1).lower()
        if m.group(1).lower() == 'pass':
          dmarc_status = 'pass'
      m = re.search(r"smtp\.mailfrom=([^;\s]+)", compact, re.IGNORECASE)
      if m and not smtp_mailfrom_val:
        smtp_mailfrom_val = m.group(1)
      m = re.search(r"header\.from=([^;\s]+)", compact, re.IGNORECASE)
      if m and not header_from_val:
        header_from_val = m.group(1)
      # DKIM identity domains
      for dm in re.findall(r"header\.d=([^;\s]+)", compact, re.IGNORECASE):
        try:
          dkim_domains.append(dm.lower())
        except Exception:
          continue
    result["spf"], result["dkim"], result["dmarc"] = spf_status, dkim_status, dmarc_status
    result["smtp_mailfrom"], result["header_from"] = smtp_mailfrom_val, header_from_val
    result["dkim_domains"] = list(dict.fromkeys(dkim_domains))  # unique, preserve order
  except Exception:
    pass
  return result


def _coerce_to_headers_text(raw: str) -> str:
    """
    If the body contains a JSON wrapper or any non-header prefix, trim to the first
    header-like line (e.g., From:, Received:, Subject:). This allows users to send
    unescaped JSON where headers are embedded in a "headers" field.
    """
    if not raw:
        return raw
    try:
        lines = raw.splitlines()
        header_line_regex = re.compile(r"^[A-Za-z][A-Za-z0-9-]*:\s?")
        start_index = None
        for i, line in enumerate(lines):
            if header_line_regex.match(line.strip()):
                start_index = i
                break
        if start_index is not None and start_index > 0:
            return "\n".join(lines[start_index:])
        return raw
    except Exception:
        return raw


async def _analyze_headers_core(raw: str) -> SuccessResponse:
    if not raw or not raw.strip():
        raise HTTPException(status_code=400, detail="Headers content is empty")

    # Parse headers using Python email library
    msg = email.message_from_string(raw)
    from_header = _decode_mime_header(msg.get("From"))
    to_header = _decode_mime_header(msg.get("To"))
    cc_header = _decode_mime_header(msg.get("Cc"))
    return_path = _decode_mime_header(msg.get("Return-Path") or msg.get("Sender"))
    message_id = _decode_mime_header(msg.get("Message-ID"))
    subject = _decode_mime_header(msg.get("Subject"))
    date_hdr = _decode_mime_header(msg.get("Date"))
    dkim_sig = msg.get("DKIM-Signature")
    dkim_sigs = msg.get_all("DKIM-Signature") or ([] if not dkim_sig else [dkim_sig])
    auth_results_all = msg.get_all("Authentication-Results") or []
    arc_auth_results_all = msg.get_all("ARC-Authentication-Results") or []
    arc_seal_all = msg.get_all("ARC-Seal") or []
    arc_msg_sig_all = msg.get_all("ARC-Message-Signature") or []
    mime_version = _decode_mime_header(msg.get("MIME-Version"))
    content_type = _decode_mime_header(msg.get("Content-Type"))
    list_unsub = _decode_mime_header(msg.get("List-Unsubscribe"))
    list_unsub_post = _decode_mime_header(msg.get("List-Unsubscribe-Post"))
    received_spf = msg.get("Received-SPF")
    received_all = msg.get_all("Received") or []

    from_name, from_email = parseaddr(from_header) if from_header else (None, None)
    _, rp_email = parseaddr(return_path) if return_path else (None, None)

    def extract_domain(email_addr: Optional[str]):
        if not email_addr or "@" not in email_addr:
            return None
        return email_addr.split("@", 1)[1].strip().lower()

    from_domain = extract_domain(from_email)
    return_path_domain = extract_domain(rp_email)

    # Parse DKIM signatures (all)
    dkim_selector = None
    dkim_domain = None
    dkim_signature_list = []
    for sig in dkim_sigs:
        try:
            s_match = re.search(r"\bs=([^;\s]+)", sig)
            d_match = re.search(r"\bd=([^;\s]+)", sig)
            bh_match = re.search(r"\bbh=([^;\s]+)", sig)
            entry = {
                "selector": s_match.group(1).strip() if s_match else None,
                "domain": (d_match.group(1).strip().lower() if d_match else None),
                "bh": bh_match.group(1).strip() if bh_match else None
            }
            dkim_signature_list.append(entry)
            # Use first observed values as primary
            if not dkim_selector and entry["selector"]:
                dkim_selector = entry["selector"]
            if not dkim_domain and entry["domain"]:
                dkim_domain = entry["domain"]
        except Exception:
            continue

    # Earliest public IP from Received chain
    sending_ip = _extract_first_public_ip_from_received(received_all)

    # Parse Authentication-Results quick summary; include ARC and Received-SPF if present
    ar_summary = _parse_authentication_results(auth_results_all)
    arc_summary = _parse_authentication_results(arc_auth_results_all)
    # Prefer explicit AR, fallback to ARC when missing
    for key in ["spf", "dkim", "dmarc"]:
        if not ar_summary.get(key) and arc_summary.get(key):
            ar_summary[key] = arc_summary[key]
    if arc_summary:
        ar_summary["arc_raw"] = arc_summary.get("raw")
    if received_spf:
        try:
            # Gmail and others may include: Received-SPF: pass (google.com: ...) client-ip=; envelope-from=; helo=
            m = re.search(r"(pass|fail|softfail|neutral|temperror|permerror|none)", received_spf, re.IGNORECASE)
            if m:
                ar_summary["received_spf"] = m.group(1).lower()
            ipm = re.search(r"client-ip=([^;\s]+)", received_spf, re.IGNORECASE)
            if ipm and not ar_summary.get("client_ip"):
                ar_summary["client_ip"] = ipm.group(1)
            env = re.search(r"envelope-from=([^;\s]+)", received_spf, re.IGNORECASE)
            if env and not ar_summary.get("smtp_mailfrom"):
                ar_summary["smtp_mailfrom"] = env.group(1)
        except Exception:
            pass

    # Choose primary domain for DNS posture evaluation
    primary_domain = return_path_domain or from_domain or dkim_domain

    # DMARC alignment checks (relaxed):
    def extract_domain(addr: Optional[str]) -> Optional[str]:
        if not addr or '@' not in addr:
            return None
        return addr.split('@', 1)[1].lower()

    header_from_domain = extract_domain(ar_summary.get("header_from") or from_email)
    smtp_mailfrom_domain = extract_domain(ar_summary.get("smtp_mailfrom"))
    dkim_domains = ar_summary.get("dkim_domains") or ([] if not dkim_domain else [dkim_domain])

    spf_aligned = False
    if header_from_domain and smtp_mailfrom_domain:
        # relaxed: organizational-domain match would be ideal; use suffix match as heuristic
        spf_aligned = header_from_domain == smtp_mailfrom_domain or header_from_domain.endswith("." + smtp_mailfrom_domain) or smtp_mailfrom_domain.endswith("." + header_from_domain)

    dkim_aligned = False
    if header_from_domain and dkim_domains:
        for dd in dkim_domains:
            if header_from_domain == dd or header_from_domain.endswith("." + dd) or str(dd).endswith("." + header_from_domain):
                dkim_aligned = True
                break

    # Evaluate DNS-based posture using existing services
    spf_result = {}
    dkim_dns_result = []
    dmarc_result = {}
    if primary_domain:
        try:
            from app.services.dns_service import dns_service
            from app.utils.validation_utils import DomainValidator
            domain_normalized = DomainValidator.normalize_domain(primary_domain)
            spf_result = await dns_service.get_spf_record(domain_normalized) or {}
            dmarc_result = await dns_service.get_dmarc_record(domain_normalized) or {}
            # If we have DKIM selector+domain from header, validate that DNS record exists
            if dkim_selector and dkim_domain:
                dkim_dns_result = await dns_service.get_dkim_records(dkim_domain, [dkim_selector]) or []
            else:
                # Broaden DKIM lookup using common selectors if header lacks selector
                common_selectors = (settings.default_dkim_selectors or "default,google,selector1,selector2,k1,mandrill,s1,s2").split(',')
                if dkim_domain:
                    dkim_dns_result = await dns_service.get_dkim_records(dkim_domain, [s.strip() for s in common_selectors if s.strip()]) or []
        except Exception as e:
            # Continue with partial results
            spf_result = spf_result or {"exists": False, "status": "error", "warnings": [str(e)]}
            dmarc_result = dmarc_result or {"exists": False, "status": "error"}

    # Compute a small industry-style score (0-10) based on DNS posture
    industry_score = 0
    # SPF (3)
    if spf_result and spf_result.get('status') == 'pass':
        industry_score += 3
    elif spf_result and spf_result.get('status') == 'warning':
        industry_score += 2
    elif spf_result and spf_result.get('status'):
        industry_score += 1
    # DKIM (3)
    dkim_has_passing = any(r and r.get('status') == 'pass' for r in (dkim_dns_result or []))
    dkim_has_records = any(r and r.get('exists') for r in (dkim_dns_result or []))
    if dkim_has_passing:
        industry_score += 3
    elif dkim_has_records:
        industry_score += 2
    elif dkim_dns_result:
        industry_score += 1
    # DMARC (4)
    if dmarc_result and dmarc_result.get('status') == 'pass':
        if dmarc_result.get('subdomain_policy') == 'none' or dmarc_result.get('policy') == 'none':
            industry_score += 3
        else:
            industry_score += 4
    elif dmarc_result and dmarc_result.get('status') == 'warning':
        industry_score += 2
    elif dmarc_result and dmarc_result.get('status'):
        industry_score += 1

    if industry_score >= 8:
        risk_level = 'low_risk'
    elif industry_score >= 6:
        risk_level = 'medium_risk'
    else:
        risk_level = 'high_risk'

    # Parse date to ISO if possible
    date_iso = None
    try:
        if date_hdr:
            dt = parsedate_to_datetime(date_hdr)
            if dt:
                date_iso = dt.isoformat()
    except Exception:
        pass

    # Parse date to ISO if possible
    date_iso = None
    try:
        if date_hdr:
            dt = parsedate_to_datetime(date_hdr)
            if dt:
                date_iso = dt.isoformat()
    except Exception:
        pass

    # Parse To/Cc addresses
    to_emails = [addr for _, addr in (getaddresses([to_header]) if to_header else [])]
    # Delivered-To/Envelope-To (common in Gmail and some servers)
    delivered_to_headers = msg.get_all("Delivered-To") or []
    envelope_to_headers = msg.get_all("Envelope-To") or []
    x_original_to_headers = msg.get_all("X-Original-To") or []
    delivered_to_all = delivered_to_headers + envelope_to_headers + x_original_to_headers
    cc_emails = [addr for _, addr in (getaddresses([cc_header]) if cc_header else [])]

    # Parse received hops into structured entries
    received_hops = []
    for r in received_all:
        try:
            hop = {"raw": r}
            # from host
            fm = re.search(r"\bfrom\s+([^;]+?)\s+(?:by|with|id|;)", r, re.IGNORECASE)
            if fm:
                hop["from"] = fm.group(1).strip()
            # by host
            bm = re.search(r"\bby\s+([^;]+?)\s+(?:with|id|;)", r, re.IGNORECASE)
            if bm:
                hop["by"] = bm.group(1).strip()
            # with proto
            wm = re.search(r"\bwith\s+([^;]+?)\s+(?:id|;)", r, re.IGNORECASE)
            if wm:
                hop["with"] = wm.group(1).strip()
            # TLS detection from hop 'with' (e.g., ESMTPS, ESMTPSA, TLS1.3)
            try:
                proto = hop.get("with", "")
                hop["tls"] = bool(re.search(r"TLS|ESMTPSA|ESMTPS", proto, re.IGNORECASE)) or bool(re.search(r"TLS\s*1\.[0-3]", r, re.IGNORECASE))
            except Exception:
                hop["tls"] = None
            # id
            idm = re.search(r"\bid\s+([^;\s]+)", r, re.IGNORECASE)
            if idm:
                hop["id"] = idm.group(1).strip()
            # date (after last ;) 
            if ";" in r:
                hop["date"] = r.split(";")[-1].strip()
            # bracketed ip
            br = re.findall(r"\[([^\]]+)\]", r)
            if br:
                hop["ips"] = br
            else:
                # fallback ip search
                ip4 = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", r)
                ip6 = re.findall(r"\b(?:[A-Fa-f0-9]{1,4}:){1,7}[A-Fa-f0-9:]{1,4}\b", r)
                hop["ips"] = list(set(ip4 + ip6)) if (ip4 or ip6) else []
            received_hops.append(hop)
        except Exception:
            continue

    # Choose sending IP fallback from client_ip when Received chain empty
    sending_ip = _extract_first_public_ip_from_received(received_all)
    if not sending_ip and ar_summary.get("client_ip"):
        sending_ip = ar_summary.get("client_ip")

    data = {
        "identities": {
            "from_name": from_name,
            "from_email": from_email,
            "from_domain": from_domain,
            "return_path": rp_email,
            "return_path_domain": return_path_domain,
            "message_id": message_id,
            "subject": subject,
            "date": date_iso or date_hdr,
            "to": to_emails,
            "cc": cc_emails,
            "delivered_to": delivered_to_all
        },
        "received_chain_count": len(received_all),
        "received_hops": received_hops,
        "sending_ip": sending_ip,
        "authentication_results": ar_summary,
        "alignment": {
            "header_from_domain": header_from_domain,
            "smtp_mailfrom_domain": smtp_mailfrom_domain,
            "dkim_domains": dkim_domains,
            "spf_aligned": spf_aligned,
            "dkim_aligned": dkim_aligned
        },
        "dkim_signature": {
            "selector": dkim_selector,
            "domain": dkim_domain,
            "present": bool(dkim_sigs)
        },
        "dkim_signatures": dkim_signature_list,
        "arc": {
            "authentication_results": arc_auth_results_all,
            "seal": arc_seal_all,
            "message_signatures": arc_msg_sig_all
        },
        "mime": {
            "version": mime_version,
            "content_type": content_type
        },
        "list_unsubscribe": {
            "value": list_unsub,
            "post": list_unsub_post
        },
        "dns_posture": {
            "primary_domain": primary_domain,
            "spf": (spf_result or {"status": "not_found", "exists": False}),
            "dkim": (dkim_dns_result or []),
            "dmarc": (dmarc_result or {"status": "not_found", "exists": False})
        },
        "industry_score": industry_score,
        "risk_level": risk_level
    }

    # Provide sections similar to referenced tool: message, hop, other
    data["sections"] = {
        "message_details": {
            "sender_name": from_name,
            "subject": subject,
            "message_id": message_id,
            "date": date_iso or date_hdr
        },
        "hop_details": {
            "count": len(received_hops),
            "hops": received_hops
        },
        "other_details": {
            "authentication_results": ar_summary,
            "arc": data["arc"],
            "mime": data["mime"],
            "list_unsubscribe": data["list_unsubscribe"]
        }
    }

    return SuccessResponse(
        message="Email header analysis completed",
        data=data
    )


@router.post("/analyze-headers", response_model=SuccessResponse)
async def analyze_email_headers(request: Request):
    """
    Analyze raw email headers.

    Accepts either:
    - application/json with { "headers": "..." } (newlines may be unescaped)
    - text/plain body containing the raw headers
    - any other content-type; falls back to treating the body as raw text
    """
    try:
        raw = None
        # Try JSON first
        try:
            payload = await request.json()
            if isinstance(payload, dict):
                raw = payload.get("headers") or payload.get("raw") or payload.get("data")
        except Exception:
            # Not JSON or invalid JSON; we'll fall back to raw body
            pass

        if not raw or not isinstance(raw, str) or not raw.strip():
            body_bytes = await request.body()
            if body_bytes:
                raw = body_bytes.decode("utf-8", errors="ignore")

        if not raw or not raw.strip():
            raise HTTPException(status_code=422, detail="No headers content found in request")

        # Trim to header-like content if a wrapper is present
        raw_trimmed = _coerce_to_headers_text(raw)

        return await _analyze_headers_core(raw_trimmed)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error analyzing headers: {str(e)}")




def _imap_connect_and_fetch(req: IMAPHeaderRequest) -> str:
    """Synchronous helper to fetch raw headers via IMAP."""
    imap = None
    try:
        if req.use_ssl:
            # Build SSL context using settings and optional CA bundle
            cafile = settings.imap_tls_cafile if getattr(settings, 'imap_tls_cafile', None) else (certifi.where() if certifi else None)
            capath = settings.imap_tls_capath if getattr(settings, 'imap_tls_capath', None) else None
            context = ssl.create_default_context(cafile=cafile, capath=capath)
            if not getattr(settings, 'imap_tls_check_hostname', True):
                context.check_hostname = False
            if not getattr(settings, 'imap_tls_verify', True):
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
            imap = imaplib.IMAP4_SSL(req.host, req.port, ssl_context=context)
        else:
            imap = imaplib.IMAP4(req.host, req.port)
        imap.login(req.username, req.password)
        typ, _ = imap.select(req.mailbox or "INBOX")
        if typ != 'OK':
            raise HTTPException(status_code=400, detail=f"Unable to select mailbox: {req.mailbox}")

        candidate_uids: List[bytes] = []

        # Priority 1: explicit UID
        if req.uid:
            uid_val = str(req.uid).encode()
            candidate_uids = [uid_val]
        else:
            # Priority 2: Message-ID search
            if req.message_id:
                msgid = req.message_id.strip()
                # Some servers need angle brackets included/excluded; try both
                queries = [f'HEADER Message-ID "{msgid}"']
                if not (msgid.startswith('<') and msgid.endswith('>')):
                    queries.append(f'HEADER Message-ID "<{msgid}>"')
                for q in queries:
                    typ, data = imap.uid('SEARCH', None, q)
                    if typ == 'OK' and data and data[0]:
                        parts = data[0].split()
                        if parts:
                            candidate_uids = parts
                            break
            # Priority 3: multiple SEARCH queries (if provided), then generic or ALL
            if not candidate_uids:
                # Try multiple queries first
                if req.search_queries:
                    for q in req.search_queries:
                        typ, data = imap.uid('SEARCH', None, q)
                        if typ == 'OK' and data and data[0]:
                            candidate_uids = data[0].split()
                            if candidate_uids:
                                break
                if not candidate_uids and req.search:
                    typ, data = imap.uid('SEARCH', None, req.search)
                    if typ == 'OK' and data and data[0]:
                        candidate_uids = data[0].split()
                else:
                    # All messages; pick latest
                    typ, data = imap.uid('SEARCH', None, 'ALL')
                    if typ == 'OK' and data and data[0]:
                        candidate_uids = data[0].split()

        if not candidate_uids:
            raise HTTPException(status_code=404, detail="No matching messages found")

        target_uid = candidate_uids[-1] if req.latest else candidate_uids[0]
        typ, fetched = imap.uid('FETCH', target_uid, '(BODY.PEEK[HEADER])')
        if typ != 'OK' or not fetched:
            raise HTTPException(status_code=404, detail="Unable to fetch headers for the selected message")

        # fetched is a list like [(b'UID (BODY[HEADER] {bytes}', b'...headers...'), b')']
        raw_bytes = b''
        for part in fetched:
            if isinstance(part, tuple) and len(part) == 2 and isinstance(part[1], (bytes, bytearray)):
                raw_bytes += part[1]

        if not raw_bytes:
            raise HTTPException(status_code=404, detail="Empty headers returned by server")

        try:
            return raw_bytes.decode('utf-8')
        except Exception:
            return raw_bytes.decode('latin-1', errors='ignore')
    finally:
        try:
            if imap is not None:
                imap.logout()
        except Exception:
            pass


@router.post("/analyze-headers-imap", response_model=SuccessResponse)
async def analyze_email_headers_imap(req: IMAPHeaderRequest):
    """
    Analyze headers by fetching them from an IMAP mailbox.
    Provide either uid, message_id, or search criteria; otherwise latest message is used.
    """
    try:
        raw = await asyncio.to_thread(_imap_connect_and_fetch, req)
        return await _analyze_headers_core(raw)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error analyzing headers (imap): {str(e)}")


@router.post("/analyze-latest-imap", response_model=SuccessResponse)
async def analyze_latest_inbox_email():
    """
    Analyze the latest email in the configured IMAP inbox.
    Configure IMAP credentials in environment variables (.env):
    IMAP_HOST, IMAP_PORT, IMAP_USERNAME, IMAP_PASSWORD, IMAP_MAILBOX, IMAP_USE_SSL.
    """
    # Validate configuration
    if not settings.imap_host or not settings.imap_username or not settings.imap_password:
        raise HTTPException(status_code=422, detail="IMAP settings are not configured on the server")

    req = IMAPHeaderRequest(
        host=settings.imap_host,
        username=settings.imap_username,
        password=settings.imap_password,
        port=settings.imap_port,
        mailbox=settings.imap_mailbox,
        use_ssl=settings.imap_use_ssl,
        latest=True
    )
    try:
        raw = await asyncio.to_thread(_imap_connect_and_fetch, req)
        return await _analyze_headers_core(raw)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error analyzing latest inbox email: {str(e)}")


@router.post("/analyze-latest-unread-imap", response_model=SuccessResponse)
async def analyze_latest_unread_inbox_email():
    """
    Analyze the latest UNSEEN (unread) email in the configured IMAP inbox.
    Uses IMAP SEARCH UNSEEN and selects the latest match.
    """
    if not settings.imap_host or not settings.imap_username or not settings.imap_password:
        raise HTTPException(status_code=422, detail="IMAP settings are not configured on the server")

    req = IMAPHeaderRequest(
        host=settings.imap_host,
        username=settings.imap_username,
        password=settings.imap_password,
        port=settings.imap_port,
        mailbox=settings.imap_mailbox,
        use_ssl=settings.imap_use_ssl,
        search="UNSEEN",
        latest=True
    )
    try:
        raw = await asyncio.to_thread(_imap_connect_and_fetch, req)
        return await _analyze_headers_core(raw)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error analyzing latest unread email: {str(e)}")
