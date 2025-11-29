
import sys
import os
sys.path.append(os.getcwd())

from app.utils.dns_utils import SPFParser, DKIMParser, DMARCParser

def test_spf():
    print("\n--- SPF Test ---")
    record = "v=spf1 include:_spf.google.com include:sendgrid.net ~all"
    result = SPFParser.parse_spf_record(record)
    print(f"Record: {record}")
    print(f"Result: {result}")

def test_dkim():
    print("\n--- DKIM Test ---")
    # Example 2048-bit key (truncated for brevity)
    record = "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1Z..."
    result = DKIMParser.parse_dkim_record(record)
    print(f"Record: {record}")
    print(f"Result: {result}")

def test_dmarc():
    print("\n--- DMARC Test ---")
    record = "v=DMARC1; p=reject; rua=mailto:dmarc@example.com; pct=100; adkim=s; aspf=s"
    result = DMARCParser.parse_dmarc_record(record)
    print(f"Record: {record}")
    print(f"Result: {result}")

if __name__ == "__main__":
    test_spf()
    test_dkim()
    test_dmarc()
