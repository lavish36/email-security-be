import os
from typing import Optional
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    """Application settings."""
    
    # API Configuration
    api_title: str = "Domain Security API"
    api_version: str = "1.0.0"
    debug: bool = False
    
    # Server Configuration
    host: str = "0.0.0.0"
    port: int = 8000
    
    # External API Keys
    ipinfo_token: Optional[str] = None
    virustotal_api_key: Optional[str] = None
    spamhaus_api_key: Optional[str] = None
    openrouter_api_key: Optional[str] = None
    openrouter_site_url: Optional[str] = None  # Optional: Site URL for rankings on openrouter.ai
    openrouter_site_name: Optional[str] = None  # Optional: Site name for rankings on openrouter.ai
    
    # Rate Limiting
    rate_limit_per_minute: int = 60
    
    # DNS Configuration
    dns_timeout: float = 5.0
    dns_retries: int = 3
    dns_nameservers: Optional[str] = None  # Comma-separated, e.g., "1.1.1.1,8.8.8.8"
    
    # Performance Configuration
    default_dkim_selectors: str = "default,google,selector1,selector2,k1,mandrill,s1,s2"  # Restored all 8 selectors for comprehensive checking
    
    # IMAP Configuration (for inbound testing mailbox)
    imap_host: Optional[str] = None
    imap_port: int = 993
    imap_username: Optional[str] = None
    imap_password: Optional[str] = None
    imap_mailbox: str = "INBOX"
    imap_use_ssl: bool = True
    # IMAP TLS options
    imap_tls_verify: bool = True
    imap_tls_check_hostname: bool = True
    imap_tls_cafile: Optional[str] = None
    imap_tls_capath: Optional[str] = None
    
    model_config = SettingsConfigDict(
        env_file=".env",
        case_sensitive=False,
        extra="ignore"  # Ignore extra environment variables (e.g., old OPENAI_API_KEY)
    )


# Global settings instance
settings = Settings() 