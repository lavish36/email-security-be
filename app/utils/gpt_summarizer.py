from typing import Dict, Any, Optional, List
import requests
import json
from app.config import settings


class GPTSummarizer:
    """GPT-powered summarization service for security scan results using OpenRouter."""
    
    def __init__(self):
        """Initialize GPT summarizer with API key from settings."""
        self.api_key = settings.openrouter_api_key
        self.site_url = settings.openrouter_site_url
        self.site_name = settings.openrouter_site_name
        self.api_url = "https://openrouter.ai/api/v1/chat/completions"
        self.is_configured = bool(self.api_key)
    
    def is_available(self) -> bool:
        """Check if GPT summarization is available (API key configured)."""
        return self.is_configured
    
    def generate_summary(self, scan_data: Dict[str, Any]) -> Optional[str]:
        """
        Generate AI-powered summary of security scan results.
        
        Args:
            scan_data: Dictionary containing scan results including:
                - domain: Domain name
                - score: Security score (0-100)
                - overall_status: Overall security status
                - recommendations: List of recommendations
                - risk_assessment: Risk assessment details
                - summary: List of summary points
                - protocol_status: Status of all protocols
                - scoring_breakdown: Detailed scoring breakdown
        
        Returns:
            AI-generated summary string or None if unavailable
        """
        if not self.is_available():
            return None
        
        try:
            # Build comprehensive prompt
            prompt = self._build_summarization_prompt(scan_data)
            
            # Prepare headers for OpenRouter API
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json"
            }
            
            # Add optional headers for rankings on openrouter.ai
            if self.site_url:
                headers["HTTP-Referer"] = self.site_url
            if self.site_name:
                headers["X-Title"] = self.site_name
            
            # Prepare request payload
            payload = {
                "model": "openai/gpt-4o-mini",  # Using cost-effective model via OpenRouter
                "messages": [
                    {
                        "role": "system",
                        "content": "You are an expert email security analyst specializing in domain security assessments. Your task is to provide clear, concise, and actionable summaries of security scan results."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                "temperature": 0.7,
                "max_tokens": 500
            }
            
            # Call OpenRouter API
            response = requests.post(
                url=self.api_url,
                headers=headers,
                data=json.dumps(payload),
                timeout=30
            )
            
            # Check for errors
            response.raise_for_status()
            
            # Parse response
            result = response.json()
            
            # Extract the summary from OpenRouter response
            if "choices" in result and len(result["choices"]) > 0:
                return result["choices"][0]["message"]["content"].strip()
            else:
                print(f"Unexpected response format from OpenRouter: {result}")
                return None
            
        except requests.exceptions.RequestException as e:
            print(f"Error generating GPT summary (API request failed): {str(e)}")
            if hasattr(e, 'response') and e.response is not None:
                try:
                    error_detail = e.response.json()
                    print(f"Error details: {error_detail}")
                except:
                    print(f"Error response: {e.response.text}")
            return None
        except Exception as e:
            print(f"Error generating GPT summary: {str(e)}")
            return None
    
    def _build_summarization_prompt(self, scan_data: Dict[str, Any]) -> str:
        """Build a comprehensive prompt for GPT summarization."""
        
        domain = scan_data.get('domain', 'Unknown')
        score = scan_data.get('score', 0)
        overall_status = scan_data.get('overall_status', 'unknown')
        recommendations = scan_data.get('recommendations', [])
        risk_assessment = scan_data.get('risk_assessment', {})
        summary = scan_data.get('summary', [])
        protocol_status = scan_data.get('protocol_status', {})
        scoring_breakdown = scan_data.get('scoring_breakdown', {})
        
        prompt = f"""Analyze the following email security scan results for domain: {domain}

## Security Score: {score}/100
## Overall Status: {overall_status}

## Summary Points:
{self._format_list(summary)}

## Protocol Status:
{self._format_protocol_status(protocol_status)}

## Risk Assessment:
{self._format_risk_assessment(risk_assessment)}

## Recommendations:
{self._format_list(recommendations)}

## Scoring Breakdown:
{self._format_scoring_breakdown(scoring_breakdown)}

---

Please provide a comprehensive, professional summary that:
1. **Executive Summary**: Start with a 2-3 sentence overview of the domain's security posture
2. **Key Findings**: Highlight the most critical security findings (both positive and negative)
3. **Risk Assessment**: Explain the risk level and what it means in practical terms
4. **Priority Actions**: List the top 3-5 most important recommendations in order of priority
5. **Overall Assessment**: Conclude with a brief assessment of the domain's security maturity

Format the response in clear, professional language suitable for both technical and non-technical stakeholders. Focus on actionable insights and prioritize critical security issues."""
        
        return prompt
    
    def _format_list(self, items: List[str]) -> str:
        """Format a list of items for the prompt."""
        if not items:
            return "None"
        return "\n".join(f"- {item}" for item in items if item)
    
    def _format_protocol_status(self, protocol_status: Dict[str, Any]) -> str:
        """Format protocol status for the prompt."""
        if not protocol_status:
            return "No protocol status available"
        
        formatted = []
        for protocol, status in protocol_status.items():
            if isinstance(status, dict):
                exists = status.get('exists', False)
                status_val = status.get('status', 'unknown')
                formatted.append(f"- {protocol.upper()}: {'✓ Configured' if exists else '✗ Missing'} (Status: {status_val})")
            else:
                formatted.append(f"- {protocol.upper()}: {status}")
        
        return "\n".join(formatted) if formatted else "No protocol details available"
    
    def _format_risk_assessment(self, risk_assessment: Dict[str, Any]) -> str:
        """Format risk assessment for the prompt."""
        if not risk_assessment:
            return "No risk assessment available"
        
        level = risk_assessment.get('level', 'unknown')
        severity = risk_assessment.get('severity', 'Unknown')
        description = risk_assessment.get('description', '')
        action_required = risk_assessment.get('action_required', '')
        vulnerabilities = risk_assessment.get('critical_vulnerabilities', [])
        
        formatted = f"""Risk Level: {level} ({severity})
Description: {description}
Action Required: {action_required}"""
        
        if vulnerabilities:
            formatted += f"\nCritical Vulnerabilities:\n{self._format_list(vulnerabilities)}"
        
        return formatted
    
    def _format_scoring_breakdown(self, scoring_breakdown: Dict[str, Any]) -> str:
        """Format scoring breakdown for the prompt."""
        if not scoring_breakdown:
            return "No scoring breakdown available"
        
        formatted = []
        for category, details in scoring_breakdown.items():
            if isinstance(details, dict):
                total = details.get('total_points', 0)
                earned = details.get('earned_points', 0)
                percentage = (earned / total * 100) if total > 0 else 0
                formatted.append(f"- {category.replace('_', ' ').title()}: {earned}/{total} points ({percentage:.1f}%)")
        
        return "\n".join(formatted) if formatted else "No scoring details available"


# Global instance - lazy initialization to avoid errors during import
_gpt_summarizer_instance = None

def get_gpt_summarizer():
    """Get or create the GPT summarizer instance (lazy initialization)."""
    global _gpt_summarizer_instance
    if _gpt_summarizer_instance is None:
        try:
            _gpt_summarizer_instance = GPTSummarizer()
        except Exception as e:
            print(f"Warning: Failed to initialize GPT summarizer: {str(e)}")
            # Return a dummy instance that always returns None
            class DummySummarizer:
                def is_available(self): return False
                def generate_summary(self, scan_data): return None
            _gpt_summarizer_instance = DummySummarizer()
    return _gpt_summarizer_instance

# For backward compatibility, create instance at module level
# but wrap in try-except to handle initialization errors gracefully
try:
    gpt_summarizer = GPTSummarizer()
except Exception as e:
    print(f"Warning: GPT summarizer initialization failed: {str(e)}")
    # Create a dummy instance that always returns None
    class DummySummarizer:
        def is_available(self): return False
        def generate_summary(self, scan_data): return None
    gpt_summarizer = DummySummarizer()

