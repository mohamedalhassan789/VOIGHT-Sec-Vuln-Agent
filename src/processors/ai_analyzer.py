"""
AI Vulnerability Analyzer
Multi-provider AI analysis for vulnerability assessment and recommendations
Supports: Anthropic Claude, OpenAI GPT, Google Gemini, Ollama (local)
"""

import logging
from typing import Dict, Optional
import json

logger = logging.getLogger(__name__)


class AIAnalyzer:
    """
    Multi-provider AI analyzer for vulnerability intelligence.
    Supports Anthropic, OpenAI, Google, and Ollama.
    """

    def __init__(self, config: Dict, secrets_manager):
        """
        Initialize AI analyzer with configuration and secrets manager.

        Args:
            config: AI configuration dictionary
            secrets_manager: SecretsManager instance for API keys
        """
        self.config = config
        self.secrets = secrets_manager
        self.provider = config.get('provider', 'none').lower()
        self.enabled = config.get('enabled', False)

        self.client = None

        if self.enabled and self.provider != 'none':
            self._initialize_provider()

    def _initialize_provider(self):
        """Initialize the selected AI provider."""
        try:
            if self.provider == 'anthropic':
                self._init_anthropic()
            elif self.provider == 'openai':
                self._init_openai()
            elif self.provider == 'google':
                self._init_google()
            elif self.provider == 'ollama':
                self._init_ollama()
            else:
                logger.warning(f"Unknown AI provider: {self.provider}")
                self.enabled = False

        except Exception as e:
            logger.error(f"Failed to initialize AI provider {self.provider}: {e}")
            self.enabled = False

    def _init_anthropic(self):
        """Initialize Anthropic Claude."""
        try:
            import anthropic

            api_key = self.secrets.get_provider_key('anthropic')
            if not api_key:
                raise ValueError("Anthropic API key not found")

            self.client = anthropic.Anthropic(api_key=api_key)
            self.model = self.config.get('anthropic', {}).get('model', 'claude-sonnet-4-5')
            logger.info(f"Initialized Anthropic Claude with model: {self.model}")

        except ImportError:
            logger.error("anthropic library not installed. Run: pip install anthropic")
            raise
        except Exception as e:
            logger.error(f"Failed to initialize Anthropic: {e}")
            raise

    def _init_openai(self):
        """Initialize OpenAI GPT."""
        try:
            import openai

            api_key = self.secrets.get_provider_key('openai')
            if not api_key:
                raise ValueError("OpenAI API key not found")

            self.client = openai.OpenAI(api_key=api_key)
            self.model = self.config.get('openai', {}).get('model', 'gpt-4o-mini')
            logger.info(f"Initialized OpenAI GPT with model: {self.model}")

        except ImportError:
            logger.error("openai library not installed. Run: pip install openai")
            raise
        except Exception as e:
            logger.error(f"Failed to initialize OpenAI: {e}")
            raise

    def _init_google(self):
        """Initialize Google Gemini."""
        try:
            import google.generativeai as genai

            api_key = self.secrets.get_provider_key('google')
            if not api_key:
                raise ValueError("Google API key not found")

            genai.configure(api_key=api_key)
            self.model_name = self.config.get('google', {}).get('model', 'gemini-2.0-flash-exp')
            self.client = genai.GenerativeModel(self.model_name)
            logger.info(f"Initialized Google Gemini with model: {self.model_name}")

        except ImportError:
            logger.error("google-generativeai library not installed. Run: pip install google-generativeai")
            raise
        except Exception as e:
            logger.error(f"Failed to initialize Google Gemini: {e}")
            raise

    def _init_ollama(self):
        """Initialize Ollama (local LLM)."""
        try:
            import requests

            self.base_url = self.config.get('ollama', {}).get('base_url', 'http://localhost:11434')
            self.model = self.config.get('ollama', {}).get('model', 'llama3.2')

            # Test connection
            response = requests.get(f"{self.base_url}/api/tags", timeout=5)
            response.raise_for_status()

            self.client = requests  # Store requests module for later use
            logger.info(f"Initialized Ollama with model: {self.model} at {self.base_url}")

        except Exception as e:
            logger.error(f"Failed to connect to Ollama: {e}")
            logger.info("Make sure Ollama is running: https://ollama.com/")
            raise

    def analyze_vulnerability(self, cve_data: Dict) -> Optional[Dict]:
        """
        Analyze a vulnerability using AI.

        Args:
            cve_data: Dictionary containing CVE information

        Returns:
            Dict: AI analysis results with recommendations
        """
        if not self.enabled:
            logger.debug("AI analysis disabled")
            return None

        try:
            # Create analysis prompt
            prompt = self._create_analysis_prompt(cve_data)

            # Call appropriate provider
            if self.provider == 'anthropic':
                return self._analyze_anthropic(prompt)
            elif self.provider == 'openai':
                return self._analyze_openai(prompt)
            elif self.provider == 'google':
                return self._analyze_google(prompt)
            elif self.provider == 'ollama':
                return self._analyze_ollama(prompt)

        except Exception as e:
            logger.error(f"AI analysis failed: {e}")
            return None

    def query_ai(self, prompt: str) -> Optional[str]:
        """
        General purpose AI query for custom prompts (e.g., remediation steps).

        Args:
            prompt: The question/prompt to send to AI

        Returns:
            str: AI response text
        """
        if not self.enabled:
            logger.debug("AI analysis disabled")
            return None

        try:
            # Call appropriate provider and return raw text
            if self.provider == 'anthropic':
                response = self.client.messages.create(
                    model=self.model,
                    max_tokens=2048,
                    messages=[{"role": "user", "content": prompt}]
                )
                return response.content[0].text

            elif self.provider == 'openai':
                response = self.client.chat.completions.create(
                    model=self.model,
                    messages=[
                        {"role": "system", "content": "You are a cybersecurity expert providing remediation guidance."},
                        {"role": "user", "content": prompt}
                    ],
                    max_tokens=2048,
                    temperature=0.3
                )
                return response.choices[0].message.content

            elif self.provider == 'google':
                response = self.client.generate_content(prompt)
                return response.text

            elif self.provider == 'ollama':
                payload = {
                    "model": self.model,
                    "prompt": prompt,
                    "stream": False
                }
                response = self.client.post(
                    f"{self.base_url}/api/generate",
                    json=payload,
                    timeout=60
                )
                response.raise_for_status()
                return response.json().get('response', '')

        except Exception as e:
            logger.error(f"AI query failed: {e}")
            return None

    def _create_analysis_prompt(self, cve_data: Dict) -> str:
        """
        Create a structured prompt for AI analysis.

        Args:
            cve_data: CVE data dictionary

        Returns:
            str: Formatted prompt
        """
        prompt = f"""Analyze this security vulnerability and provide actionable intelligence:

CVE ID: {cve_data.get('cve_id', 'Unknown')}
CVSS Score: {cve_data.get('cvss_score', 'N/A')}
Severity: {cve_data.get('severity', 'Unknown')}
Description: {cve_data.get('description', 'No description')}

Exploit Available: {cve_data.get('exploit_available', False)}
CISA KEV: {cve_data.get('in_cisa_kev', False)}

Please provide:
1. **Risk Assessment**: Brief analysis of the threat level and exploitability
2. **Impact**: What systems/data could be affected
3. **Recommended Actions**: Specific mitigation steps (prioritized)
4. **Urgency**: How quickly should this be addressed (Immediate/High/Medium/Low)

Keep the response concise and actionable for an IT security team.
Format the response as JSON with keys: risk_assessment, impact, recommended_actions (array), urgency
"""
        return prompt

    def _analyze_anthropic(self, prompt: str) -> Dict:
        """Analyze using Anthropic Claude."""
        try:
            response = self.client.messages.create(
                model=self.model,
                max_tokens=1024,
                messages=[
                    {"role": "user", "content": prompt}
                ]
            )

            content = response.content[0].text
            return self._parse_ai_response(content)

        except Exception as e:
            logger.error(f"Anthropic API error: {e}")
            raise

    def _analyze_openai(self, prompt: str) -> Dict:
        """Analyze using OpenAI GPT."""
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a cybersecurity expert analyzing vulnerabilities."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=1024,
                temperature=0.3
            )

            content = response.choices[0].message.content
            return self._parse_ai_response(content)

        except Exception as e:
            logger.error(f"OpenAI API error: {e}")
            raise

    def _analyze_google(self, prompt: str) -> Dict:
        """Analyze using Google Gemini."""
        try:
            response = self.client.generate_content(prompt)
            content = response.text
            return self._parse_ai_response(content)

        except Exception as e:
            logger.error(f"Google Gemini API error: {e}")
            raise

    def _analyze_ollama(self, prompt: str) -> Dict:
        """Analyze using Ollama (local LLM)."""
        try:
            payload = {
                "model": self.model,
                "prompt": prompt,
                "stream": False
            }

            response = self.client.post(
                f"{self.base_url}/api/generate",
                json=payload,
                timeout=60
            )
            response.raise_for_status()

            content = response.json().get('response', '')
            return self._parse_ai_response(content)

        except Exception as e:
            logger.error(f"Ollama API error: {e}")
            raise

    def _parse_ai_response(self, content: str) -> Dict:
        """
        Parse AI response into structured format.

        Args:
            content: Raw AI response text

        Returns:
            Dict: Parsed analysis results
        """
        # Try to parse as JSON first
        try:
            # Look for JSON in the response
            if '{' in content and '}' in content:
                json_start = content.find('{')
                json_end = content.rfind('}') + 1
                json_str = content[json_start:json_end]
                return json.loads(json_str)
        except json.JSONDecodeError:
            pass

        # If not JSON, structure the response manually
        return {
            "risk_assessment": self._extract_section(content, "risk"),
            "impact": self._extract_section(content, "impact"),
            "recommended_actions": self._extract_actions(content),
            "urgency": self._extract_urgency(content),
            "raw_analysis": content
        }

    def _extract_section(self, content: str, section_name: str) -> str:
        """Extract a specific section from the AI response."""
        content_lower = content.lower()
        section_lower = section_name.lower()

        if section_lower in content_lower:
            start_idx = content_lower.find(section_lower)
            # Find the next section or end
            next_sections = ['recommended', 'urgency', 'impact', 'actions']
            end_idx = len(content)

            for next_section in next_sections:
                if next_section in content_lower[start_idx + 50:]:
                    potential_end = content_lower.find(next_section, start_idx + 50)
                    if potential_end > start_idx:
                        end_idx = min(end_idx, potential_end)

            return content[start_idx:end_idx].strip()

        return "No specific assessment provided"

    def _extract_actions(self, content: str) -> list:
        """Extract recommended actions from the response."""
        actions = []
        lines = content.split('\n')

        for line in lines:
            line = line.strip()
            # Look for numbered lists or bullet points
            if line and (line[0].isdigit() or line.startswith('-') or line.startswith('*')):
                # Clean up the line
                action = line.lstrip('0123456789.-* ').strip()
                if action and len(action) > 10:  # Filter out very short lines
                    actions.append(action)

        return actions[:5] if actions else ["Review vendor security advisories", "Apply available patches"]

    def _extract_urgency(self, content: str) -> str:
        """Extract urgency level from the response."""
        content_lower = content.lower()

        if any(word in content_lower for word in ['immediate', 'critical', 'urgent', 'asap']):
            return 'Immediate'
        elif any(word in content_lower for word in ['high', 'soon', 'priority']):
            return 'High'
        elif any(word in content_lower for word in ['medium', 'moderate']):
            return 'Medium'
        else:
            return 'Low'

    def test_connection(self) -> bool:
        """
        Test AI provider connection.

        Returns:
            bool: True if connection successful
        """
        if not self.enabled:
            return False

        try:
            test_cve = {
                'cve_id': 'CVE-TEST',
                'cvss_score': 7.5,
                'severity': 'HIGH',
                'description': 'Test vulnerability',
                'exploit_available': False,
                'in_cisa_kev': False
            }

            result = self.analyze_vulnerability(test_cve)
            return result is not None

        except Exception as e:
            logger.error(f"AI provider test failed: {e}")
            return False


# Example usage
if __name__ == "__main__":
    from utils.logger import setup_logger
    from utils.secrets_manager import SecretsManager

    logger = setup_logger(log_level="DEBUG")

    # Example configuration
    config = {
        'enabled': False,
        'provider': 'ollama',
        'ollama': {
            'base_url': 'http://localhost:11434',
            'model': 'llama3.2'
        }
    }

    secrets = SecretsManager()
    analyzer = AIAnalyzer(config, secrets)

    if analyzer.enabled:
        test_cve = {
            'cve_id': 'CVE-2024-1234',
            'cvss_score': 9.8,
            'severity': 'CRITICAL',
            'description': 'Remote code execution vulnerability',
            'exploit_available': True,
            'in_cisa_kev': True
        }

        result = analyzer.analyze_vulnerability(test_cve)
        print("\nAI Analysis Result:")
        print(json.dumps(result, indent=2))
    else:
        print("AI analysis is disabled")
