import os
import json
import logging
from typing import Dict, List, Any, Optional
from dotenv import load_dotenv

# Explicitly load .env file from project root
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
load_dotenv(dotenv_path=os.path.join(ROOT_DIR, ".env"), override=True)

from src.data_loader import load_evaluation_cases

INVESTIGATOR_SYSTEM_PROMPT = """
You are SentinelX Lead Cyber Incident Investigator.
Your task is to analyze the provided normalized security log events and synthesize structured investigation findings.

STRICT INSTRUCTIONS:
1. Analyze the provided events chronologically.
2. Identify distinct attack stages (e.g. Initial Access, Privilege Escalation, Credential Access, Persistence, Lateral Movement, Impact, Exfiltration).
3. Map each finding to the most relevant MITRE ATT&CK technique (e.g. T1110.001, T1078.003, T1053.003, T1486).
4. CITE EXACT EVENT IDs (e.g. ["EVT-1001", "EVT-1002"]) from the input data that support your finding.
5. NEVER INVENT EVENT IDs or fake log evidence. ONLY cite event IDs present in the input dataset.
6. Clearly distinguish observed log evidence from inference.
7. Assign an AI confidence score between 0.50 and 0.99 reflecting your confidence in the finding.
8. Provide actionable defensive recommendations.
9. Do NOT assign verification status (such as SUPPORTED or UNSUPPORTED). The verification status will be determined independently by an automated verifier.

OUTPUT FORMAT:
Return ONLY a valid JSON array of finding objects. Do not include markdown code blocks or conversational text.
Each finding object MUST contain:
- finding_id: String (e.g. "FINDING-AI-001")
- title: Short descriptive finding title
- description: Detailed finding description
- attack_stage: Attack stage string
- mitre_technique: MITRE ATT&CK technique code (e.g. "T1110.001")
- ai_confidence: Float (0.50 to 0.99)
- supporting_event_ids: List of string event IDs (e.g. ["EVT-1001", "EVT-1002"])
- recommendation: Defensive recommendation string
"""

import copy

# Module-level cache for Gemini responses to avoid duplicate API calls
_GEMINI_CACHE: Dict[str, List[Dict[str, Any]]] = {}

def clear_gemini_cache() -> None:
    """Clears the in-memory Gemini response cache."""
    _GEMINI_CACHE.clear()

def get_gemini_api_key() -> Optional[str]:
    """
    Safely retrieves GEMINI_API_KEY from environment or Streamlit secrets.
    Does not log, print, or expose the key.
    """
    # 1. Check environment variables (.env loaded)
    api_key = os.getenv("GEMINI_API_KEY")
    if api_key and api_key.strip() and api_key.strip() != "your_gemini_api_key_here":
        return api_key.strip()

    # 2. Check Streamlit secrets (for Streamlit Community Cloud deployment)
    try:
        import streamlit as st
        if hasattr(st, "secrets") and "GEMINI_API_KEY" in st.secrets:
            s_key = str(st.secrets["GEMINI_API_KEY"]).strip()
            if s_key and s_key != "your_gemini_api_key_here":
                return s_key
    except Exception:
        pass

    return None

def is_gemini_available() -> bool:
    """Checks whether GEMINI_API_KEY is available and configured (via env or Streamlit secrets)."""
    return get_gemini_api_key() is not None

def run_ai_investigation_gemini(events: List[Dict[str, Any]], force_refresh: bool = False) -> List[Dict[str, Any]]:
    """
    Executes live AI investigation using Gemini API via google-genai SDK.
    Strictly receives normalized security events and returns fresh AI findings.
    Does NOT load or access evaluation_cases.json.
    Caches responses to prevent redundant API calls on identical inputs.
    """
    cache_key = f"evt_len_{len(events)}_" + (events[0].get("event_id", "") if events else "")
    if not force_refresh and cache_key in _GEMINI_CACHE:
        return copy.deepcopy(_GEMINI_CACHE[cache_key])

    api_key = get_gemini_api_key()
    if not api_key:
        raise ValueError(
            "GEMINI_API_KEY is missing or unconfigured. "
            "Please configure GEMINI_API_KEY in Streamlit Secrets or your local .env file."
        )

    try:
        from google import genai
        client = genai.Client(api_key=api_key)

        # Prepare compact event summary for LLM prompt
        event_summaries = []
        for e in events[:35]:  # Event stream summary
            event_summaries.append({
                "event_id": e.get("event_id"),
                "timestamp": e.get("timestamp"),
                "event_type": e.get("event_type"),
                "process": e.get("process"),
                "action": e.get("action"),
                "severity": e.get("severity"),
                "mitre_technique": e.get("mitre_technique"),
                "description": e.get("description")
            })

        user_prompt = f"Analyze these normalized security log events and synthesize structured investigation findings:\n{json.dumps(event_summaries, indent=2)}"

        # Active Gemini models supported by current Google GenAI API
        model_names = ['gemini-2.5-flash', 'gemini-3-flash-preview', 'gemini-flash-latest']
        response_text = None
        last_err = None

        for m_name in model_names:
            try:
                response = client.models.generate_content(
                    model=m_name,
                    contents=user_prompt,
                    config={
                        'temperature': 0.1,
                        'system_instruction': INVESTIGATOR_SYSTEM_PROMPT,
                        'response_mime_type': 'application/json'
                    }
                )
                if response and response.text:
                    response_text = response.text.strip()
                    break
            except Exception as ex:
                last_err = ex
                continue

        if not response_text:
            raise RuntimeError(f"Gemini API call failed: {last_err}")

        # Clean code block backticks if present
        if response_text.startswith("```json"):
            response_text = response_text[7:]
        if response_text.startswith("```"):
            response_text = response_text[3:]
        if response_text.endswith("```"):
            response_text = response_text[:-3]

        parsed_findings = json.loads(response_text.strip())

        if isinstance(parsed_findings, list) and len(parsed_findings) > 0:
            validated = []
            for idx, f in enumerate(parsed_findings):
                validated.append({
                    "finding_id": f.get("finding_id", f"FINDING-AI-{idx+1:03d}"),
                    "title": f.get("title", f"AI Finding {idx+1}"),
                    "description": f.get("description", "AI-generated incident finding."),
                    "attack_stage": f.get("attack_stage", "Unspecified Stage"),
                    "mitre_technique": f.get("mitre_technique", "T1059"),
                    "ai_confidence": float(f.get("ai_confidence", 0.90)),
                    "supporting_event_ids": f.get("supporting_event_ids", []),
                    "recommendation": f.get("recommendation", "Audit system access logs.")
                })
            _GEMINI_CACHE[cache_key] = validated
            return validated

    except Exception as e:
        logging.error(f"Gemini API investigation failed: {e}")
        raise e

    raise ValueError("Gemini API returned invalid or empty response structure.")

def run_investigation(events: List[Dict[str, Any]], mode: str = "controlled_demo", force_refresh: bool = False) -> List[Dict[str, Any]]:
    """
    Receives normalized security events and produces structured investigation findings.

    Args:
        events: List of normalized event dictionaries.
        mode: "controlled_demo" / "demo" (Benchmark cases) or "live_ai" / "ai" (Gemini LLM)
        force_refresh: If True, bypasses cache in live AI mode.
    """
    if mode in ["ai", "live_ai"]:
        # STRICT RULE: Must NEVER load evaluation_cases.json when in live_ai mode
        return run_ai_investigation_gemini(events, force_refresh=force_refresh)

    # Controlled Verification Demo Mode ONLY (investigation_mode == "controlled_demo" or "demo")
    cases = load_evaluation_cases()
    findings = []
    for c in cases:
        findings.append({
            "finding_id": c.get("finding_id"),
            "title": c.get("title"),
            "description": c.get("description"),
            "attack_stage": c.get("attack_stage"),
            "mitre_technique": c.get("mitre_technique"),
            "ai_confidence": c.get("ai_confidence", 0.90),
            "supporting_event_ids": c.get("supporting_event_ids", []),
            "recommendation": c.get("recommendation", "Audit system access logs.")
        })

    return findings

