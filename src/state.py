"""
SentinelX - LangGraph State Definition
"""
from typing import Dict, List, Any, Optional
from typing_extensions import TypedDict

class SentinelState(TypedDict, total=False):
    """
    Typed state object for SentinelX LangGraph workflow.
    """
    incident_id: str
    investigation_mode: str
    events: List[Dict[str, Any]]
    findings: List[Dict[str, Any]]
    evidence_results: List[Dict[str, Any]]
    verification_results: List[Dict[str, Any]]
    trust_score: float
    report: Dict[str, Any]
    evaluation_summary: Dict[str, Any]

