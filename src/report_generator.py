"""
SentinelX - Incident Report Generator
Generates a structured, human-readable Incident Investigation Report.
"""
from typing import Dict, List, Any

STATUS_BADGE_MAP = {
    "SUPPORTED": "🟢 SUPPORTED",
    "UNSUPPORTED": "🔴 UNSUPPORTED",
    "INSUFFICIENT_EVIDENCE": "🟡 INSUFFICIENT EVIDENCE"
}

def generate_incident_report(
    incident_id: str,
    events: List[Dict[str, Any]],
    findings: List[Dict[str, Any]],
    verification_results: List[Dict[str, Any]],
    trust_score: float
) -> Dict[str, Any]:
    """
    Generates structured incident report containing:
    1. Incident Overview
    2. Attack Timeline
    3. Verified Findings
    4. Actionable Defensive Recommendations
    """
    # Map verification results by finding_id
    ver_map = {r["finding_id"]: r for r in verification_results if "finding_id" in r}
    
    # 1. Incident Overview
    highest_severity = "LOW"
    sev_order = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    for e in events:
        s = e.get("severity", "LOW")
        if sev_order.get(s, 1) > sev_order.get(highest_severity, 1):
            highest_severity = s
            
    overview = {
        "incident_id": incident_id,
        "title": "CAM-LDS APT Attack Campaign (SSH Intrusion to Ransomware)",
        "severity": highest_severity,
        "evidence_trust_score": trust_score,
        "total_events": len(events),
        "total_findings": len(findings),
        "supported_findings_count": sum(1 for r in verification_results if r.get("verification_status") == "SUPPORTED"),
        "unsupported_findings_count": sum(1 for r in verification_results if r.get("verification_status") == "UNSUPPORTED"),
        "insufficient_findings_count": sum(1 for r in verification_results if r.get("verification_status") == "INSUFFICIENT_EVIDENCE")
    }
    
    # 2. Attack Timeline (Chronological key events)
    timeline_events = []
    # Filter for unique process/action timeline events
    seen_keys = set()
    for ev in events:
        key = (ev.get("process"), ev.get("action"))
        if key not in seen_keys and ev.get("severity") in ["HIGH", "CRITICAL"]:
            seen_keys.add(key)
            timeline_events.append({
                "timestamp": ev.get("timestamp"),
                "event_id": ev.get("event_id"),
                "process": ev.get("process"),
                "action": ev.get("action"),
                "severity": ev.get("severity"),
                "mitre_technique": ev.get("mitre_technique"),
                "description": ev.get("description")
            })
            
    # 3. Verified Findings List
    report_findings = []
    recommendations = []
    
    for f in findings:
        fid = f["finding_id"]
        v_res = ver_map.get(fid, {})
        status = v_res.get("verification_status", "INSUFFICIENT_EVIDENCE")
        badge = STATUS_BADGE_MAP.get(status, status)
        
        report_findings.append({
            "finding_id": fid,
            "title": f.get("title"),
            "description": f.get("description"),
            "attack_stage": f.get("attack_stage"),
            "mitre_technique": f.get("mitre_technique"),
            "ai_confidence": f.get("ai_confidence", 0.0),
            "ai_confidence_pct": f"{round(f.get('ai_confidence', 0.0) * 100.0, 1)}%",
            "verification_status": status,
            "status_badge": badge,
            "evidence_score": v_res.get("evidence_score", 0.0),
            "evidence_score_pct": f"{v_res.get('evidence_score', 0.0)}%",
            "supporting_events": v_res.get("supporting_event_ids", []),
            "missing_evidence": v_res.get("missing_evidence", []),
            "contradictions": v_res.get("contradictions", []),
            "explanation": v_res.get("verification_explanation", "")
        })
        
        if f.get("recommendation") and status == "SUPPORTED":
            recommendations.append({
                "finding_id": fid,
                "title": f.get("title"),
                "recommendation": f.get("recommendation")
            })
            
    return {
        "overview": overview,
        "timeline": timeline_events,
        "findings": report_findings,
        "recommendations": recommendations
    }
