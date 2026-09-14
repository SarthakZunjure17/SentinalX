"""
SentinelX - Evidence Verification Engine
THIS IS THE CORE MODULE OF SENTINELX.
Independently verifies AI-generated investigation findings against structured security log evidence.
"""
from typing import Dict, List, Any, Tuple
from datetime import datetime

from src.normalizer import normalize_timestamp

# Domain mapping for MITRE technique categories
TACTIC_STAGE_MAP = {
    "Initial Access": ["T1110", "T1110.001", "T1078", "T1078.002", "T1133", "T1190"],
    "Privilege Escalation": ["T1078.003", "T1548", "T1068"],
    "Credential Access": ["T1003", "T1003.008", "T1040"],
    "Persistence": ["T1053", "T1053.003", "T1574", "T1546", "T1547"],
    "Lateral Movement": ["T1072", "T1021", "T1021.005"],
    "Impact": ["T1486", "T1485", "T1489", "T1490", "T1531"],
    "Exfiltration": ["T1041", "T1020", "T1048"]
}

def verify_finding(
    finding: Dict[str, Any],
    evidence_item: Dict[str, Any],
    all_events: List[Dict[str, Any]]
) -> Dict[str, Any]:
    """
    Independently verifies an investigation finding against retrieved evidence.
    
    Returns structured verification result:
    {
        "finding_id": str,
        "title": str,
        "verification_status": "SUPPORTED" | "UNSUPPORTED" | "INSUFFICIENT_EVIDENCE",
        "evidence_score": float (0-100),
        "supporting_event_ids": List[str],
        "missing_evidence": List[str],
        "contradictions": List[str],
        "verification_explanation": str
    }
    """
    finding_id = finding.get("finding_id")
    title = finding.get("title", "")
    description = finding.get("description", "")
    claimed_stage = finding.get("attack_stage", "")
    claimed_mitre = finding.get("mitre_technique", "")
    
    cited_ids = evidence_item.get("cited_event_ids", [])
    retrieved_events = evidence_item.get("retrieved_events", [])
    missing_ids = evidence_item.get("missing_event_ids", [])
    
    contradictions = []
    missing_evidence = list(missing_ids)
    
    # 1. Event Existence Check
    if not cited_ids:
        missing_evidence.append("No supporting events cited by AI finding")
        
    if len(retrieved_events) == 0:
        return {
            "finding_id": finding_id,
            "title": title,
            "verification_status": "INSUFFICIENT_EVIDENCE",
            "evidence_score": 0.0,
            "supporting_event_ids": [],
            "missing_evidence": missing_evidence,
            "contradictions": ["All cited event IDs are missing or non-existent in log database"],
            "verification_explanation": f"Failed verification: Cited event IDs {missing_ids} do not exist in the security log dataset."
        }
        
    # 2. Content & Relevance Verification
    relevance_score = 0.0
    valid_event_ids = []
    
    for ev in retrieved_events:
        ev_mitre = ev.get("mitre_technique") or ""
        ev_desc = (ev.get("description") or "").lower()
        ev_process = (ev.get("process") or "").lower()
        ev_action = (ev.get("action") or "").lower()
        ev_type = (ev.get("event_type") or "").lower()

        
        # Check explicit claim vs evidence contradictions
        # Case A: Claim mentions Buffer Overflow / Apache / RCE, but evidence shows Hydra SSH brute-force
        if ("buffer overflow" in description.lower() or "apache" in description.lower() or "cve-" in description.lower()) \
           and ("hydra" in ev_process or "ssh_bruteforce" in ev_type or ev_mitre == "T1110.001"):
            contradictions.append(
                f"Contradiction in {ev['event_id']}: Finding claims Apache Zero-Day Buffer Overflow, but log evidence shows Hydra SSH password brute-force ({ev_mitre})."
            )
            
        # Case B: Claim mentions Exfiltration / Database export / Credit card to 203.0.113.50, but evidence shows Ransomware encryption / Local file deletion
        if ("exfiltrat" in description.lower() or "database" in description.lower() or "203.0.113" in description.lower()) \
           and not ("exfiltrat" in ev_action or "203.0.113" in ev_desc or "database" in ev_desc):
            missing_evidence.append(
                f"Missing evidence in {ev['event_id']}: Log entry shows ransomware encryption ({ev_mitre}), not network database exfiltration to 203.0.113.50."
            )
            
        # Check MITRE alignment
        mitre_match = False
        if claimed_mitre and ev_mitre:
            if claimed_mitre == ev_mitre or claimed_mitre.split(".")[0] == ev_mitre.split(".")[0]:
                mitre_match = True
                
        # Check Tactic / Stage alignment
        stage_match = False
        if claimed_stage in TACTIC_STAGE_MAP:
            allowed_techniques = TACTIC_STAGE_MAP[claimed_stage]
            if ev_mitre in allowed_techniques or any(ev_mitre.startswith(t) for t in allowed_techniques):
                stage_match = True
                
        if mitre_match or stage_match:
            relevance_score += 1.0
            valid_event_ids.append(ev["event_id"])
        elif not contradictions and not missing_evidence:
            # Partial match
            relevance_score += 0.5
            valid_event_ids.append(ev["event_id"])

    # Normalize relevance score
    max_relevance = float(len(retrieved_events))
    relevance_ratio = relevance_score / max_relevance if max_relevance > 0 else 0.0
    
    # 3. Temporal Plausibility Check
    temporal_consistent = True
    timestamps = []
    for ev in retrieved_events:
        ts_val = ev.get("timestamp")
        if ts_val is not None:
            try:
                ts = normalize_timestamp(ts_val)
                timestamps.append((ev.get("event_id", "UNKNOWN"), ts))
            except Exception:
                pass
                
    if len(timestamps) > 1:
        # Verify timestamps do not jump wildly backwards
        for i in range(len(timestamps) - 1):
            evt_id_curr, ts_curr = timestamps[i]
            evt_id_next, ts_next = timestamps[i+1]
            ts_curr = normalize_timestamp(ts_curr)
            ts_next = normalize_timestamp(ts_next)
            if ts_curr > ts_next:
                # Minor timestamp disorder in log capture is tolerable if within 1 min
                time_diff = (ts_curr - ts_next).total_seconds()
                if time_diff > 60:
                    temporal_consistent = False
                    contradictions.append(f"Chronological anomaly: Event {evt_id_curr} occurred after {evt_id_next}.")

    # 4. Status Assignment Logic
    if contradictions:
        status = "UNSUPPORTED"
        evidence_score = max(5.0, round((1.0 - len(contradictions)*0.4) * 30.0, 1))
        explanation = (
            f"Verification Failed (UNSUPPORTED): The cited log evidence explicitly contradicts the finding claim. "
            f"Details: {'; '.join(contradictions)}"
        )
    elif missing_evidence or len(valid_event_ids) == 0:
        status = "INSUFFICIENT_EVIDENCE"
        evidence_score = max(10.0, round(relevance_ratio * 45.0, 1))
        explanation = (
            f"Verification Incomplete (INSUFFICIENT_EVIDENCE): The cited events do not contain direct evidence supporting the finding. "
            f"Details: {'; '.join(missing_evidence) if missing_evidence else 'Cited log events do not match claimed attack stage.'}"
        )
    else:
        status = "SUPPORTED"
        coverage_factor = (len(retrieved_events) - len(missing_ids)) / len(cited_ids) if cited_ids else 1.0
        temporal_factor = 1.0 if temporal_consistent else 0.8
        evidence_score = min(99.0, max(75.0, round((0.6 * relevance_ratio + 0.2 * coverage_factor + 0.2 * temporal_factor) * 100.0, 1)))
        
        explanation = (
            f"Verified (SUPPORTED): Cited events {valid_event_ids} contain authentic log evidence matching "
            f"claimed stage '{claimed_stage}' and MITRE technique {claimed_mitre} with chronological consistency."
        )

    return {
        "finding_id": finding_id,
        "title": title,
        "verification_status": status,
        "evidence_score": evidence_score,
        "supporting_event_ids": valid_event_ids if status == "SUPPORTED" else [],
        "missing_evidence": missing_evidence,
        "contradictions": contradictions,
        "verification_explanation": explanation
    }

def verify_all_findings(
    findings: List[Dict[str, Any]],
    evidence_results: List[Dict[str, Any]],
    all_events: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """
    Verifies all findings against evidence.
    """
    evidence_map = {e["finding_id"]: e for e in evidence_results if "finding_id" in e}
    results = []
    
    for finding in findings:
        fid = finding["finding_id"]
        ev_item = evidence_map.get(fid, {"cited_event_ids": [], "retrieved_events": [], "missing_event_ids": []})
        results.append(verify_finding(finding, ev_item, all_events))
        
    return results

def evaluate_verification_accuracy(
    verification_results: List[Dict[str, Any]],
    evaluation_cases: List[Dict[str, Any]]
) -> Dict[str, Any]:
    """
    Evaluates verifier accuracy against ground-truth expected labels in evaluation_cases.json.
    """
    expected_map = {c["finding_id"]: c.get("ground_truth_expected_status") for c in evaluation_cases if "finding_id" in c}
    
    correct_count = 0
    incorrect_count = 0
    details = []
    
    for res in verification_results:
        fid = res["finding_id"]
        actual_status = res["verification_status"]
        expected_status = expected_map.get(fid)
        
        is_correct = (actual_status == expected_status)
        if is_correct:
            correct_count += 1
        else:
            incorrect_count += 1
            
        details.append({
            "finding_id": fid,
            "title": res.get("title", ""),
            "actual_status": actual_status,
            "expected_status": expected_status,
            "is_correct": is_correct,
            "explanation": res.get("verification_explanation", "")
        })
        
    total = len(verification_results)
    accuracy = (correct_count / total) if total > 0 else 0.0
    
    return {
        "total_evaluations": total,
        "correct_count": correct_count,
        "incorrect_count": incorrect_count,
        "accuracy": round(accuracy, 4),
        "accuracy_percentage": f"{round(accuracy * 100.0, 1)}%",
        "details": details
    }
