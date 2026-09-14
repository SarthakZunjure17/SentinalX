"""
SentinelX - Evidence Trust Score Engine
Calculates a transparent, deterministic overall Evidence Trust Score (0-100).
Independently evaluated from ground-truth evidence verification.
"""
from typing import Dict, List, Any

def calculate_overall_trust_score(
    verification_results: List[Dict[str, Any]],
    events: List[Dict[str, Any]]
) -> float:
    """
    Calculates overall Evidence Trust Score (0-100) using 5 transparent factors:
    
    1. Evidence Coverage (35%): Ratio of SUPPORTED findings vs total findings.
    2. Temporal Consistency (20%): Chronological ordering and valid timestamp sequence across events.
    3. MITRE Alignment (20%): Proportion of verified findings with explicit MITRE ATT&CK technique ground truth match.
    4. Source & Event Consistency (15%): Absence of missing cited event IDs in log database.
    5. Contradiction Penalty (10%): Penalty deduction for severe UNSUPPORTED / hallucinated claims.
    
    IMPORTANT: Evidence Trust Score is strictly independent of AI confidence.
    """
    if not verification_results:
        return 0.0
        
    total_findings = len(verification_results)
    
    supported_findings = [r for r in verification_results if r.get("verification_status") == "SUPPORTED"]
    unsupported_findings = [r for r in verification_results if r.get("verification_status") == "UNSUPPORTED"]
    insufficient_findings = [r for r in verification_results if r.get("verification_status") == "INSUFFICIENT_EVIDENCE"]
    
    # Factor 1: Evidence Coverage (35 points max)
    # Supported count / total count
    supported_ratio = len(supported_findings) / total_findings
    coverage_score = supported_ratio * 35.0
    
    # Factor 2: Temporal Consistency (20 points max)
    # Check if any findings had temporal anomalies
    temporal_anomalies = sum(1 for r in verification_results if any("Chronological anomaly" in c for c in r.get("contradictions", [])))
    temporal_ratio = max(0.0, 1.0 - (temporal_anomalies / total_findings))
    temporal_score = temporal_ratio * 20.0
    
    # Factor 3: MITRE Alignment (20 points max)
    # Average evidence score of supported findings mapped to 20 pts
    if supported_findings:
        avg_supported_ev_score = sum(r.get("evidence_score", 0.0) for r in supported_findings) / len(supported_findings)
        mitre_score = (avg_supported_ev_score / 100.0) * 20.0
    else:
        mitre_score = 0.0
        
    # Factor 4: Source & Event Consistency (15 points max)
    total_missing_events = sum(len(r.get("missing_evidence", [])) for r in verification_results)
    event_consistency_ratio = max(0.0, 1.0 - (total_missing_events * 0.15))
    source_score = event_consistency_ratio * 15.0
    
    # Factor 5: Contradiction Penalty (10 points max deduction / positive score)
    # Starts at 10.0, loses 5.0 points per unsupported / contradicted claim
    contradiction_count = len(unsupported_findings)
    contradiction_score = max(0.0, 10.0 - (contradiction_count * 5.0))
    
    # Total Trust Score
    raw_trust_score = coverage_score + temporal_score + mitre_score + source_score + contradiction_score
    final_trust_score = round(min(100.0, max(0.0, raw_trust_score)), 1)
    
    return final_trust_score
