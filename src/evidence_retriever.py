"""
SentinelX - Evidence Retrieval Node
Retrieves exact log events cited by AI findings and identifies missing evidence.
"""
from typing import Dict, List, Any

def retrieve_evidence_for_findings(
    findings: List[Dict[str, Any]], 
    events: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """
    For every finding:
    1. Reads cited event IDs (supporting_event_ids).
    2. Retrieves matching normalized security events.
    3. Identifies missing event IDs.
    """
    event_map = {e["event_id"]: e for e in events if "event_id" in e}
    evidence_results = []
    
    for finding in findings:
        finding_id = finding.get("finding_id")
        cited_ids = finding.get("supporting_event_ids", [])
        
        retrieved_events = []
        missing_ids = []
        
        for eid in cited_ids:
            if eid in event_map:
                retrieved_events.append(event_map[eid])
            else:
                missing_ids.append(eid)
                
        evidence_results.append({
            "finding_id": finding_id,
            "cited_event_ids": cited_ids,
            "retrieved_events": retrieved_events,
            "missing_event_ids": missing_ids,
            "evidence_count": len(retrieved_events)
        })
        
    return evidence_results
