"""
SentinelX - Comprehensive Unit & Pipeline Test Suite
Tests evidence verification engine, trust score, and LangGraph workflow.
"""
import os
import sys
try:
    import pytest
except ImportError:
    pytest = None


# Ensure root is in python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.data_loader import load_demo_incident, load_evaluation_cases
from src.normalizer import normalize_incident_events
from src.evidence_retriever import retrieve_evidence_for_findings
from src.verifier import verify_finding, verify_all_findings, evaluate_verification_accuracy
from src.trust_score import calculate_overall_trust_score
from src.graph import run_investigation_pipeline, build_sentinelx_graph

def get_test_data():
    incident = load_demo_incident()
    events = normalize_incident_events(incident["events"])
    eval_cases = load_evaluation_cases()
    return events, eval_cases

def test_1_supported_finding_verification():
    events, eval_cases = get_test_data()
    supported_case = [c for c in eval_cases if c["finding_id"] == "FINDING-001"][0]
    
    evidence_res = retrieve_evidence_for_findings([supported_case], events)
    verification = verify_finding(supported_case, evidence_res[0], events)
    
    assert verification["verification_status"] == "SUPPORTED", f"Expected SUPPORTED, got {verification['verification_status']}"
    assert verification["evidence_score"] >= 75.0, "Expected evidence score >= 75 for supported finding"
    assert len(verification["supporting_event_ids"]) > 0

def test_2_unsupported_hallucinated_claim_verification():
    events, eval_cases = get_test_data()
    unsupported_case = [c for c in eval_cases if c["finding_id"] == "FINDING-005"][0]
    
    evidence_res = retrieve_evidence_for_findings([unsupported_case], events)
    verification = verify_finding(unsupported_case, evidence_res[0], events)
    
    assert verification["verification_status"] == "UNSUPPORTED", f"Expected UNSUPPORTED, got {verification['verification_status']}"
    assert len(verification["contradictions"]) > 0, "Expected explicit contradictions to be recorded"
    assert verification["evidence_score"] <= 30.0

def test_3_insufficient_evidence_claim_verification():
    events, eval_cases = get_test_data()
    insufficient_case = [c for c in eval_cases if c["finding_id"] == "FINDING-006"][0]
    
    evidence_res = retrieve_evidence_for_findings([insufficient_case], events)
    verification = verify_finding(insufficient_case, evidence_res[0], events)
    
    assert verification["verification_status"] == "INSUFFICIENT_EVIDENCE", f"Expected INSUFFICIENT_EVIDENCE, got {verification['verification_status']}"
    assert len(verification["missing_evidence"]) > 0, "Expected missing evidence items to be recorded"

def test_4_missing_event_id_handling():
    events, _ = get_test_data()
    fake_case = {
        "finding_id": "FINDING-999",
        "title": "Non-existent event claim",
        "description": "Claims event that does not exist in database.",
        "attack_stage": "Initial Access",
        "mitre_technique": "T1110.001",
        "supporting_event_ids": ["EVT-99999", "EVT-88888"]
    }
    
    evidence_res = retrieve_evidence_for_findings([fake_case], events)
    verification = verify_finding(fake_case, evidence_res[0], events)
    
    assert verification["verification_status"] == "INSUFFICIENT_EVIDENCE"
    assert "EVT-99999" in evidence_res[0]["missing_event_ids"]
    assert "EVT-88888" in evidence_res[0]["missing_event_ids"]

def test_5_temporal_inconsistency_handling():
    events, _ = get_test_data()
    # Out of order events
    out_of_order_events = [
        {"event_id": "EVT-T1", "timestamp": "2025-12-12T12:00:00.000000", "mitre_technique": "T1110.001", "description": "Later event"},
        {"event_id": "EVT-T2", "timestamp": "2025-12-12T10:00:00.000000", "mitre_technique": "T1110.001", "description": "Earlier event"}
    ]
    fake_case = {
        "finding_id": "FINDING-TEMPORAL",
        "title": "Temporal anomaly claim",
        "description": "Claims sequence of out-of-order events.",
        "attack_stage": "Initial Access",
        "mitre_technique": "T1110.001",
        "supporting_event_ids": ["EVT-T1", "EVT-T2"]
    }
    
    evidence_item = {"cited_event_ids": ["EVT-T1", "EVT-T2"], "retrieved_events": out_of_order_events, "missing_event_ids": []}
    verification = verify_finding(fake_case, evidence_item, out_of_order_events)
    
    assert any("Chronological anomaly" in c for c in verification["contradictions"])

def test_6_trust_score_calculation():
    events, eval_cases = get_test_data()
    evidence_res = retrieve_evidence_for_findings(eval_cases, events)
    verifications = verify_all_findings(eval_cases, evidence_res, events)
    
    trust_score = calculate_overall_trust_score(verifications, events)
    assert 0.0 <= trust_score <= 100.0, f"Trust score {trust_score} out of 0-100 bounds"
    assert trust_score != 94.0, "Trust score must be calculated deterministically and not equal fixed LLM confidence"

def test_7_complete_langgraph_execution():
    state = run_investigation_pipeline("INC-2025-CAM-LDS-001")
    
    assert "report" in state
    assert "trust_score" in state
    assert "verification_results" in state
    assert len(state["verification_results"]) == 6
    assert state["evaluation_summary"]["accuracy"] == 1.0, f"Verification accuracy should be 1.0 (100%), got {state['evaluation_summary']['accuracy']}"

if __name__ == "__main__":
    print("Running pytest suite...")
    test_1_supported_finding_verification()
    test_2_unsupported_hallucinated_claim_verification()
    test_3_insufficient_evidence_claim_verification()
    test_4_missing_event_id_handling()
    test_5_temporal_inconsistency_handling()
    test_6_trust_score_calculation()
    test_7_complete_langgraph_execution()
    print("ALL 7 TESTS PASSED SUCCESSFULLY!")
