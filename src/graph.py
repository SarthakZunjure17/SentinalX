"""
SentinelX - LangGraph Workflow Definition
Implements the 6-step state graph:
LOAD EVENTS -> INVESTIGATE -> RETRIEVE EVIDENCE -> VERIFY CLAIMS -> CALCULATE TRUST -> GENERATE REPORT
"""
from typing import Dict, Any
from langgraph.graph import StateGraph, START, END

from src.state import SentinelState
from src.data_loader import load_demo_incident, load_normalized_events, load_evaluation_cases
from src.normalizer import normalize_incident_events
from src.investigator import run_investigation
from src.evidence_retriever import retrieve_evidence_for_findings
from src.verifier import verify_all_findings, evaluate_verification_accuracy
from src.trust_score import calculate_overall_trust_score
from src.report_generator import generate_incident_report

# Node 1: Load Events
def load_events_node(state: SentinelState) -> Dict[str, Any]:
    incident_id = state.get("incident_id", "INC-2025-CAM-LDS-001")
    incident = load_demo_incident()
    raw_events = incident.get("events", [])
    events = normalize_incident_events(raw_events)
    return {"incident_id": incident_id, "events": events}

# Node 2: Investigate
def investigate_node(state: SentinelState) -> Dict[str, Any]:
    events = state.get("events", [])
    mode = state.get("investigation_mode", "demo")
    findings = run_investigation(events, mode=mode)
    return {"findings": findings}

# Node 3: Retrieve Evidence
def retrieve_evidence_node(state: SentinelState) -> Dict[str, Any]:
    findings = state.get("findings", [])
    events = state.get("events", [])
    evidence_results = retrieve_evidence_for_findings(findings, events)
    return {"evidence_results": evidence_results}

# Node 4: Verify Claims
def verify_claims_node(state: SentinelState) -> Dict[str, Any]:
    findings = state.get("findings", [])
    evidence_results = state.get("evidence_results", [])
    events = state.get("events", [])
    mode = state.get("investigation_mode", "controlled_demo")
    
    verification_results = verify_all_findings(findings, evidence_results, events)
    
    # Evaluate verifier accuracy against ground truth evaluation cases ONLY in benchmark/demo mode
    if mode in ["demo", "controlled_demo"]:
        eval_cases = load_evaluation_cases()
        evaluation_summary = evaluate_verification_accuracy(verification_results, eval_cases)
    else:
        evaluation_summary = {
            "mode": mode,
            "source": "Generated dynamically by Live Gemini AI from security event stream",
            "total_evaluations": len(verification_results)
        }
    
    return {
        "verification_results": verification_results,
        "evaluation_summary": evaluation_summary
    }

# Node 5: Calculate Trust
def calculate_trust_node(state: SentinelState) -> Dict[str, Any]:
    verification_results = state.get("verification_results", [])
    events = state.get("events", [])
    trust_score = calculate_overall_trust_score(verification_results, events)
    return {"trust_score": trust_score}

# Node 6: Generate Report
def generate_report_node(state: SentinelState) -> Dict[str, Any]:
    incident_id = state.get("incident_id", "INC-2025-CAM-LDS-001")
    events = state.get("events", [])
    findings = state.get("findings", [])
    verification_results = state.get("verification_results", [])
    trust_score = state.get("trust_score", 0.0)
    
    report = generate_incident_report(
        incident_id=incident_id,
        events=events,
        findings=findings,
        verification_results=verification_results,
        trust_score=trust_score
    )
    return {"report": report}

def build_sentinelx_graph():
    """
    Constructs and compiles the SentinelX LangGraph investigation workflow.
    """
    workflow = StateGraph(SentinelState)
    
    # Add Nodes
    workflow.add_node("load_events", load_events_node)
    workflow.add_node("investigate", investigate_node)
    workflow.add_node("retrieve_evidence", retrieve_evidence_node)
    workflow.add_node("verify_claims", verify_claims_node)
    workflow.add_node("calculate_trust", calculate_trust_node)
    workflow.add_node("generate_report", generate_report_node)
    
    # Define Edges
    workflow.add_edge(START, "load_events")
    workflow.add_edge("load_events", "investigate")
    workflow.add_edge("investigate", "retrieve_evidence")
    workflow.add_edge("retrieve_evidence", "verify_claims")
    workflow.add_edge("verify_claims", "calculate_trust")
    workflow.add_edge("calculate_trust", "generate_report")
    workflow.add_edge("generate_report", END)
    
    return workflow.compile()

def run_investigation_pipeline(incident_id: str = "INC-2025-CAM-LDS-001", mode: str = "demo") -> SentinelState:
    """
    Executes full SentinelX LangGraph investigation workflow.
    """
    app = build_sentinelx_graph()
    initial_state = {"incident_id": incident_id, "investigation_mode": mode}
    final_state = app.invoke(initial_state)
    return final_state

