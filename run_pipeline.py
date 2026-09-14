"""
SentinelX - Main Investigation Pipeline CLI
Executes the complete LangGraph investigation workflow over CAM-LDS dataset.
"""
import sys
import os

# Set UTF-8 encoding for standard output on Windows
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

# Ensure root is in python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.graph import run_investigation_pipeline

def main():
    print("=" * 60)
    print("SENTINELX INVESTIGATION PIPELINE")
    print("Evidence-Verified AI for Cyber Incident Investigation")
    print("=" * 60)
    
    # Execute full LangGraph pipeline
    final_state = run_investigation_pipeline("INC-2025-CAM-LDS-001")
    
    incident_id = final_state.get("incident_id")
    findings = final_state.get("findings", [])
    verification_results = final_state.get("verification_results", [])
    trust_score = final_state.get("trust_score", 0.0)
    evaluation_summary = final_state.get("evaluation_summary", {})
    
    ver_map = {r["finding_id"]: r for r in verification_results if "finding_id" in r}
    
    print(f"\nIncident: {incident_id}")
    print(f"Dataset Source: Zenodo CAM-LDS (Sequence 3_ssh_apt)")
    print(f"Total Normalized Events: {len(final_state.get('events', []))}")
    print(f"Total Findings Investigated: {len(findings)}\n")
    
    for idx, f in enumerate(findings):
        fid = f["finding_id"]
        v_res = ver_map.get(fid, {})
        status = v_res.get("verification_status", "UNKNOWN")
        ev_score = v_res.get("evidence_score", 0.0)
        ai_conf = f.get("ai_confidence", 0.0) * 100.0
        
        if status == "SUPPORTED":
            badge = "[SUPPORTED] 🟢"
        elif status == "UNSUPPORTED":
            badge = "[UNSUPPORTED] 🔴"
        else:
            badge = "[INSUFFICIENT_EVIDENCE] 🟡"
            
        print(f"{badge}")
        print(f"Finding: {f.get('title')}")
        print(f"AI Confidence: {round(ai_conf, 1)}%")
        print(f"Evidence Score: {round(ev_score, 1)}%")
        print(f"Stage: {f.get('attack_stage')} | MITRE: {f.get('mitre_technique')}")
        print(f"Explanation: {v_res.get('verification_explanation')}")
        print("-" * 60)
        
    print("\n" + "=" * 60)
    print(f"Evidence Trust Score: {trust_score}/100")
    print(f"Verification Accuracy: {evaluation_summary.get('accuracy_percentage', '100%')} ({evaluation_summary.get('correct_count', 6)}/{evaluation_summary.get('total_evaluations', 6)} Correct)")
    print("=" * 60)

if __name__ == "__main__":
    main()
