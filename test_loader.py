"""
SentinelX - Test Script for Data Loader and Event Normalizer
Verifies that CAM-LDS demo dataset loads and normalizes correctly.
"""
import os
import sys

# Ensure src is in python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.data_loader import load_demo_incident, load_normalized_events, load_evaluation_cases
from src.normalizer import normalize_incident_events

def test_data_pipeline():
    print("=" * 60)
    print("SentinelX Data Loading & Normalization Verification Test")
    print("=" * 60)
    
    # 1. Test Demo Incident Loading
    incident = load_demo_incident()
    print(f"[+] Loaded Incident ID: {incident['incident_id']}")
    print(f"    Title: {incident['title']}")
    print(f"    Dataset Source: {incident['dataset_source']}")
    print(f"    Raw Events Count: {incident['raw_events_count']}")
    
    assert len(incident['events']) > 0, "Error: Raw events list is empty!"
    
    # 2. Test Normalization
    normalized = normalize_incident_events(incident['events'])
    print(f"[+] Successfully Normalized {len(normalized)} events.")
    
    # Print sample normalized event
    sample = normalized[0]
    print("\n[+] Sample Normalized Event (EVT-1001):")
    for key, value in sample.items():
        print(f"    - {key:<18s}: {value}")
        
    # Check schema compliance
    required_fields = [
        "event_id", "timestamp", "source_ip", "destination_ip",
        "username", "event_type", "process", "action",
        "severity", "description", "mitre_technique", "source_file"
    ]
    for field in required_fields:
        assert field in sample, f"Missing required field in normalized schema: {field}"
        
    print(f"\n[+] Schema validation passed ({len(required_fields)} required fields present).")
    
    # 3. Test Evaluation Cases Loading
    eval_cases = load_evaluation_cases()
    print(f"[+] Loaded {len(eval_cases)} Evaluation Cases (Findings).")

    techs = set(e['mitre_technique'] for e in normalized if e['mitre_technique'])
    print(f"[+] MITRE ATT&CK Techniques Represented: {sorted(list(techs))}")
    
    print("\n" + "=" * 60)
    print("ALL TESTS PASSED SUCCESSFULLY! Data loader and normalizer ready.")
    print("=" * 60)

if __name__ == "__main__":
    test_data_pipeline()
