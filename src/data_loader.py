import json
import os
import copy
from functools import lru_cache
from typing import Dict, List, Any, Optional

def get_data_dir() -> str:
    """Returns absolute path to the data directory."""
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base_dir, "data")

@lru_cache(maxsize=4)
def _read_json_file(filepath: str) -> Any:
    """Cached internal reader for JSON data files."""
    with open(filepath, "r", encoding="utf-8") as f:
        return json.load(f)

from src.normalizer import normalize_timestamp

def load_demo_incident(filepath: Optional[str] = None) -> Dict[str, Any]:
    """Loads raw demo incident extracted from CAM-LDS dataset (cached & canonicalized)."""
    if filepath is None:
        filepath = os.path.join(get_data_dir(), "demo_incident.json")
    
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"Demo incident file not found at: {filepath}")
        
    incident = copy.deepcopy(_read_json_file(filepath))
    # Canonicalize every event timestamp at data loading boundary
    if "events" in incident and isinstance(incident["events"], list):
        for ev in incident["events"]:
            raw_ts = ev.get("timestamp") or ev.get("start-datetime") or ev.get("@timestamp")
            if raw_ts is not None:
                ev["timestamp"] = normalize_timestamp(raw_ts).isoformat()
    return incident

def load_normalized_events(filepath: Optional[str] = None) -> List[Dict[str, Any]]:
    """Loads normalized security events (cached & canonicalized)."""
    if filepath is None:
        filepath = os.path.join(get_data_dir(), "normalized_events.json")
        
    if not os.path.exists(filepath):
        return []
        
    events = copy.deepcopy(_read_json_file(filepath))
    for ev in events:
        raw_ts = ev.get("timestamp")
        if raw_ts is not None:
            ev["timestamp"] = normalize_timestamp(raw_ts).isoformat()
    return events

def save_normalized_events(events: List[Dict[str, Any]], filepath: Optional[str] = None) -> None:
    """Saves normalized security events to JSON and clears cache."""
    if filepath is None:
        filepath = os.path.join(get_data_dir(), "normalized_events.json")
        
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(events, f, indent=2)
    _read_json_file.cache_clear()

def load_evaluation_cases(filepath: Optional[str] = None) -> List[Dict[str, Any]]:
    """Loads evaluation findings containing ground truth and synthetic claims for verifier testing (cached)."""
    if filepath is None:
        filepath = os.path.join(get_data_dir(), "evaluation_cases.json")
        
    if not os.path.exists(filepath):
        return []
        
    return copy.deepcopy(_read_json_file(filepath))
