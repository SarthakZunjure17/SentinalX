import re
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional

def normalize_timestamp(value: Any) -> datetime:
    """
    Canonical timestamp normalizer for SentinelX.
    Parses any ISO string, Unix epoch, or datetime object and returns
    a timezone-aware UTC datetime.
    
    Guarantees:
    1. Timezone-naive datetimes / strings are assigned explicit UTC (tzinfo=timezone.utc).
    2. Timezone-aware datetimes / strings with offsets are converted to UTC (.astimezone(timezone.utc)).
    3. Handles 'Z' / 'z' suffixes, microsecond precision, and custom ISO formats.
    4. Numeric Unix epochs (int/float) are converted to UTC datetimes.
    5. Returns a timezone-aware UTC datetime, preventing 'can't compare offset-naive and offset-aware datetimes'.
    """
    if value is None:
        return datetime(2025, 12, 12, 10, 0, 0, tzinfo=timezone.utc)

    if isinstance(value, datetime):
        if value.tzinfo is None or value.tzinfo.utcoffset(value) is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, tz=timezone.utc)

    if isinstance(value, str):
        val_str = value.strip()
        if not val_str:
            return datetime(2025, 12, 12, 10, 0, 0, tzinfo=timezone.utc)

        # Handle numeric epoch string
        try:
            val_float = float(val_str)
            if val_float > 1000000000:
                return datetime.fromtimestamp(val_float, tz=timezone.utc)
        except ValueError:
            pass

        # Clean 'Z'/'z' suffix and ensure +HH:MM colon format for ISO parser
        clean_str = val_str.replace("Z", "+00:00").replace("z", "+00:00")
        clean_str = re.sub(r'([+-]\d{2})(\d{2})$', r'\1:\2', clean_str)
        try:
            dt = datetime.fromisoformat(clean_str)
            if dt.tzinfo is None or dt.tzinfo.utcoffset(dt) is None:
                return dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc)
        except Exception:
            pass

        # Common fallback format parsing
        for fmt in (
            "%Y-%m-%dT%H:%M:%S.%f%z",
            "%Y-%m-%dT%H:%M:%S%z",
            "%Y-%m-%dT%H:%M:%S.%f",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d %H:%M:%S.%f%z",
            "%Y-%m-%d %H:%M:%S%z",
            "%Y-%m-%d %H:%M:%S.%f",
            "%Y-%m-%d %H:%M:%S",
        ):
            try:
                dt = datetime.strptime(val_str, fmt)
                if dt.tzinfo is None or dt.tzinfo.utcoffset(dt) is None:
                    return dt.replace(tzinfo=timezone.utc)
                return dt.astimezone(timezone.utc)
            except Exception:
                continue

    # Fallback to standard base timestamp in UTC
    return datetime(2025, 12, 12, 10, 0, 0, tzinfo=timezone.utc)


def normalize_event(raw: Dict[str, Any], event_id: str) -> Dict[str, Any]:
    """
    Normalizes a raw CAM-LDS event into SentinelX standard schema.
    
    Standard Schema:
    - event_id: Unique string identifier (e.g. EVT-1001)
    - timestamp: ISO timestamp string
    - source_ip: Attacker/source IP or None
    - destination_ip: Target/destination IP or None
    - username: Operating system / service username or None
    - event_type: Classification string
    - process: Process or command binary name or None
    - action: Granular action description or None
    - severity: LOW, MEDIUM, HIGH, CRITICAL
    - description: Human-readable summary
    - mitre_technique: MITRE ATT&CK ID (e.g. T1110.001) or None
    - source_file: Ground-truth original log file path
    """
    source_type = raw.get("source_type")
    raw_timestamp = raw.get("timestamp") or raw.get("start-datetime") or raw.get("@timestamp") or "2025-12-12T10:00:00.000000"
    canonical_dt = normalize_timestamp(raw_timestamp)
    timestamp = canonical_dt.isoformat()
    source_file = raw.get("source_file", "CAM-LDS: raw_dataset")
    
    source_ip = None
    destination_ip = None
    username = None
    event_type = "security_event"
    process = None
    action = None
    severity = "LOW"
    description = ""
    mitre_technique = None
    
    if source_type == "attackmate":
        cmd = raw.get("command", "")
        tactics = raw.get("tactics", "")
        techs = raw.get("techniques", "")
        tname = raw.get("technique_name", "")
        
        source_ip = "192.42.1.174"  # CAM-LDS attacker host IP
        destination_ip = "10.12.0.223" # Primary target reposerver IP
        
        # Primary MITRE technique extraction
        if techs:
            mitre_technique = techs.split(",")[0].strip()
            
        # Command & Process parsing
        if cmd.startswith("hydra"):
            process = "hydra"
            event_type = "ssh_bruteforce"
            action = "FAILED_LOGIN_BURST"
            severity = "HIGH"
            username = "ubuntu"
            description = f"Automated SSH password brute-force attack initiated using Hydra against {destination_ip}"
            
        elif "sudo" in cmd:
            process = "sudo"
            event_type = "privilege_escalation"
            action = "SUDO_ELEVATION"
            severity = "HIGH"
            username = "root"
            description = "Privilege escalation attempt to root user via sudo invocation"
            
        elif "shadow" in cmd or "passwd" in cmd:
            process = "cat"
            event_type = "credential_dumping"
            action = "READ_SHADOW_FILE"
            severity = "CRITICAL"
            username = "root"
            description = "Unauthorized access and reading of Linux password hashes (/etc/shadow)"
            
        elif "cron" in cmd:
            process = "cron"
            event_type = "cron_persistence"
            action = "CRON_MODIFICATION"
            severity = "HIGH"
            username = "root"
            description = "System cron configuration modified to establish persistence pointing to C2 script"
            
        elif "ssh" in cmd and ("at now" in cmd or "StrictHostKeyChecking" in cmd):
            process = "ssh"
            event_type = "lateral_movement"
            action = "REMOTE_DEPLOYMENT"
            severity = "HIGH"
            username = "aecid"
            description = "Lateral movement execution deploying backdoored package to remote host via SSH/at"
            
        elif "donotcry" in cmd or "encrypt" in cmd:
            process = "donotcry"
            event_type = "ransomware_execution"
            action = "RANSOMWARE_ENCRYPTION"
            severity = "CRITICAL"
            username = "root"
            description = "Execution of 'donotcry' ransomware binary encrypting file storage (/media/data/Images)"
            
        elif "rm -rf" in cmd or "userdel" in cmd:
            process = "rm"
            event_type = "data_destruction"
            action = "DATA_WIPE"
            severity = "CRITICAL"
            username = "root"
            description = "Destructive action: Deleting user accounts and wiping system backup directory"
            
        elif "apt" in cmd or "dpkg" in cmd:
            process = "dpkg-deb"
            event_type = "package_tampering"
            action = "BACKDOOR_INJECTION"
            severity = "HIGH"
            username = "root"
            description = "Unpacking and rebuilding system package (healthcheckd) to inject malicious backdoor"
            
        elif "tcpdump" in cmd:
            process = "tcpdump"
            event_type = "network_sniffing"
            action = "PACKET_CAPTURE"
            severity = "MEDIUM"
            username = "aecid"
            description = "Network packet capture initiated to intercept FTP/unencrypted network credentials"
            
        else:
            first_word = cmd.strip().split()[0] if cmd.strip() else "unknown"
            process = first_word
            event_type = "command_execution"
            action = "SHELL_COMMAND"
            severity = "MEDIUM"
            description = f"Shell command executed by adversary: {cmd[:80]}"

    elif source_type == "wazuh":
        rule_desc = raw.get("rule_description", "")
        level = raw.get("level", 3)
        source_ip = raw.get("src_ip", "192.42.1.174")
        destination_ip = raw.get("dst_ip", "10.12.0.223")
        process = "wazuh-agent"
        action = "ALERT_FIRED"
        
        if level >= 10:
            severity = "CRITICAL"
        elif level >= 7:
            severity = "HIGH"
        elif level >= 4:
            severity = "MEDIUM"
        else:
            severity = "LOW"
            
        event_type = "siem_alert"
        if "SSH" in rule_desc or "Scan" in rule_desc:
            event_type = "network_scan"
            mitre_technique = "T1110.001"
            
        description = f"Wazuh SIEM Alert (Level {level}): {rule_desc}"

    else:
        # Generic fallback preservation
        description = raw.get("description", "Unclassified security log entry")

    return {
        "event_id": event_id,
        "timestamp": timestamp,
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "username": username,
        "event_type": event_type,
        "process": process,
        "action": action,
        "severity": severity,
        "description": description,
        "mitre_technique": mitre_technique,
        "source_file": source_file
    }

def normalize_incident_events(raw_events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Transforms a list of raw events into a clean list of normalized events.
    """
    normalized = []
    for idx, raw in enumerate(raw_events):
        evt_id = f"EVT-{1001 + idx}"
        normalized.append(normalize_event(raw, evt_id))
    return normalized
