"""Focused contract tests for the authoritative v2.31 detector policy."""

from copy import deepcopy
from datetime import timedelta
import importlib.util
import os
import pathlib
import sys
import tempfile
import unittest

import pandas as pd
import yaml


ROOT = pathlib.Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "chronoSIFT_v2_31.py"
RULES_PATH = ROOT / "rules" / "rules_profiled_audited_nsrl_updates_baseline_yara_fixed_v10.yaml"
WEIGHTS_PATH = ROOT / "rules" / "weights_profiled_audited_nsrl_updates_baseline_yara_fixed_v8.yaml"

SPEC = importlib.util.spec_from_file_location("chronosift_v231_detector_policy", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)
ChronoSiftEngine = MODULE.ChronoSiftEngine


def _load_yaml(path):
    with path.open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle) or {}


def _replace_config_scalar(value, old, new):
    if isinstance(value, dict):
        for key, item in value.items():
            value[key] = _replace_config_scalar(item, old, new)
        return value
    if isinstance(value, list):
        for index, item in enumerate(value):
            value[index] = _replace_config_scalar(item, old, new)
        return value
    return new if value == old else value


BASE_RULES = _load_yaml(RULES_PATH)
BASE_WEIGHTS = _load_yaml(WEIGHTS_PATH)
EXPECTED_YARA_POLICY_DIGEST = (
    "d35d406119926a120ccabc3ea5769d1ca756b7ee299452f707844d5e9e054b79"
)
BASE_YARA_PATH = str(
    (
        ROOT
        / BASE_RULES["detector_policy"]["detectors"]["yara_classification"][
            "metadata"
        ]["path"]
    ).resolve()
)


def _expected_atomic_execution_gate(
    source_signals,
    output_signal,
    rule_id,
    description="Canonical execution signal derived from execution-related source detections",
    confidence="high",
):
    return {
        "stage": "atomic",
        "executor": "signal_gate",
        "enabled": True,
        "evidence_type": "direct",
        "inputs": {"signals": list(source_signals)},
        "conditions": {"match": "any", "minimum_value_exclusive": 0},
        "emissions": [
            {
                "name": output_signal,
                "value": 1,
                "rule_id": rule_id,
                "description": description,
                "confidence": confidence,
            }
        ],
        "evidence": {"derived_from": {"resolver": "matched_signals"}},
    }


def _expected_clamav_category(
    name,
    rule_id,
    description,
    *,
    suppress_generic=False,
    confidence="high",
    include_forensic_category=True,
):
    evidence = ["filename", "av_signature", "platform", "category", "family"]
    if include_forensic_category:
        evidence.append("forensic_category")
    return {
        "suppress_generic": suppress_generic,
        "emission": {
            "name": name,
            "value": 1,
            "rule_id": rule_id,
            "description": description,
            "confidence": confidence,
        },
        "evidence": evidence,
    }


def _expected_clamav_classifier():
    return {
        "stage": "atomic",
        "executor": "clamav_classifier",
        "enabled": True,
        "evidence_type": "direct",
        "default_category": "malware",
        "category_tokens": {
            "ransomware": "ransomware",
            "trojan": "malware",
            "backdoor": "malware",
            "virus": "malware",
            "worm": "malware",
            "malware": "malware",
            "dropper": "malware",
            "downloader": "malware",
            "loader": "malware",
            "infostealer": "malware",
            "spyware": "malware",
            "keylogger": "malware",
            "ircbot": "malware",
            "proxy": "malware",
            "rootkit": "exploit",
            "exploit": "exploit",
            "tool": "offensive_tool",
            "hacktool": "offensive_tool",
            "pua": "pua",
            "adware": "pua",
            "coinminer": "pua",
            "joke": "pua",
            "phishing": "malware",
            "packed": "malware",
            "packer": "malware",
            "file": "malware",
            "countermeasure": "offensive_tool",
        },
        "family_overrides": [
            {"contains": family, "category": category}
            for family, category in [
                ("mimikatz", "offensive_tool"),
                ("pwdump", "offensive_tool"),
                ("lazagne", "offensive_tool"),
                ("rubeus", "offensive_tool"),
                ("impacket", "offensive_tool"),
                ("cobaltstrike", "offensive_tool"),
                ("metasploit", "offensive_tool"),
                ("meterpreter", "offensive_tool"),
                ("sharphound", "offensive_tool"),
                ("bloodhound", "offensive_tool"),
                ("c99shell", "webshell"),
                ("c99", "webshell"),
                ("r57shell", "webshell"),
                ("b374k", "webshell"),
                ("weevely", "webshell"),
                ("wso", "webshell"),
                ("petya", "ransomware"),
                ("wannacry", "ransomware"),
                ("lockbit", "ransomware"),
                ("conti", "ransomware"),
                ("revil", "ransomware"),
                ("ryuk", "ransomware"),
                ("maze", "ransomware"),
                ("blackcat", "ransomware"),
                ("alphv", "ransomware"),
                ("babuk", "ransomware"),
                ("akira", "ransomware"),
                ("razy", "ransomware"),
            ]
        ],
        "generic": {
            "emission": {
                "name": "av_hit",
                "value": 1,
                "rule_id": "AV_HIT",
                "description": "Antivirus detection: {forensic_category}",
                "confidence": "high",
            },
            "unclassified_description": "Antivirus hit present",
            "evidence": [
                "filename",
                "av_signature",
                "platform",
                "category",
                "family",
                "forensic_category",
            ],
        },
        "categories": {
            "offensive_tool": _expected_clamav_category(
                "av_offensive_tool",
                "AV_OFFENSIVE_TOOL",
                "Antivirus classified an offensive tool",
            ),
            "ransomware": _expected_clamav_category(
                "av_ransomware",
                "AV_RANSOMWARE",
                "Antivirus classified ransomware",
            ),
            "exploit": _expected_clamav_category(
                "av_exploit",
                "AV_EXPLOIT",
                "Antivirus classified an exploit or rootkit",
            ),
            "malware": _expected_clamav_category(
                "av_malware",
                "AV_MALWARE",
                "Antivirus classified malware",
            ),
            "pua": _expected_clamav_category(
                "av_pua",
                "AV_PUA",
                "Potentially Unwanted Application detected by antivirus",
                suppress_generic=True,
                confidence="low",
                include_forensic_category=False,
            ),
            "webshell": _expected_clamav_category(
                "av_webshell",
                "AV_WEBSHELL",
                "Antivirus classified a web shell",
            ),
        },
    }


TEMPORAL_ARTIFACT_FIELDS = [
    "filename",
    "relative_path",
    "display_name",
    "pathspec",
    "link_target",
]
TEMPORAL_COPY_TOKENS = [
    "copy ",
    "cp ",
    "xcopy ",
    "robocopy",
    "move ",
    "mv ",
    "copy-item",
    "tar ",
    "zip ",
    "7z ",
    "rar ",
    "scp ",
    "sftp ",
    "curl ",
    "wget ",
]
TEMPORAL_PASSWORD_LABELS = [
    "login data",
    "key4.db",
    "logins.json",
    ".kdbx",
    "credentials",
    "vault",
    "web.config",
]
TEMPORAL_FOLLOW_ON_SIGNALS = [
    "transfer_execution",
    "data_transfer_tool_exec",
    "staging_then_transfer",
    "large_http_transfer",
    "archive_created",
    "large_archive_created",
]


def _expected_artifact_follow_on_policy(
    *,
    source_signals,
    labels,
    output_signal,
    rule_id,
    description,
):
    return {
        "stage": "temporal",
        "executor": "artifact_follow_on_sequence",
        "enabled": True,
        "evidence_type": "contextual",
        "lookback": "1h",
        "window_bounds": "closed",
        "ordering": "source_at_or_before_follow_on",
        "key": {"scope": "deadbox_global"},
        "emit_on": "source",
        "source": {
            "any_signals": list(source_signals),
            "minimum_signal_value_exclusive": 0,
        },
        "inputs": {
            "path": {
                "resolver": "best_effort_file_path",
                "fields": list(TEMPORAL_ARTIFACT_FIELDS),
            },
            "combined_text": {
                "resolver": "concat_lower",
                "fields": ["message", "command_line"],
            },
        },
        "labels": {"contains_any": list(labels)},
        "copy_stage": {
            "command_tokens": list(TEMPORAL_COPY_TOKENS),
            "support_text_tokens": list(TEMPORAL_PASSWORD_LABELS),
            "support_signals": ["credential_dumping", "password_store_access"],
            "minimum_signal_value_exclusive": 0,
        },
        "follow_on": {
            "any_signals": list(TEMPORAL_FOLLOW_ON_SIGNALS),
            "minimum_signal_value_exclusive": 0,
            "allow_unlabelled": True,
        },
        "follow_on_qualification": {
            "any": [
                {"all": ["copy_command", "copy_text_support"]},
                {"all": ["copy_command", "copy_signal_support"]},
                {"all": ["follow_on_signal"]},
            ]
        },
        "emissions": [
            {
                "name": output_signal,
                "value": 1,
                "rule_id": rule_id,
                "description": description,
                "confidence": "medium",
            }
        ],
        "evidence": {
            "hostname": {"resolver": "row_field", "field": "hostname"},
            "source_timestamp": {"resolver": "source_timestamp"},
            "window_seconds": {"resolver": "window_seconds"},
        },
    }


def _expected_signal_projection(*, stage, projections):
    return {
        "stage": stage,
        "executor": "signal_projection",
        "enabled": True,
        "evidence_type": "direct",
        "projections": [
            {
                "inputs": {"signals": list(source_signals)},
                "conditions": {
                    "match": "any",
                    "minimum_value_exclusive": 0,
                },
                "strength": "maximum_matched_times_emission_value",
                "emissions": [
                    {
                        "name": output_signal,
                        "value": 1,
                        "rule_id": rule_id,
                        "description": description,
                        "confidence": "high",
                    }
                ],
            }
            for source_signals, output_signal, rule_id, description in projections
        ],
        "evidence": {"derived_from": {"resolver": "matched_signals"}},
    }


PERSISTENCE_PROJECTION_DESCRIPTION = (
    "Canonical persistence signal derived from persistence-related source detections"
)
TRANSFER_PROJECTION_DESCRIPTION = (
    "Canonical transfer/exfiltration signal derived from staging, transfer, or "
    "exfiltration-pattern detections"
)


def _expected_named_emission(name, rule_id, description, confidence):
    return {
        "name": name,
        "value": 1,
        "rule_id": rule_id,
        "description": description,
        "confidence": confidence,
    }


def _expected_canonical_authentication():
    description = (
        "Canonical authentication signal derived from protocol-specific "
        "success/failure semantics"
    )
    emissions = (
        ("success", "auth_success", "AUTH_SUCCESS"),
        ("failure", "auth_failure", "AUTH_FAILURE"),
        ("remote_success", "auth_remote_success", "AUTH_REMOTE_SUCCESS"),
        ("remote_failure", "auth_remote_failure", "AUTH_REMOTE_FAILURE"),
        ("local_success", "auth_local_success", "AUTH_LOCAL_SUCCESS"),
        ("local_failure", "auth_local_failure", "AUTH_LOCAL_FAILURE"),
        (
            "remote_interactive_success",
            "auth_remote_interactive_success",
            "AUTH_REMOTE_INTERACTIVE_SUCCESS",
        ),
        (
            "remote_shell_success",
            "auth_remote_shell_success",
            "AUTH_REMOTE_SHELL_SUCCESS",
        ),
        ("invalid_user", "auth_invalid_user", "AUTH_INVALID_USER"),
        (
            "new_credentials_logon",
            "auth_newcredentials_logon",
            "AUTH_NEWCREDENTIALS_LOGON",
        ),
        ("service_logon", "auth_service_logon", "AUTH_SERVICE_LOGON"),
        ("ntlm_remote", "auth_ntlm_remote", "AUTH_NTLM_REMOTE"),
        (
            "lateral_movement",
            "lateral_movement_indicator",
            "LATERAL_MOVEMENT_INDICATOR",
        ),
    )
    return {
        "stage": "atomic",
        "executor": "canonical_authentication",
        "enabled": True,
        "evidence_type": "direct",
        "inputs": {
            "fields": {
                "outcome": "auth_outcome",
                "protocol": "auth_protocol",
                "direction": "auth_direction",
                "logon_type": "logon_type",
                "message": "message",
                "authentication_package": "authentication_package",
            },
            "source_signals": {
                "success": ["auth_success_generic", "ssh_success", "rdp_success"],
                "failure": ["auth_fail_generic", "ssh_fail", "rdp_fail"],
                "minimum_signal_value_exclusive": 0,
            },
        },
        "outcomes": {
            "success": "success",
            "failure": "failure",
            "outcome_source_match": "any",
            "conflict_resolution": "allow_both",
        },
        "semantics": {
            "remote": {
                "match": "any",
                "direction_values": ["remote"],
                "protocol_values": ["ssh", "rdp", "windows-network"],
            },
            "remote_interactive": {
                "match": "any",
                "protocol_values": ["rdp"],
                "logon_types": ["10"],
            },
            "remote_shell": {"protocol_values": ["ssh"]},
            "invalid_user": {"message_contains": ["invalid user", "unknown user"]},
            "new_credentials": {"logon_types": ["9"]},
            "service_logon": {"logon_types": ["4", "5"]},
            "ntlm_remote": {"authentication_packages": ["ntlm"]},
            "lateral_movement": {
                "include_remote": True,
                "logon_types": ["3", "10"],
                "authentication_packages": ["ntlm"],
                "minimum_matches": 2,
            },
        },
        "eligibility": {
            "all": [],
            "any": ["success", "failure"],
            "none": [],
        },
        "decisions": {
            "success": {"all": ["success"], "any": [], "none": []},
            "failure": {"all": ["failure"], "any": [], "none": []},
            "remote_success": {
                "all": ["success", "remote"], "any": [], "none": [],
            },
            "remote_failure": {
                "all": ["failure", "remote"], "any": [], "none": [],
            },
            "local_success": {
                "all": ["success"], "any": [], "none": ["remote"],
            },
            "local_failure": {
                "all": ["failure"], "any": [], "none": ["remote"],
            },
            "remote_interactive_success": {
                "all": ["success", "remote", "remote_interactive"],
                "any": [], "none": [],
            },
            "remote_shell_success": {
                "all": ["success", "remote", "remote_shell"],
                "any": [], "none": [],
            },
            "invalid_user": {
                "all": ["failure", "invalid_user"], "any": [], "none": [],
            },
            "new_credentials_logon": {
                "all": ["success", "new_credentials"],
                "any": [], "none": [],
            },
            "service_logon": {
                "all": ["success", "service_logon"],
                "any": [], "none": [],
            },
            "ntlm_remote": {
                "all": ["success", "remote", "ntlm_package"],
                "any": [], "none": [],
            },
            "lateral_movement": {
                "all": ["success", "lateral_movement"],
                "any": [], "none": [],
            },
        },
        "emissions": {
            semantic: _expected_named_emission(
                signal_name,
                rule_id,
                description,
                "high",
            )
            for semantic, signal_name, rule_id in emissions
        },
        "evidence": ["derived_from"],
    }


def _expected_execution_context_classifier():
    emissions = (
        ("from_tmp", "exec_from_tmp", "EXEC_FROM_TMP", "Execution path indicates a temporary directory", "medium"),
        ("from_user_writable", "exec_from_user_writable", "EXEC_FROM_USER_WRITABLE", "Execution path indicates a user-writable location", "medium"),
        ("suspicious_path", "exec_suspicious_path", "EXEC_SUSPICIOUS_PATH", "Execution path indicates a suspicious location", "medium"),
        ("system_binary_in_user_path", "exec_system_binary_in_user_path", "EXEC_SYSTEM_BINARY_IN_USER_PATH", "System binary name executed from a suspicious or user-writable path", "medium"),
        ("compiler_activity", "exec_compiler_activity", "EXEC_COMPILER_ACTIVITY", "Compiler or build-tool activity observed", "medium"),
        ("shell_spawn", "exec_shell_spawn", "EXEC_SHELL_SPAWN", "Shell execution observed", "medium"),
        ("network_tool", "exec_network_tool", "EXEC_NETWORK_TOOL", "Network transfer tooling observed", "medium"),
        ("archive_tool", "exec_archive_tool", "EXEC_ARCHIVE_TOOL", "Archive tooling observed", "medium"),
        ("privileged_context", "exec_privileged_context", "EXEC_PRIVILEGED_CONTEXT", "Execution occurred in a privileged user context", "medium"),
        ("new_suid_binary", "exec_new_suid_binary", "EXEC_NEW_SUID_BINARY", "Privilege-escalation or SUID-related command semantics observed", "high"),
    )
    return {
        "stage": "atomic",
        "executor": "execution_context_classifier",
        "enabled": True,
        "evidence_type": "direct",
        "inputs": {
            "path": {
                "resolver": "first_nonempty",
                "fields": [
                    "image_path", "new_process_name", "file_path", "filename",
                    "relative_path", "display_name", "pathspec", "path",
                ],
            },
            "command": {
                "resolver": "first_nonempty",
                "fields": ["actor_cmd", "command_line", "command", "message"],
            },
            "actor": {
                "resolver": "first_nonempty",
                "fields": ["actor_principal", "actor_user"],
            },
        },
        "classification": {
            "temporary_path_contains": [
                "/tmp/", "/var/tmp/", "/dev/shm/", "\\temp\\", "%temp%",
                "\\windows\\temp\\", "\\appdata\\local\\temp\\",
            ],
            "user_writable_path_contains": [
                "/tmp/", "/var/tmp/", "/dev/shm/", "/home/", "/users/",
                "/downloads/", "\\users\\public\\", "\\users\\", "\\temp\\",
                "\\appdata\\", "%temp%", "%appdata%", "\\windows\\temp\\",
                "\\appdata\\local\\temp\\",
            ],
            "suspicious_path_contains": [
                "/run/", "/var/run/", "/opt/", "\\programdata\\",
                "\\perflogs\\", "\\recycler\\", "\\windows\\debug\\",
                "\\intel\\",
            ],
            "system_binary_names": [
                "svchost.exe", "lsass.exe", "explorer.exe", "sshd", "bash",
            ],
            "command_names": {
                "compiler": ["gcc", "cc", "make"],
                "shell": ["sh", "bash", "cmd", "cmd.exe", "powershell", "pwsh"],
                "network": [
                    "nc", "netcat", "ncat", "socat", "curl", "wget", "ftp",
                    "scp", "sftp",
                ],
                "archive": ["tar", "zip", "7z", "rar", "gzip"],
            },
            "privileged_actors": ["root", "administrator", "admin"],
            "suid_regex": (
                r"(?i)(?:chmod\s+4[0-7]{3}|chmod\s+u\+s|setuid|setgid|"
                r"chown\s+root(?::root)?|suid)"
            ),
        },
        "decisions": {
            "from_tmp": {
                "all": ["temporary_path"], "any": [], "none": [],
            },
            "from_user_writable": {
                "all": [],
                "any": ["temporary_path", "user_writable_path"],
                "none": [],
            },
            "suspicious_path": {
                "all": ["suspicious_path"],
                "any": [],
                "none": ["temporary_path", "user_writable_path"],
            },
            "system_binary_in_user_path": {
                "all": ["system_binary_name"],
                "any": [
                    "temporary_path", "user_writable_path", "suspicious_path",
                ],
                "none": [],
            },
            "compiler_activity": {
                "all": ["compiler_command"], "any": [], "none": [],
            },
            "shell_spawn": {
                "all": ["shell_command"], "any": [], "none": [],
            },
            "network_tool": {
                "all": ["network_command"], "any": [], "none": [],
            },
            "archive_tool": {
                "all": ["archive_command"], "any": [], "none": [],
            },
            "privileged_context": {
                "all": ["privileged_actor"], "any": [], "none": [],
            },
            "new_suid_binary": {
                "all": ["suid_command"], "any": [], "none": [],
            },
        },
        "emissions": {
            semantic: _expected_named_emission(
                signal_name, rule_id, description, confidence
            )
            for semantic, signal_name, rule_id, description, confidence in emissions
        },
        "evidence": ["path", "command", "actor_user", "derived_from"],
    }


def _expected_file_lifecycle():
    emissions = (
        ("created", "file_created", "FILE_CREATED", "File creation-like timestamp observed", "low"),
        ("modified", "file_modified", "FILE_MODIFIED", "File modification-like timestamp observed", "low"),
        ("deleted", "file_deleted", "FILE_DELETED", "File deletion-like artefact observed", "low"),
        ("web_executable_created", "web_executable_file_created", "WEB_EXECUTABLE_FILE_CREATED", "Executable web content created under a web root", "medium"),
        ("archive_created", "archive_created", "ARCHIVE_CREATED", "Archive creation artefact observed", "medium"),
        ("database_dump_candidate", "database_dump_candidate", "DATABASE_DUMP_CANDIDATE", "Database dump-like file artefact observed", "medium"),
        ("defacement_candidate", "defacement_candidate", "DEFACEMENT_CANDIDATE", "Web content modified under a web root", "medium"),
        ("sensitive_file_access", "sensitive_file_access", "SENSITIVE_FILE_ACCESS", "Sensitive path artefact observed", "medium"),
        ("short_lived_file", "short_lived_file", "SHORT_LIVED_FILE", "Suspicious file was created and deleted within a bounded window", "medium"),
        ("mass_file_modification", "mass_file_modification", "MASS_FILE_MODIFICATION", "Large number of file modifications observed within a bounded window", "medium"),
        ("ransomware_extension_burst", "ransomware_extension_burst", "RANSOMWARE_EXTENSION_BURST", "Burst of ransomware-style encrypted file extensions observed within a bounded window", "medium"),
    )
    return {
        "stage": "contextual",
        "executor": "file_lifecycle",
        "enabled": True,
        "evidence_type": "direct",
        "inputs": {
            "path": {
                "resolver": "best_effort_file_path",
                "fields": list(TEMPORAL_ARTIFACT_FIELDS),
            },
            "timestamp_description_field": "timestamp_desc",
            "host_field": "hostname",
            "parser_field": "parser",
            "message_field": "message",
            "file_size_field": "file_size",
            "allocation_field": "is_allocated",
        },
        "classification": {
            "timestamp_kinds": {
                "priority": ["create", "delete", "modify", "access"],
                "contains": {
                    "create": ["create", "creation", "birth"],
                    "delete": ["delet"],
                    "modify": ["modif", "change", "content", "mtime"],
                    "access": ["access", "open", "atime"],
                },
            },
            "path_contains": {
                "web_root": [
                    "/var/www/", "/srv/www/", "/usr/share/nginx/html/",
                    "/htdocs/", "/httpdocs/", "\\inetpub\\wwwroot\\",
                    "\\xampp\\htdocs\\",
                ],
                "sensitive": [
                    "/etc/passwd", "/etc/shadow", "/etc/sudoers", "/root/.ssh/",
                    "/.ssh/", "/.gnupg/", "/.bash_history", "/.zsh_history",
                    "/.mysql_history", "/.psql_history", "id_rsa", "id_dsa",
                    "id_ecdsa", "id_ed25519", "authorized_keys", "known_hosts",
                    "\\windows\\system32\\config\\sam",
                    "\\windows\\system32\\config\\system",
                    "\\windows\\system32\\config\\security", "ntds.dit",
                    "web.config", "\\repair\\sam", "\\repair\\system",
                ],
                "database_dump_name": ["dump", "mysqldump", "pg_dump", "sqlite dump"],
                "excluded_update": [
                    "\\winsxs\\", "\\softwaredistribution\\",
                    "\\windows\\assembly\\", "\\windows\\installer\\",
                    "/usr/lib/", "/usr/share/doc/", "/usr/share/man/",
                    "/var/cache/apt/", "/var/cache/dnf/", "/var/cache/yum/",
                    "/var/lib/dpkg/", "/var/lib/rpm/",
                ],
            },
            "extensions": {
                "web_script": [
                    ".php", ".phtml", ".php3", ".php4", ".php5", ".asp",
                    ".aspx", ".ashx", ".jsp", ".jspx", ".cgi", ".pl",
                ],
                "web_content": [
                    ".php", ".phtml", ".php3", ".php4", ".php5", ".asp",
                    ".aspx", ".jsp", ".jspx", ".cgi", ".pl", ".html",
                    ".htm", ".js", ".css",
                ],
                "database_dump": [".sql", ".dump", ".bak", ".sqlite", ".db"],
                "archive": [".zip", ".7z", ".rar", ".tar", ".gz", ".tgz", ".bz2", ".xz"],
            },
            "suspicious_temp_basename_contains": ["tmp", "temp"],
            "ransomware_extension_suffixes": [
                ".locked", ".lockbit", ".encrypted", ".crypt", ".crypted",
                ".conti", ".akira", ".blackcat", ".cl0p", ".clop", ".zepto",
                ".cerber", ".deadbolt", ".wannacry", ".wncry", ".play",
                ".royal", ".phobos",
            ],
            "derived_predicates": {
                "suspicious_web": {
                    "all": ["web_root", "web_script_extension"],
                    "any": [],
                    "none": [],
                },
                "database_dump": {
                    "all": [],
                    "any": [
                        "database_dump_extension",
                        "database_dump_basename",
                        "database_dump_message",
                    ],
                    "none": [],
                },
                "unallocated_with_extension": {
                    "all": ["unallocated", "extension_present"],
                    "any": [],
                    "none": [],
                },
                "path_not_excluded_update": {
                    "all": ["path_present"],
                    "any": [],
                    "none": ["excluded_update_path"],
                },
            },
        },
        "conditions": {
            "weight_aware_semantics": ["created", "modified", "deleted"],
            "row_emissions": {
                "created": {
                    "match": "all",
                    "timestamp_kinds": ["create"],
                    "derived_predicates": ["path_present"],
                },
                "modified": {
                    "match": "all",
                    "timestamp_kinds": ["modify"],
                    "derived_predicates": ["path_present"],
                },
                "deleted": {
                    "match": "any",
                    "timestamp_kinds": ["delete"],
                    "derived_predicates": ["unallocated_with_extension"],
                },
                "web_executable_created": {
                    "match": "all",
                    "timestamp_kinds": ["create"],
                    "derived_predicates": [
                        "path_present", "web_root", "web_script_extension",
                    ],
                },
                "archive_created": {
                    "match": "all",
                    "timestamp_kinds": ["create"],
                    "derived_predicates": ["path_present", "archive_extension"],
                },
                "database_dump_candidate": {
                    "match": "all",
                    "timestamp_kinds": ["create"],
                    "derived_predicates": ["path_present", "database_dump"],
                },
                "defacement_candidate": {
                    "match": "all",
                    "timestamp_kinds": ["modify"],
                    "derived_predicates": [
                        "path_present", "web_root", "web_content_extension",
                    ],
                },
                "sensitive_file_access": {
                    "match": "all",
                    "timestamp_kinds": [],
                    "derived_predicates": ["path_present", "sensitive_path"],
                },
            },
            "windows": {
                "short_lived_file": {
                    "lookback": "2h",
                    "key_fields": ["host", "path"],
                    "source_timestamp_kinds": ["create"],
                    "target_timestamp_kinds": ["delete"],
                    "source_selection": "latest",
                    "ordering": "before_or_same",
                    "window_bounds": "closed",
                    "emit_on": "target",
                    "conditions": {
                        "any": [
                            {"all": ["source_suspicious_web"]},
                            {"all": ["target_suspicious_web"]},
                            {
                                "all": [
                                    "target_web_script_extension",
                                    "target_suspicious_temp_basename",
                                ]
                            },
                        ]
                    },
                },
                "mass_file_modification": {
                    "lookback": "10m",
                    "threshold": 25,
                    "threshold_comparison": "at_least",
                    "window_bounds": "closed",
                    "eligible_timestamp_kinds": ["modify"],
                    "group_by": ["host", "parent_directory"],
                    "max_emissions_per_group": 1,
                    "conditions": {
                        "any": [
                            {"all": ["path_present", "path_not_excluded_update"]}
                        ]
                    },
                },
                "ransomware_extension_burst": {
                    "lookback": "15m",
                    "threshold": 6,
                    "threshold_comparison": "at_least",
                    "window_bounds": "closed",
                    "eligible_timestamp_kinds": ["create", "modify"],
                    "group_by": ["host"],
                    "max_emissions_per_group": 1,
                    "conditions": {
                        "any": [
                            {
                                "all": [
                                    "path_present", "path_not_excluded_update",
                                    "ransomware_extension_suffix",
                                ]
                            }
                        ]
                    },
                },
            },
        },
        "emissions": {
            semantic: _expected_named_emission(
                signal_name, rule_id, description, confidence
            )
            for semantic, signal_name, rule_id, description, confidence in emissions
        },
        "evidence": {
            "created": ["path", "timestamp_desc"],
            "modified": ["path", "timestamp_desc"],
            "deleted": ["path", "timestamp_desc", "is_allocated"],
            "web_executable_created": ["path", "parser", "hostname"],
            "archive_created": ["path", "file_size"],
            "database_dump_candidate": ["path", "message"],
            "defacement_candidate": ["path", "hostname"],
            "sensitive_file_access": ["path", "timestamp_desc"],
            "short_lived_file": ["path", "create_timestamp", "delete_timestamp", "lifetime_seconds"],
            "mass_file_modification": ["host", "directory", "window_seconds", "count_in_window"],
            "ransomware_extension_burst": ["host", "window_seconds", "count_in_window", "extensions"],
        },
    }


def _expected_mft_timestomping():
    excluded = [
        "\\winsxs\\", "\\softwaredistribution\\", "\\windows\\assembly\\",
        "\\windows\\installer\\", "/usr/lib/", "/usr/share/doc/",
        "/usr/share/man/", "/var/cache/apt/", "/var/cache/dnf/",
        "/var/cache/yum/", "/var/lib/dpkg/", "/var/lib/rpm/",
    ]
    return {
        "stage": "contextual",
        "executor": "mft_timestomping",
        "enabled": True,
        "evidence_type": "direct",
        "inputs": {
            "path": {
                "resolver": "best_effort_file_path",
                "fields": list(TEMPORAL_ARTIFACT_FIELDS),
            },
            "parser_field": "parser",
            "timestamp_description_field": "timestamp_desc",
        },
        "conditions": {
            "parser_contains": ["mft"],
            "creation_contains": ["creation", "birth"],
            "attributes": {
                "standard_information_contains": [
                    "$standard_information", "$si", "standard information",
                ],
                "file_name_contains": ["$file_name", "$fn", "file name"],
            },
            "minimum_delta": "1s",
            "excluded_path_contains": excluded,
            "bulk_extraction": {
                "group_by": "parent_directory",
                "threshold": 5,
            },
        },
        "branches": {
            "targeted": {
                "description": (
                    "MFT $STANDARD_INFORMATION creation predates $FILE_NAME "
                    "creation, indicating timestamp manipulation (T1070.006)"
                ),
                "confidence": "high",
                "evidence": ["path", "si_creation", "fn_creation", "delta_seconds"],
            },
            "bulk_extraction_likely": {
                "description": (
                    "MFT creation attributes differ across a bulk directory cohort, "
                    "suggesting archive extraction or file copy rather than targeted "
                    "timestomping"
                ),
                "confidence": "low",
                "evidence": [
                    "path", "si_creation", "fn_creation", "delta_seconds",
                    "bulk_extraction_dampened", "directory_hit_count",
                ],
            },
        },
        "emissions": [
            _expected_named_emission(
                "timestomping",
                "TIMESTOMPING",
                "MFT attribute timestamp inconsistency detected",
                "high",
            )
        ],
    }


EXPECTED_DETECTOR_POLICY = {
    "version": 1,
    "mode": "authoritative",
    "detectors": {
        "clamav_classification": _expected_clamav_classifier(),
        "systemd_service_persistence": {
            "stage": "contextual",
            "executor": "systemd_service_persistence",
            "enabled": True,
            "branch_mode": "first_match",
            "branch_order": ["artifact_change", "command_activity"],
            "evidence_type": "direct",
            "inputs": {
                "path": {
                    "resolver": "best_effort_file_path",
                    "fields": [
                        "filename",
                        "relative_path",
                        "display_name",
                        "pathspec",
                        "link_target",
                    ],
                },
                "timestamp_kind": {
                    "resolver": "timestamp_desc_kind",
                    "field": "timestamp_desc",
                    "kinds": {
                        "priority": ["create", "delete", "modify", "access"],
                        "contains": {
                            "create": ["create", "creation", "birth"],
                            "delete": ["delet"],
                            "modify": ["modif", "change", "content", "mtime"],
                            "access": ["access", "open", "atime"],
                        },
                    },
                },
                "combined_text": {
                    "resolver": "concat_lower",
                    "fields": ["actor_cmd", "command_line", "message"],
                    "first_existing": ["actor_url", "url"],
                },
            },
            "branches": {
                "artifact_change": {
                    "conditions": {
                        "any": [
                            {
                                "all": [
                                    "artifact_path", "unit_extension",
                                    "timestamp_kind",
                                ]
                            }
                        ]
                    },
                    "path_contains": [
                        "/etc/systemd/system/", "/lib/systemd/system/",
                        "/usr/lib/systemd/system/", "/etc/init.d/",
                        "/system/currentcontrolset/services/",
                    ],
                    "extension_in": [
                        ".service", ".socket", ".timer", ".mount", ".path",
                    ],
                    "timestamp_kinds": ["create", "modify", "delete"],
                    "description": "Systemd unit artefact changed under a service manager path",
                    "confidence": "high",
                    "evidence": ["path", "timestamp_desc", "hostname"],
                },
                "command_activity": {
                    "conditions": {
                        "any": [
                            {"all": ["persistent_token"]},
                            {
                                "all": [
                                    "transient_token",
                                    "unit_reference_extension",
                                ]
                            },
                            {
                                "all": [
                                    "transient_token", "unit_reference_path",
                                ]
                            },
                        ]
                    },
                    "persistent_tokens": [
                        "systemctl enable",
                        "systemctl link",
                        "systemctl preset",
                        "daemon-reload",
                    ],
                    "transient_tokens": ["systemctl start", "systemctl restart"],
                    "unit_reference_extensions": [
                        ".service", ".socket", ".timer", ".mount", ".path",
                    ],
                    "unit_reference_path_tokens": [
                        "/etc/systemd/",
                        "/lib/systemd/system/",
                        "/usr/lib/systemd/system/",
                        "/run/systemd/system/",
                    ],
                    "description": (
                        "Systemd enablement or unit-management semantics observed in command or log text"
                    ),
                    "confidence": "medium",
                    "evidence": ["command", "message", "hostname"],
                },
            },
            "emissions": [
                {
                    "name": "systemd_service_persistence",
                    "value": 1,
                    "rule_id": "SYSTEMD_SERVICE_PERSISTENCE",
                }
            ],
            "evidence": {
                "path": {
                    "resolver": "best_effort_file_path",
                    "fields": list(TEMPORAL_ARTIFACT_FIELDS),
                },
                "timestamp_desc": {
                    "resolver": "row_field",
                    "field": "timestamp_desc",
                    "max_chars": 120,
                },
                "hostname": {"resolver": "row_field", "field": "hostname"},
                "command": {
                    "resolver": "first_nonempty",
                    "fields": [
                        "actor_cmd", "command_line", "message", "actor_url", "url",
                    ],
                    "max_chars": 240,
                },
                "message": {
                    "resolver": "first_nonempty",
                    "fields": [
                        "message", "actor_url", "url", "actor_cmd", "command_line",
                    ],
                    "max_chars": 240,
                },
            },
        },
        "download_to_execution": {
            "stage": "temporal",
            "executor": "signal_sequence_by_artifact",
            "enabled": True,
            "evidence_type": "contextual",
            "lookback": "2h",
            "ordering": "source_at_or_before_target",
            "window_bounds": "closed",
            "source_selection": "earliest_in_window",
            "emit_on": "target",
            "key": {
                "scope": "deadbox_global",
                "host_field": "hostname",
                "artifact": {
                    "resolver": "best_effort_file_basename",
                    "fields": [
                        "filename",
                        "relative_path",
                        "display_name",
                        "pathspec",
                        "link_target",
                    ],
                },
            },
            "source": {
                "any_signals": ["browser_download"],
                "minimum_signal_value_exclusive": 0,
            },
            "target": {
                "any_signals": [
                    "suspicious_execution",
                    "prefetch_execution",
                    "amcache_execution",
                    "execution_lolbin",
                    "execution_interpreter",
                ],
                "minimum_signal_value_exclusive": 0,
            },
            "emissions": [
                {
                    "name": "user_execution_after_download",
                    "value": 1,
                    "rule_id": "USER_EXECUTION_AFTER_DOWNLOAD",
                    "description": "Downloaded item was executed within a bounded window",
                    "confidence": "medium",
                },
                {
                    "name": "ingress_tool_transfer",
                    "value": 1,
                    "rule_id": "INGRESS_TOOL_TRANSFER",
                    "description": "Downloaded or retrieved tool was subsequently executed",
                    "confidence": "medium",
                },
            ],
            "evidence": [
                "filename",
                "download_timestamp",
                "execution_timestamp",
                "hostname",
            ],
        },
        "canonical_authentication": _expected_canonical_authentication(),
        "execution_context_classifier": _expected_execution_context_classifier(),
        "file_lifecycle": _expected_file_lifecycle(),
        "mft_timestomping": _expected_mft_timestomping(),
        "masquerading": {
            "stage": "contextual",
            "executor": "signal_gate",
            "enabled": True,
            "evidence_type": "direct",
            "inputs": {"signals": ["exec_system_binary_in_user_path"]},
            "conditions": {"match": "any", "minimum_value_exclusive": 0},
            "emissions": [
                {
                    "name": "masquerading",
                    "value": 1,
                    "rule_id": "MASQUERADING",
                    "description": (
                        "Trusted or system binary name executed from an unexpected "
                        "user-writable or suspicious path"
                    ),
                    "confidence": "medium",
                }
            ],
            "evidence": {
                "path": {
                    "resolver": "best_effort_file_path",
                    "fields": [
                        "filename",
                        "relative_path",
                        "display_name",
                        "pathspec",
                        "link_target",
                    ],
                },
                "command": {
                    "resolver": "first_nonempty",
                    "fields": ["actor_cmd"],
                    "max_chars": 240,
                },
                "hostname": {"resolver": "row_field", "field": "hostname"},
            },
        },
        "automated_collection": {
            "stage": "contextual",
            "executor": "signal_gate",
            "enabled": True,
            "evidence_type": "contextual",
            "inputs": {
                "signals": [
                    "sensitive_file_access",
                    "password_store_access",
                    "archive_created",
                    "large_archive_created",
                    "repeated_scheduled_exec",
                ]
            },
            "conditions": {
                "match": "all",
                "minimum_value_exclusive": 0,
                "groups": [
                    {
                        "match": "any",
                        "signals": [
                            "sensitive_file_access",
                            "password_store_access",
                        ],
                    },
                    {
                        "match": "any",
                        "signals": [
                            "archive_created",
                            "large_archive_created",
                            "repeated_scheduled_exec",
                        ],
                    },
                ],
            },
            "emissions": [
                {
                    "name": "automated_collection",
                    "value": 1,
                    "rule_id": "AUTOMATED_COLLECTION",
                    "description": (
                        "Sensitive access combined with archiving or repeated "
                        "scheduled execution suggests automated collection"
                    ),
                    "confidence": "low",
                }
            ],
            "evidence": {
                "hostname": {"resolver": "row_field", "field": "hostname"},
                "path": {
                    "resolver": "best_effort_file_path",
                    "fields": [
                        "filename",
                        "relative_path",
                        "display_name",
                        "pathspec",
                        "link_target",
                    ],
                },
            },
        },
        "canonical_persistence_projection": _expected_signal_projection(
            stage="contextual",
            projections=[
                (
                    [
                        "persistence_service",
                        "persistence_scheduled_task",
                        "persistence_runkey",
                        "systemd_service_persistence",
                        "authorized_keys_persistence",
                        "authorized_keys_root_persistence",
                    ],
                    "persistence_mechanism",
                    "PERSISTENCE_MECHANISM",
                    PERSISTENCE_PROJECTION_DESCRIPTION,
                ),
                (
                    ["persistence_service", "systemd_service_persistence"],
                    "persistence_service_install",
                    "PERSISTENCE_SERVICE_INSTALL",
                    PERSISTENCE_PROJECTION_DESCRIPTION,
                ),
                (
                    ["persistence_scheduled_task"],
                    "persistence_scheduled",
                    "PERSISTENCE_SCHEDULED",
                    PERSISTENCE_PROJECTION_DESCRIPTION,
                ),
                (
                    ["persistence_runkey"],
                    "persistence_registry",
                    "PERSISTENCE_REGISTRY",
                    PERSISTENCE_PROJECTION_DESCRIPTION,
                ),
                (
                    [
                        "account_or_group_change",
                        "authorized_keys_persistence",
                        "authorized_keys_root_persistence",
                    ],
                    "identity_persistence_change",
                    "IDENTITY_PERSISTENCE_CHANGE",
                    (
                        "Canonical identity persistence signal derived from broader "
                        "account/group change provenance"
                    ),
                ),
            ],
        ),
        "canonical_transfer_projection": _expected_signal_projection(
            stage="contextual",
            projections=[
                (
                    ["large_archive_created", "archive_created"],
                    "staging_archive",
                    "STAGING_ARCHIVE",
                    TRANSFER_PROJECTION_DESCRIPTION,
                ),
                (
                    ["data_transfer_tool_exec"],
                    "transfer_execution",
                    "TRANSFER_EXECUTION",
                    TRANSFER_PROJECTION_DESCRIPTION,
                ),
                (
                    ["large_http_transfer"],
                    "transfer_large_http",
                    "TRANSFER_LARGE_HTTP",
                    TRANSFER_PROJECTION_DESCRIPTION,
                ),
            ],
        ),
        "canonical_transfer_post_temporal_projection": _expected_signal_projection(
            stage="temporal",
            projections=[
                (
                    ["staging_then_transfer"],
                    "transfer_exfiltration_pattern",
                    "TRANSFER_EXFILTRATION_PATTERN",
                    TRANSFER_PROJECTION_DESCRIPTION,
                ),
                (
                    ["cross_border_transfer"],
                    "transfer_cross_border",
                    "TRANSFER_CROSS_BORDER",
                    TRANSFER_PROJECTION_DESCRIPTION,
                ),
                (
                    ["sensitive_data_staged", "archive_after_sensitive_access"],
                    "transfer_sensitive_staging",
                    "TRANSFER_SENSITIVE_STAGING",
                    TRANSFER_PROJECTION_DESCRIPTION,
                ),
            ],
        ),
        "ransomware_impact": {
            "stage": "temporal",
            "executor": "temporal_context_branches",
            "enabled": True,
            "evidence_type": "contextual",
            "lookback": "2h",
            "window_bounds": "closed",
            "key": {"scope": "deadbox_global"},
            "emit_on": "source",
            "source": {
                "any_signals": [
                    "mass_file_modification",
                    "ransomware_extension_burst",
                    "yara_ransomware",
                    "av_ransomware",
                ],
                "minimum_signal_value_exclusive": 0,
            },
            "branches": {
                "prior_support": {
                    "direction": "before_or_same",
                    "any_signals": [
                        "defender_disabled",
                        "inhibit_system_recovery",
                        "suspicious_execution",
                    ],
                    "minimum_signal_value_exclusive": 0,
                    "description": (
                        "Ransomware-like activity followed defense impairment, "
                        "recovery inhibition, or suspicious execution within a "
                        "bounded window"
                    ),
                },
                "ransom_note": {
                    "direction": "same_or_after",
                    "path": {
                        "resolver": "best_effort_file_path",
                        "fields": list(TEMPORAL_ARTIFACT_FIELDS),
                    },
                    "basename_contains": [
                        "readme",
                        "decrypt",
                        "recover",
                        "restore",
                        "how_to",
                        "ransom",
                    ],
                    "description": (
                        "Ransomware-like file-change activity was followed by likely "
                        "ransom-note creation within a bounded window"
                    ),
                },
            },
            "emissions": [
                {
                    "name": "ransomware_impact",
                    "value": 1,
                    "rule_id": "RANSOMWARE_IMPACT",
                    "description": (
                        "Ransomware-like activity has bounded supporting impact context"
                    ),
                    "confidence": "medium",
                }
            ],
            "evidence": {
                "hostname": {"resolver": "row_field", "field": "hostname"},
                "source_signals": {"resolver": "matched_source_signals"},
                "support_timestamp": {"resolver": "support_timestamp"},
                "ransom_note_timestamp": {"resolver": "ransom_note_timestamp"},
            },
        },
        "automated_exfiltration": {
            "stage": "temporal",
            "executor": "counted_signal_window",
            "enabled": True,
            "evidence_type": "contextual",
            "lookback": "30m",
            "window_bounds": "closed",
            "key": {"scope": "deadbox_global"},
            "emit_on": ["counted", "current_support"],
            "threshold": 2,
            "minimum_signal_value_exclusive": 0,
            "count": {
                "mode": "rows_once",
                "any_signals": [
                    "transfer_execution",
                    "data_transfer_tool_exec",
                    "staging_then_transfer",
                    "large_http_transfer",
                ],
            },
            "support": {
                "window_any_signals": [
                    "sensitive_file_access",
                    "password_store_access",
                ],
                "current_any_signals": [
                    "suspicious_execution",
                    "application_layer_protocol",
                    "staging_then_transfer",
                    "cross_border_transfer",
                ],
            },
            "emissions": [
                {
                    "name": "automated_exfiltration",
                    "value": 1,
                    "rule_id": "AUTOMATED_EXFILTRATION",
                    "description": (
                        "Repeated transfer behaviour co-occurred with sensitive "
                        "access, staging, or exfiltration context within a bounded "
                        "window"
                    ),
                    "confidence": "low",
                }
            ],
            "evidence": {
                "hostname": {"resolver": "row_field", "field": "hostname"},
                "count_in_window": {"resolver": "count_in_window"},
                "window_seconds": {"resolver": "window_seconds"},
            },
        },
        "credential_dump_collection": _expected_artifact_follow_on_policy(
            source_signals=[
                "credential_dumping",
                "yara_offensive_tool",
                "av_offensive_tool",
            ],
            labels=[
                "lsass.dmp",
                "lsass",
                "ntds.dit",
                "sam.save",
                "security.save",
                "system.save",
                "comsvcs.dll",
                "minidump",
                "procdump",
                "sekurlsa",
            ],
            output_signal="credential_dump_collection",
            rule_id="CREDENTIAL_DUMP_COLLECTION",
            description=(
                "Credential-dumping or offensive-tool evidence was followed by "
                "copying, archiving, or transfer activity within a bounded window"
            ),
        ),
        "password_store_exfil_chain": _expected_artifact_follow_on_policy(
            source_signals=["password_store_access"],
            labels=TEMPORAL_PASSWORD_LABELS,
            output_signal="password_store_exfil_chain",
            rule_id="PASSWORD_STORE_EXFIL_CHAIN",
            description=(
                "Password-store access was followed by copy, archive, or transfer "
                "activity within a bounded window"
            ),
        ),
        "webshell_activity": {
            "stage": "temporal",
            "executor": "signal_sequence",
            "enabled": True,
            "evidence_type": "contextual",
            "lookback": "30m",
            "ordering": "source_at_or_before_target",
            "window_bounds": "closed",
            "source_selection": "earliest_in_window",
            "emit_on": "target",
            "key": {"scope": "deadbox_global"},
            "source": {
                "any_signals": ["webshell_artifact"],
                "minimum_signal_value_exclusive": 0,
            },
            "target": {
                "any_signals": [
                    "web_exploitation_hint",
                    "exploit_public_facing_app",
                ],
                "minimum_signal_value_exclusive": 0,
            },
            "emissions": [
                {
                    "name": "webshell_activity",
                    "value": 1,
                    "rule_id": "WEBSHELL_ACTIVITY",
                    "description": (
                        "Web-shell-like file artefact and suspicious web request "
                        "activity co-occurred within a bounded window"
                    ),
                    "confidence": "high",
                }
            ],
            "evidence": {
                "hostname": {"resolver": "target_field", "field": "hostname"},
                "artifact_timestamp": {"resolver": "source_timestamp"},
                "request_timestamp": {"resolver": "target_timestamp"},
            },
        },
        "execution_lolbin": _expected_atomic_execution_gate(
            ["lolbin_windows", "lolbin_linux"],
            "execution_lolbin",
            "EXECUTION_LOLBIN",
        ),
        "execution_lolbin_suspicious_args": _expected_atomic_execution_gate(
            ["lolbin_suspicious_args"],
            "execution_lolbin_suspicious_args",
            "EXECUTION_LOLBIN_SUSPICIOUS_ARGS",
        ),
        "execution_interpreter": _expected_atomic_execution_gate(
            ["interpreter_exec_linux"],
            "execution_interpreter",
            "EXECUTION_INTERPRETER",
        ),
        "execution_scheduled": _expected_atomic_execution_gate(
            ["scheduled_exec"],
            "execution_scheduled",
            "EXECUTION_SCHEDULED",
        ),
        "execution_privileged_scheduled": _expected_atomic_execution_gate(
            ["privileged_scheduled_exec"],
            "execution_privileged_scheduled",
            "EXECUTION_PRIVILEGED_SCHEDULED",
        ),
        "suspicious_execution": _expected_atomic_execution_gate(
            [
                "interpreter_exec_linux",
                "lolbin_windows",
                "lolbin_linux",
                "lolbin_suspicious_args",
                "scheduled_exec",
                "privileged_scheduled_exec",
                "data_transfer_tool_exec",
            ],
            "suspicious_execution",
            "SUSPICIOUS_EXECUTION",
            description=(
                "Suspicious execution family derived from execution-related "
                "atomic detections"
            ),
            confidence="medium",
        ),
    },
}


class ChronoSiftV231DetectorPolicyTest(unittest.TestCase):
    def _engine(self, rules=None, weights=None):
        rules_doc = deepcopy(BASE_RULES if rules is None else rules)
        weights_doc = deepcopy(BASE_WEIGHTS if weights is None else weights)
        return ChronoSiftEngine(
            rules_doc,
            weights_doc,
            yara_metadata_path=BASE_YARA_PATH,
        )

    @staticmethod
    def _systemd_config(rules):
        return rules["detector_policy"]["detectors"]["systemd_service_persistence"]

    @staticmethod
    def _download_config(rules):
        return rules["detector_policy"]["detectors"]["download_to_execution"]

    @staticmethod
    def _clamav_config(rules):
        return rules["detector_policy"]["detectors"]["clamav_classification"]

    @staticmethod
    def _yara_config(rules):
        return rules["detector_policy"]["detectors"]["yara_classification"]

    @staticmethod
    def _correlation_config(rules):
        return rules["detector_policy"]["detectors"]["referenced_file_correlation"]

    @staticmethod
    def _web_request_config(rules):
        return rules["detector_policy"]["detectors"]["web_request_classification"]

    @staticmethod
    def _webshell_artifact_config(rules):
        return rules["detector_policy"]["detectors"]["webshell_artifact"]

    @staticmethod
    def _web_upload_chain_config(rules):
        return rules["detector_policy"]["detectors"]["web_upload_execution_chain"]

    @staticmethod
    def _masquerading_config(rules):
        return rules["detector_policy"]["detectors"]["masquerading"]

    @staticmethod
    def _automated_collection_config(rules):
        return rules["detector_policy"]["detectors"]["automated_collection"]

    @staticmethod
    def _ransomware_config(rules):
        return rules["detector_policy"]["detectors"]["ransomware_impact"]

    @staticmethod
    def _automated_exfiltration_config(rules):
        return rules["detector_policy"]["detectors"]["automated_exfiltration"]

    @staticmethod
    def _credential_collection_config(rules):
        return rules["detector_policy"]["detectors"]["credential_dump_collection"]

    @staticmethod
    def _password_store_exfil_config(rules):
        return rules["detector_policy"]["detectors"]["password_store_exfil_chain"]

    @staticmethod
    def _webshell_config(rules):
        return rules["detector_policy"]["detectors"]["webshell_activity"]

    @staticmethod
    def _detector_config(rules, detector_id):
        return rules["detector_policy"]["detectors"][detector_id]

    @staticmethod
    def _apply_systemd(engine, rows):
        index = pd.date_range("2024-06-16T10:00:00Z", periods=len(rows), freq="min")
        frame = pd.DataFrame(rows, index=index)
        signal_map = {}
        explain_map = {}
        engine._apply_systemd_service_persistence_sparse(
            frame, signal_map, explain_map
        )
        return frame, signal_map, explain_map

    @staticmethod
    def _download_frame(gap="5m"):
        start = pd.Timestamp("2024-06-16T12:00:00Z")
        index = pd.DatetimeIndex([start, start + pd.Timedelta(gap)])
        return pd.DataFrame(
            [
                {"filename": " Payload.EXE ", "hostname": "victim1"},
                {"relative_path": "/tmp/payload.exe", "hostname": "victim1"},
            ],
            index=index,
        )

    @staticmethod
    def _apply_download(engine, frame, source_signal, target_signal):
        signal_map = {0: {source_signal: 1.0}, 1: {target_signal: 1.0}}
        explain_map = {0: [], 1: []}
        engine._apply_deadbox_temporal_composites_sparse(frame, signal_map, explain_map)
        return signal_map, explain_map

    @staticmethod
    def _apply_temporal_policies(engine, frame, signal_map):
        explain_map = {row_i: [] for row_i in range(len(frame))}
        engine._apply_deadbox_temporal_composites_sparse(
            frame,
            signal_map,
            explain_map,
        )
        return signal_map, explain_map

    @staticmethod
    def _apply_contextual_signal_adjustments(engine, rows, signal_map):
        frame = pd.DataFrame(
            rows,
            index=pd.date_range(
                "2024-06-16T22:40:00Z", periods=len(rows), freq="min"
            ),
        )
        explain_map = {}
        engine._apply_ordered_signal_adjustments_sparse(
            frame,
            signal_map,
            explain_map,
            None,
            detector_id="contextual_signal_adjustments",
        )
        return signal_map, explain_map

    def test_baseline_policy_is_present_and_exactly_preserves_the_migrated_contract(self):
        self.assertTrue(BASE_YARA_PATH.strip())
        self.assertIn("detector_policy", BASE_RULES)
        baseline_legacy_subset = deepcopy(BASE_RULES["detector_policy"])
        baseline_legacy_subset["detectors"].pop("yara_classification")
        baseline_legacy_subset["detectors"].pop("web_request_classification")
        baseline_legacy_subset["detectors"].pop("referenced_file_correlation")
        baseline_legacy_subset["detectors"].pop("webshell_artifact")
        baseline_legacy_subset["detectors"].pop("web_upload_execution_chain")
        baseline_legacy_subset["detectors"].pop("persistence_configuration")
        baseline_legacy_subset["detectors"].pop("direct_attack_semantics")
        baseline_legacy_subset["detectors"].pop("repeated_scheduled_execution")
        baseline_legacy_subset["detectors"].pop("contextual_signal_adjustments")
        baseline_legacy_subset["detectors"].pop("geographic_continuity")
        baseline_legacy_subset["detectors"].pop("impossible_travel")
        baseline_legacy_subset["detectors"].pop("ip_scope_continuity")
        self.assertEqual(
            set(baseline_legacy_subset),
            set(EXPECTED_DETECTOR_POLICY),
        )
        for policy_key, expected_value in EXPECTED_DETECTOR_POLICY.items():
            if policy_key == "detectors":
                continue
            self.assertEqual(
                baseline_legacy_subset[policy_key],
                expected_value,
                policy_key,
            )
        self.assertEqual(
            set(baseline_legacy_subset["detectors"]),
            set(EXPECTED_DETECTOR_POLICY["detectors"]),
        )
        for detector_id, expected_detector in EXPECTED_DETECTOR_POLICY[
            "detectors"
        ].items():
            self.assertEqual(
                baseline_legacy_subset["detectors"][detector_id],
                expected_detector,
                detector_id,
            )

        engine = self._engine()
        policy = engine.detector_policy
        self.assertEqual((policy.version, policy.mode), (1, "authoritative"))
        self.assertIsInstance(
            policy.systemd_service_persistence,
            MODULE.SystemdServicePersistencePolicy,
        )
        self.assertIsInstance(
            policy.download_to_execution,
            MODULE.DownloadExecutionPolicy,
        )
        self.assertEqual(len(policy.detectors), 35)
        web = policy.web_request_classification
        self.assertIsInstance(web, MODULE.WebRequestClassifierPolicy)
        self.assertTrue(web.enabled)
        self.assertEqual(web.indicators.decode_rounds, 2)
        self.assertEqual(
            tuple(pattern.name for pattern in web.indicators.sqli_patterns),
            (
                "union_select",
                "schema_enumeration",
                "database_function",
                "file_access",
                "time_delay",
                "error_based",
                "stacked_query",
                "boolean_tautology",
                "ordered_probe",
                "inline_subquery",
            ),
        )
        self.assertEqual(web.upload.upload_methods, frozenset({"POST", "PUT", "PATCH"}))
        self.assertEqual(
            web.upload.filename_extension_admission,
            "nonempty_suffix",
        )
        self.assertEqual(web.upload.mime_value_pairing, "exactly_one")
        self.assertEqual(
            tuple(branch.branch_id for branch in web.upload.mime_mismatch.branches),
            (
                "image_extension_non_image_content_type",
                "executable_extension_image_content_type",
            ),
        )
        self.assertIn(
            "command_injection",
            web.outcomes.attempt_when.indicators_any,
        )
        self.assertEqual(
            web.outcomes.attempt_when.indicator_prefixes_any,
            ("sqli:",),
        )
        self.assertEqual(
            web.outcomes.selection.ranks,
            {"observed": 0, "attempt": 1, "probable_success": 2},
        )
        self.assertEqual(web.sqli.baseline_key_fields, ("host", "method", "endpoint"))
        self.assertEqual(web.sqli.baseline_scope, "partition")
        self.assertIsNone(web.sqli.baseline_lookback)
        self.assertEqual(web.sqli.baseline_statistic, "median")
        self.assertEqual(web.sqli.threshold_combine, "maximum")
        self.assertEqual(
            web.sqli.threshold_terms,
            ("response_minimum", "baseline_ratio", "baseline_delta"),
        )
        self.assertEqual(
            web.sqli.decisions_by_semantic["probable_success"].require_all,
            frozenset(
                {
                    "indicators", "successful_response", "response_bytes",
                    "threshold_exceeded",
                }
            ),
        )
        self.assertEqual(
            tuple(emission.name for emission in web.emissions),
            (
                "web_sqli_attempt",
                "web_sqli_response_anomaly",
                "web_sqli_probable_success",
                "exploit_public_facing_app",
            ),
        )

        self.assertEqual(
            tuple(branch.branch_id for branch in web.exploit_branches),
            ("executable_upload", "exploit_syntax", "configured_hint"),
        )
        self.assertEqual(len(web.policy_digest), 64)
        correlation = policy.referenced_file_correlation
        self.assertIsInstance(
            correlation,
            MODULE.ReferencedFileCorrelationPolicy,
        )
        self.assertTrue(correlation.enabled)
        self.assertEqual(correlation.basename_fallback, "relative_only")
        self.assertEqual(
            correlation.web_outcome_merge.merge("probable_success", "attempt"),
            "probable_success",
        )
        self.assertEqual(
            correlation.web_outcome_merge.merge("attempt", "confirmed_follow_on"),
            "confirmed_follow_on",
        )
        self.assertEqual(
            tuple(correlation.propagation),
            ("yara", "av", "luhn"),
        )
        self.assertEqual(
            tuple(branch.branch_id for branch in correlation.web_branches),
            (
                "file_access",
                "malicious_file_access",
                "sensitive_file_download",
                "malicious_file_upload",
                "confirmed_webshell_access",
            ),
        )
        self.assertEqual(len(correlation.mapping_outputs), 6)
        self.assertEqual(len(correlation.mapping_branches), 6)
        self.assertEqual(len(correlation.policy_digest), 64)

        artifact = policy.webshell_artifact
        self.assertIsInstance(artifact, MODULE.WebshellArtifactPolicy)
        self.assertTrue(artifact.enabled)
        self.assertEqual(
            artifact.path_fields,
            ("filename", "relative_path", "display_name", "pathspec", "link_target"),
        )
        self.assertEqual(
            artifact.script_extensions,
            frozenset(
                {
                    ".php", ".phtml", ".php3", ".php4", ".php5", ".asp",
                    ".aspx", ".ashx", ".jsp", ".jspx", ".cgi", ".pl",
                }
            ),
        )
        self.assertEqual(artifact.support_match, "any")
        self.assertEqual(
            artifact.support_signals,
            frozenset({"referenced_file_av_hit", "referenced_file_yara_hit"}),
        )
        self.assertEqual(artifact.emission.name, "webshell_artifact")
        self.assertEqual(artifact.emission.rule_id, "WEBSHELL_ARTIFACT")

        systemd = policy.systemd_service_persistence
        self.assertTrue(systemd.enabled)
        self.assertEqual(systemd.branch_mode, "first_match")
        self.assertEqual(
            systemd.branch_order, ("artifact_change", "command_activity")
        )
        self.assertEqual(
            systemd.path_fields,
            ("filename", "relative_path", "display_name", "pathspec", "link_target"),
        )
        self.assertEqual(systemd.timestamp_field, "timestamp_desc")
        self.assertEqual(systemd.text_fields, ("actor_cmd", "command_line", "message"))
        self.assertEqual(systemd.first_existing_text_fields, ("actor_url", "url"))
        self.assertEqual(systemd.artifact.timestamp_kinds, frozenset({"create", "modify", "delete"}))
        self.assertEqual(
            systemd.artifact.conditions.any_all,
            (frozenset({"artifact_path", "unit_extension", "timestamp_kind"}),),
        )
        self.assertEqual(
            systemd.command.persistent_tokens,
            ("systemctl enable", "systemctl link", "systemctl preset", "daemon-reload"),
        )
        self.assertEqual(systemd.emission.name, "systemd_service_persistence")
        self.assertEqual(systemd.emission.value, 1.0)
        self.assertEqual(systemd.emission.rule_id, "SYSTEMD_SERVICE_PERSISTENCE")

        download = policy.download_to_execution
        self.assertTrue(download.enabled)
        self.assertEqual(download.lookback, timedelta(hours=2))
        self.assertEqual(download.ordering, "source_at_or_before_target")
        self.assertEqual(download.window_bounds, "closed")
        self.assertEqual(download.source_selection, "earliest_in_window")
        self.assertEqual(download.key_scope, "deadbox_global")
        self.assertEqual(download.host_field, "hostname")
        self.assertEqual(download.source_signals, frozenset({"browser_download"}))
        self.assertEqual(
            download.target_signals,
            frozenset(
                {
                    "suspicious_execution",
                    "prefetch_execution",
                    "amcache_execution",
                    "execution_lolbin",
                    "execution_interpreter",
                }
            ),
        )
        self.assertEqual(
            tuple(emission.name for emission in download.emissions),
            ("user_execution_after_download", "ingress_tool_transfer"),
        )

        authentication = policy.canonical_authentication
        self.assertIsInstance(authentication, MODULE.CanonicalAuthenticationPolicy)
        self.assertTrue(authentication.enabled)
        self.assertEqual(
            (
                authentication.outcome_field,
                authentication.protocol_field,
                authentication.direction_field,
                authentication.logon_type_field,
                authentication.message_field,
                authentication.authentication_package_field,
            ),
            (
                "auth_outcome",
                "auth_protocol",
                "auth_direction",
                "logon_type",
                "message",
                "authentication_package",
            ),
        )
        self.assertEqual(
            authentication.success_sources,
            frozenset({"auth_success_generic", "ssh_success", "rdp_success"}),
        )
        self.assertEqual(
            authentication.failure_sources,
            frozenset({"auth_fail_generic", "ssh_fail", "rdp_fail"}),
        )
        self.assertEqual(
            (authentication.success_value, authentication.failure_value),
            ("success", "failure"),
        )
        self.assertEqual(authentication.outcome_source_match, "any")
        self.assertEqual(authentication.conflict_resolution, "allow_both")
        self.assertEqual(authentication.remote_direction_values, frozenset({"remote"}))
        self.assertEqual(
            authentication.remote_protocol_values,
            frozenset({"ssh", "rdp", "windows-network"}),
        )
        self.assertEqual(
            authentication.remote_interactive_logon_types,
            frozenset({"10"}),
        )
        self.assertEqual(authentication.remote_shell_protocol_values, frozenset({"ssh"}))
        self.assertEqual(authentication.invalid_user_tokens, ("invalid user", "unknown user"))
        self.assertEqual(authentication.new_credentials_logon_types, frozenset({"9"}))
        self.assertEqual(authentication.service_logon_types, frozenset({"4", "5"}))
        self.assertEqual(authentication.ntlm_authentication_packages, frozenset({"ntlm"}))
        self.assertTrue(authentication.lateral_include_remote)
        self.assertEqual(authentication.lateral_logon_types, frozenset({"3", "10"}))
        self.assertEqual(authentication.lateral_minimum_matches, 2)
        self.assertEqual(authentication.eligibility.require_all, frozenset())
        self.assertEqual(
            authentication.eligibility.require_any,
            frozenset({"success", "failure"}),
        )
        self.assertEqual(authentication.eligibility.exclude_any, frozenset())
        self.assertEqual(
            authentication.decisions_by_semantic[
                "remote_interactive_success"
            ].require_all,
            frozenset({"success", "remote", "remote_interactive"}),
        )
        self.assertEqual(authentication.evidence, ("derived_from",))
        self.assertEqual(
            tuple(authentication.emissions_by_semantic),
            (
                "success",
                "failure",
                "remote_success",
                "remote_failure",
                "local_success",
                "local_failure",
                "remote_interactive_success",
                "remote_shell_success",
                "invalid_user",
                "new_credentials_logon",
                "service_logon",
                "ntlm_remote",
                "lateral_movement",
            ),
        )
        self.assertEqual(
            tuple(emission.name for emission in authentication.emissions),
            (
                "auth_success",
                "auth_failure",
                "auth_remote_success",
                "auth_remote_failure",
                "auth_local_success",
                "auth_local_failure",
                "auth_remote_interactive_success",
                "auth_remote_shell_success",
                "auth_invalid_user",
                "auth_newcredentials_logon",
                "auth_service_logon",
                "auth_ntlm_remote",
                "lateral_movement_indicator",
            ),
        )

        execution_context = policy.execution_context_classifier
        self.assertIsInstance(
            execution_context,
            MODULE.ExecutionContextClassifierPolicy,
        )
        self.assertTrue(execution_context.enabled)
        self.assertEqual(
            execution_context.path_fields,
            (
                "image_path", "new_process_name", "file_path", "filename",
                "relative_path", "display_name", "pathspec", "path",
            ),
        )
        self.assertEqual(
            execution_context.command_fields,
            ("actor_cmd", "command_line", "command", "message"),
        )
        self.assertEqual(
            execution_context.actor_fields,
            ("actor_principal", "actor_user"),
        )
        self.assertEqual(
            execution_context.temporary_path_tokens,
            (
                "/tmp/", "/var/tmp/", "/dev/shm/", "/temp/", "%temp%",
                "/windows/temp/", "/appdata/local/temp/",
            ),
        )
        self.assertEqual(
            execution_context.system_binary_names,
            frozenset({"svchost.exe", "lsass.exe", "explorer.exe", "sshd", "bash"}),
        )
        self.assertEqual(
            execution_context.decisions_by_semantic[
                "suspicious_path"
            ].exclude_any,
            frozenset({"temporary_path", "user_writable_path"}),
        )
        self.assertEqual(execution_context.compiler_names, frozenset({"gcc", "cc", "make"}))
        self.assertEqual(
            execution_context.shell_names,
            frozenset({"sh", "bash", "cmd", "cmd.exe", "powershell", "pwsh"}),
        )
        self.assertEqual(
            execution_context.network_tool_names,
            frozenset({"nc", "netcat", "ncat", "socat", "curl", "wget", "ftp", "scp", "sftp"}),
        )
        self.assertEqual(
            execution_context.archive_tool_names,
            frozenset({"tar", "zip", "7z", "rar", "gzip"}),
        )
        self.assertEqual(
            execution_context.privileged_actors,
            frozenset({"root", "administrator", "admin"}),
        )
        self.assertEqual(
            execution_context.suid_pattern.pattern,
            (
                r"(?i)(?:chmod\s+4[0-7]{3}|chmod\s+u\+s|setuid|setgid|"
                r"chown\s+root(?::root)?|suid)"
            ),
        )
        self.assertEqual(
            tuple(execution_context.emissions_by_semantic),
            (
                "from_tmp",
                "from_user_writable",
                "suspicious_path",
                "system_binary_in_user_path",
                "compiler_activity",
                "shell_spawn",
                "network_tool",
                "archive_tool",
                "privileged_context",
                "new_suid_binary",
            ),
        )
        self.assertEqual(
            execution_context.evidence,
            ("path", "command", "actor_user", "derived_from"),
        )

        lifecycle = policy.file_lifecycle
        self.assertIsInstance(lifecycle, MODULE.FileLifecyclePolicy)
        self.assertTrue(lifecycle.enabled)
        self.assertEqual(lifecycle.path_fields, tuple(TEMPORAL_ARTIFACT_FIELDS))
        self.assertEqual(
            (
                lifecycle.timestamp_field,
                lifecycle.host_field,
                lifecycle.parser_field,
                lifecycle.message_field,
                lifecycle.file_size_field,
                lifecycle.allocation_field,
            ),
            (
                "timestamp_desc", "hostname", "parser", "message", "file_size",
                "is_allocated",
            ),
        )
        self.assertEqual(
            lifecycle.timestamp_kind_priority,
            ("create", "delete", "modify", "access"),
        )
        self.assertEqual(
            lifecycle.timestamp_kind_tokens,
            {
                "create": ("create", "creation", "birth"),
                "delete": ("delet",),
                "modify": ("modif", "change", "content", "mtime"),
                "access": ("access", "open", "atime"),
            },
        )
        self.assertIn("/var/www/", lifecycle.web_root_tokens)
        self.assertIn("/windows/system32/config/sam", lifecycle.sensitive_path_tokens)
        self.assertEqual(
            lifecycle.database_dump_name_tokens,
            ("dump", "mysqldump", "pg_dump", "sqlite dump"),
        )
        self.assertIn("/softwaredistribution/", lifecycle.excluded_update_path_tokens)
        self.assertEqual(
            lifecycle.web_script_extensions,
            frozenset(
                {
                    ".php", ".phtml", ".php3", ".php4", ".php5", ".asp",
                    ".aspx", ".ashx", ".jsp", ".jspx", ".cgi", ".pl",
                }
            ),
        )
        self.assertEqual(
            lifecycle.archive_extensions,
            frozenset({".zip", ".7z", ".rar", ".tar", ".gz", ".tgz", ".bz2", ".xz"}),
        )
        self.assertEqual(lifecycle.suspicious_temp_basename_tokens, ("tmp", "temp"))
        self.assertEqual(
            lifecycle.ransomware_extension_suffixes[:3],
            (".locked", ".lockbit", ".encrypted"),
        )
        self.assertEqual(
            lifecycle.row_decisions_by_semantic["deleted"],
            MODULE.FileLifecycleRowDecisionPolicy(
                match="any",
                timestamp_kinds=frozenset({"delete"}),
                derived_predicates=frozenset({"unallocated_with_extension"}),
            ),
        )
        self.assertEqual(lifecycle.short_lived.lookback, timedelta(hours=2))
        self.assertEqual(lifecycle.short_lived.key_fields, ("host", "path"))
        self.assertEqual(
            lifecycle.short_lived.conditions.any_all,
            (
                frozenset({"source_suspicious_web"}),
                frozenset({"target_suspicious_web"}),
                frozenset(
                    {
                        "target_web_script_extension",
                        "target_suspicious_temp_basename",
                    }
                ),
            ),
        )
        self.assertEqual(
            (
                lifecycle.mass_modification.lookback,
                lifecycle.mass_modification.threshold,
            ),
            (timedelta(minutes=10), 25),
        )
        self.assertEqual(
            (
                lifecycle.ransomware_burst.lookback,
                lifecycle.ransomware_burst.threshold,
            ),
            (timedelta(minutes=15), 6),
        )
        self.assertEqual(
            lifecycle.weight_aware_semantics,
            frozenset({"created", "modified", "deleted"}),
        )
        self.assertEqual(
            tuple(lifecycle.emissions_by_semantic),
            (
                "created", "modified", "deleted", "web_executable_created",
                "archive_created", "database_dump_candidate", "defacement_candidate",
                "sensitive_file_access", "short_lived_file",
                "mass_file_modification", "ransomware_extension_burst",
            ),
        )
        self.assertEqual(
            lifecycle.evidence_by_semantic["mass_file_modification"],
            ("host", "directory", "window_seconds", "count_in_window"),
        )

        timestomping = policy.mft_timestomping
        self.assertIsInstance(timestomping, MODULE.MftTimestompingPolicy)
        self.assertTrue(timestomping.enabled)
        self.assertEqual(timestomping.path_fields, tuple(TEMPORAL_ARTIFACT_FIELDS))
        self.assertEqual(
            (timestomping.parser_field, timestomping.timestamp_field),
            ("parser", "timestamp_desc"),
        )
        self.assertEqual(timestomping.parser_tokens, ("mft",))
        self.assertEqual(timestomping.creation_tokens, ("creation", "birth"))
        self.assertEqual(
            timestomping.standard_information_tokens,
            ("$standard_information", "$si", "standard information"),
        )
        self.assertEqual(
            timestomping.file_name_tokens,
            ("$file_name", "$fn", "file name"),
        )
        self.assertEqual(timestomping.minimum_delta, timedelta(seconds=1))
        self.assertIn("/winsxs/", timestomping.excluded_path_tokens)
        self.assertEqual(timestomping.bulk_group_threshold, 5)
        self.assertEqual(
            (timestomping.emission.name, timestomping.emission.value),
            ("timestomping", 1.0),
        )
        self.assertEqual(
            (
                timestomping.targeted_explanation.confidence,
                timestomping.targeted_explanation.evidence,
            ),
            ("high", ("path", "si_creation", "fn_creation", "delta_seconds")),
        )
        self.assertEqual(
            (
                timestomping.bulk_explanation.confidence,
                timestomping.bulk_explanation.evidence,
            ),
            (
                "low",
                (
                    "path", "si_creation", "fn_creation", "delta_seconds",
                    "bulk_extraction_dampened", "directory_hit_count",
                ),
            ),
        )

        masquerading = policy.masquerading
        self.assertIsInstance(masquerading, MODULE.SignalGatePolicy)
        self.assertEqual(
            masquerading.input_signals,
            frozenset({"exec_system_binary_in_user_path"}),
        )
        self.assertEqual(masquerading.minimum_value_exclusive, 0.0)

        automated_collection = policy.definition("automated_collection").payload
        self.assertIsInstance(automated_collection, MODULE.SignalGatePolicy)
        self.assertTrue(automated_collection.enabled)
        self.assertEqual(automated_collection.match, "all")
        self.assertEqual(automated_collection.minimum_value_exclusive, 0.0)
        self.assertEqual(
            automated_collection.input_signals,
            frozenset(
                {
                    "sensitive_file_access",
                    "password_store_access",
                    "archive_created",
                    "large_archive_created",
                    "repeated_scheduled_exec",
                }
            ),
        )
        self.assertEqual(
            tuple((group.match, group.signals) for group in automated_collection.input_groups),
            (
                (
                    "any",
                    frozenset({"sensitive_file_access", "password_store_access"}),
                ),
                (
                    "any",
                    frozenset(
                        {
                            "archive_created",
                            "large_archive_created",
                            "repeated_scheduled_exec",
                        }
                    ),
                ),
            ),
        )
        self.assertEqual(
            automated_collection.emissions[0].name,
            "automated_collection",
        )

        expected_projections = {
            "canonical_persistence_projection": (
                "contextual",
                (
                    (
                        frozenset(
                            {
                                "persistence_service",
                                "persistence_scheduled_task",
                                "persistence_runkey",
                                "systemd_service_persistence",
                                "authorized_keys_persistence",
                                "authorized_keys_root_persistence",
                            }
                        ),
                        "persistence_mechanism",
                        "PERSISTENCE_MECHANISM",
                    ),
                    (
                        frozenset(
                            {"persistence_service", "systemd_service_persistence"}
                        ),
                        "persistence_service_install",
                        "PERSISTENCE_SERVICE_INSTALL",
                    ),
                    (
                        frozenset({"persistence_scheduled_task"}),
                        "persistence_scheduled",
                        "PERSISTENCE_SCHEDULED",
                    ),
                    (
                        frozenset({"persistence_runkey"}),
                        "persistence_registry",
                        "PERSISTENCE_REGISTRY",
                    ),
                    (
                        frozenset(
                            {
                                "account_or_group_change",
                                "authorized_keys_persistence",
                                "authorized_keys_root_persistence",
                            }
                        ),
                        "identity_persistence_change",
                        "IDENTITY_PERSISTENCE_CHANGE",
                    ),
                ),
            ),
            "canonical_transfer_projection": (
                "contextual",
                (
                    (
                        frozenset({"large_archive_created", "archive_created"}),
                        "staging_archive",
                        "STAGING_ARCHIVE",
                    ),
                    (
                        frozenset({"data_transfer_tool_exec"}),
                        "transfer_execution",
                        "TRANSFER_EXECUTION",
                    ),
                    (
                        frozenset({"large_http_transfer"}),
                        "transfer_large_http",
                        "TRANSFER_LARGE_HTTP",
                    ),
                ),
            ),
            "canonical_transfer_post_temporal_projection": (
                "temporal",
                (
                    (
                        frozenset({"staging_then_transfer"}),
                        "transfer_exfiltration_pattern",
                        "TRANSFER_EXFILTRATION_PATTERN",
                    ),
                    (
                        frozenset({"cross_border_transfer"}),
                        "transfer_cross_border",
                        "TRANSFER_CROSS_BORDER",
                    ),
                    (
                        frozenset(
                            {"sensitive_data_staged", "archive_after_sensitive_access"}
                        ),
                        "transfer_sensitive_staging",
                        "TRANSFER_SENSITIVE_STAGING",
                    ),
                ),
            ),
        }
        for detector_id, (stage, expected_rules) in expected_projections.items():
            definition = policy.definition(detector_id)
            projection_policy = definition.payload
            self.assertEqual((definition.stage, definition.executor), (stage, "signal_projection"))
            self.assertIsInstance(projection_policy, MODULE.SignalProjectionPolicy)
            self.assertTrue(projection_policy.enabled)
            self.assertEqual(projection_policy.evidence_type, "direct")
            self.assertEqual(
                tuple((item.name, item.resolver) for item in projection_policy.evidence),
                (("derived_from", "matched_signals"),),
            )
            self.assertEqual(
                tuple(
                    (
                        rule.input_signals,
                        rule.emission.name,
                        rule.emission.rule_id,
                    )
                    for rule in projection_policy.projections
                ),
                expected_rules,
            )
            self.assertTrue(
                all(
                    rule.match == "any"
                    and rule.minimum_value_exclusive == 0.0
                    and rule.strength == "maximum_matched_times_emission_value"
                    and rule.emission.value == 1.0
                    and rule.emission.confidence == "high"
                    for rule in projection_policy.projections
                )
            )

        ransomware = policy.ransomware_impact
        self.assertIsInstance(ransomware, MODULE.RansomwareImpactPolicy)
        self.assertTrue(ransomware.enabled)
        self.assertEqual(ransomware.lookback, timedelta(hours=2))
        self.assertEqual(ransomware.key_scope, "deadbox_global")
        self.assertEqual(
            ransomware.source_signals,
            frozenset(
                {
                    "mass_file_modification",
                    "ransomware_extension_burst",
                    "yara_ransomware",
                    "av_ransomware",
                }
            ),
        )
        self.assertEqual(
            ransomware.support_signals,
            frozenset(
                {
                    "defender_disabled",
                    "inhibit_system_recovery",
                    "suspicious_execution",
                }
            ),
        )
        self.assertEqual(
            ransomware.note_path_fields,
            tuple(TEMPORAL_ARTIFACT_FIELDS),
        )
        self.assertEqual(
            ransomware.note_basename_tokens,
            ("readme", "decrypt", "recover", "restore", "how_to", "ransom"),
        )
        self.assertEqual(ransomware.emission.name, "ransomware_impact")
        self.assertEqual(
            tuple((item.name, item.resolver, item.fields) for item in ransomware.evidence),
            (
                ("hostname", "row_field", ("hostname",)),
                ("source_signals", "matched_source_signals", ()),
                ("support_timestamp", "support_timestamp", ()),
                ("ransom_note_timestamp", "ransom_note_timestamp", ()),
            ),
        )

        automated_exfiltration = policy.automated_exfiltration
        self.assertIsInstance(
            automated_exfiltration,
            MODULE.CountedSignalWindowPolicy,
        )
        self.assertEqual(automated_exfiltration.lookback, timedelta(minutes=30))
        self.assertEqual(automated_exfiltration.threshold, 2)
        self.assertEqual(
            automated_exfiltration.counted_signals,
            frozenset(
                {
                    "transfer_execution",
                    "data_transfer_tool_exec",
                    "staging_then_transfer",
                    "large_http_transfer",
                }
            ),
        )
        self.assertEqual(
            automated_exfiltration.window_support_signals,
            frozenset({"sensitive_file_access", "password_store_access"}),
        )
        self.assertEqual(
            automated_exfiltration.current_support_signals,
            frozenset(
                {
                    "suspicious_execution",
                    "application_layer_protocol",
                    "staging_then_transfer",
                    "cross_border_transfer",
                }
            ),
        )
        self.assertEqual(
            automated_exfiltration.emit_on_roles,
            frozenset({"counted", "current_support"}),
        )
        self.assertEqual(
            automated_exfiltration.emission.name,
            "automated_exfiltration",
        )

        credential_collection = policy.credential_dump_collection
        password_store_exfil = policy.password_store_exfil_chain
        for follow_on_policy in (credential_collection, password_store_exfil):
            self.assertIsInstance(
                follow_on_policy,
                MODULE.ArtifactFollowOnPolicy,
            )
            self.assertTrue(follow_on_policy.enabled)
            self.assertEqual(follow_on_policy.lookback, timedelta(hours=1))
            self.assertEqual(follow_on_policy.key_scope, "deadbox_global")
            self.assertEqual(
                follow_on_policy.path_fields,
                tuple(TEMPORAL_ARTIFACT_FIELDS),
            )
            self.assertEqual(follow_on_policy.text_fields, ("message", "command_line"))
            self.assertEqual(
                follow_on_policy.follow_on_signals,
                frozenset(TEMPORAL_FOLLOW_ON_SIGNALS),
            )
            self.assertTrue(follow_on_policy.allow_unlabelled_follow_on)
        self.assertEqual(
            credential_collection.source_signals,
            frozenset(
                {
                    "credential_dumping",
                    "yara_offensive_tool",
                    "av_offensive_tool",
                }
            ),
        )
        self.assertEqual(
            credential_collection.emission.name,
            "credential_dump_collection",
        )
        self.assertEqual(
            password_store_exfil.source_signals,
            frozenset({"password_store_access"}),
        )
        self.assertEqual(
            password_store_exfil.emission.name,
            "password_store_exfil_chain",
        )

        webshell = policy.webshell_activity
        self.assertIsInstance(webshell, MODULE.SignalSequencePolicy)
        self.assertEqual(webshell.lookback, timedelta(minutes=30))
        self.assertEqual(webshell.key_scope, "deadbox_global")
        self.assertEqual(webshell.key_field, "")
        self.assertEqual(webshell.source_signals, frozenset({"webshell_artifact"}))
        self.assertEqual(
            webshell.target_signals,
            frozenset({"web_exploitation_hint", "exploit_public_facing_app"}),
        )

        upload_chain = policy.web_upload_execution_chain
        self.assertIsInstance(upload_chain, MODULE.SignalSequencePolicy)
        self.assertEqual(upload_chain.lookback, timedelta(minutes=30))
        self.assertEqual(upload_chain.key_scope, "deadbox_global")
        self.assertEqual(
            upload_chain.source_signals,
            frozenset({"webshell_artifact"}),
        )
        self.assertEqual(
            upload_chain.target_signals,
            frozenset(
                {
                    "prefetch_execution",
                    "amcache_execution",
                    "suspicious_execution",
                    "execution_lolbin",
                    "execution_interpreter",
                }
            ),
        )
        self.assertEqual(upload_chain.target_context.match, "any")
        self.assertIn(".php", upload_chain.target_context.combined_text_contains)
        self.assertEqual(
            upload_chain.emissions[0].name,
            "web_upload_execution_chain",
        )

        atomic_definitions = {
            definition.detector_id: definition
            for definition in policy.definitions(stage="atomic")
        }
        self.assertEqual(
            set(atomic_definitions),
            {
                "clamav_classification",
                "yara_classification",
                "web_request_classification",
                "canonical_authentication",
                "execution_context_classifier",
                "execution_lolbin",
                "execution_lolbin_suspicious_args",
                "execution_interpreter",
                "execution_scheduled",
                "execution_privileged_scheduled",
                "suspicious_execution",
            },
        )
        classifier = policy.clamav_classification
        self.assertIsInstance(classifier, MODULE.ClamAVClassifierPolicy)
        self.assertTrue(classifier.enabled)
        self.assertEqual(classifier.default_category, "malware")
        self.assertEqual(len(classifier.category_tokens), 27)
        self.assertEqual(len(classifier.family_overrides), 28)
        self.assertEqual(len(classifier.policy_digest), 64)
        self.assertEqual(
            tuple(emission.name for emission in classifier.emissions),
            (
                "av_hit",
                "av_offensive_tool",
                "av_ransomware",
                "av_exploit",
                "av_malware",
                "av_pua",
                "av_webshell",
            ),
        )
        yara = policy.yara_classification
        self.assertIsInstance(yara, MODULE.YaraClassifierPolicy)
        self.assertTrue(yara.enabled)
        self.assertEqual(yara.metadata_path, "rules/yara-forge-rules-extended.yar")
        self.assertEqual(
            (yara.metadata_on_missing, yara.metadata_on_parse_error),
            ("name_only", "name_only"),
        )
        self.assertEqual(
            (yara.default_score, yara.default_quality),
            (75, 70),
        )
        self.assertEqual(
            (yara.unindexed_rule, yara.unindexed_score, yara.unindexed_quality),
            ("name_only", 0, 0),
        )
        self.assertEqual(yara.default_category, "malware")
        self.assertEqual(len(yara.classification_rules), 12)
        self.assertEqual(yara.policy_digest, EXPECTED_YARA_POLICY_DIGEST)
        self.assertEqual(
            tuple(rule.rule_id for rule in yara.classification_rules),
            (
                "tc_ransomware",
                "tc_malware",
                "tc_exploit",
                "ransomware_tag",
                "informational_certificate_tag",
                "informational_certificate_category",
                "certificate_name",
                "webshell_name",
                "offensive_tool_name",
                "ransomware_name",
                "apt_name",
                "exploit_name",
            ),
        )
        self.assertEqual(
            tuple(yara.categories),
            (
                "offensive_tool", "ransomware", "webshell", "apt",
                "exploit", "certificate", "malware",
            ),
        )
        self.assertFalse(
            yara.categories["certificate"].contributes_to_strength
        )
        self.assertTrue(
            all(
                category.contributes_to_strength
                for name, category in yara.categories.items()
                if name != "certificate"
            )
        )
        self.assertEqual(
            tuple(emission.name for emission in yara.emissions),
            (
                "yara_hit_strength",
                "yara_offensive_tool",
                "yara_ransomware",
                "yara_webshell",
                "yara_apt",
                "yara_exploit",
                "yara_certificate_blocklist",
                "yara_malware",
            ),
        )
        self.assertEqual(
            (
                yara.referenced_file_gate.minimum_score,
                yara.referenced_file_gate.minimum_quality,
                yara.referenced_file_gate.allow_unnamed,
            ),
            (75, 70, False),
        )
        self.assertNotIn(
            "certificate",
            yara.referenced_file_gate.categories,
        )
        self.assertTrue(
            all(
                definition.executor == "signal_gate"
                and isinstance(definition.payload, MODULE.SignalGatePolicy)
                for detector_id, definition in atomic_definitions.items()
                if detector_id not in {
                    "clamav_classification",
                    "yara_classification",
                    "web_request_classification",
                    "canonical_authentication",
                    "execution_context_classifier",
                }
            )
        )
        self.assertEqual(
            atomic_definitions["suspicious_execution"].payload.input_signals,
            frozenset(
                {
                    "interpreter_exec_linux",
                    "lolbin_windows",
                    "lolbin_linux",
                    "lolbin_suspicious_args",
                    "scheduled_exec",
                    "privileged_scheduled_exec",
                    "data_transfer_tool_exec",
                }
            ),
        )

    def test_rule_signal_merge_policy_is_typed_and_runtime_authoritative(self):
        engine = self._engine()
        self.assertEqual(
            engine.rule_signal_merge_policy,
            MODULE.RuleSignalMergePolicy(
                atomic_rules="maximum", temporal_rules="maximum"
            ),
        )
        frame = pd.DataFrame(
            [
                {
                    "parser": "winevt/security",
                    "event_identifier": "4624",
                    "logon_type": "10",
                    "message": "Logon success",
                }
            ],
            index=pd.DatetimeIndex([pd.Timestamp("2024-06-16T12:00:00Z")]),
        )
        maximum = engine.apply_atomic(frame, apply_profiling=False)
        maximum_signals = maximum.attrs["chronosift_sparse"]["signal_map"][0]
        self.assertEqual(maximum_signals["auth_success_generic"], 1.0)

        sum_rules = deepcopy(BASE_RULES)
        sum_rules["rule_signal_merge"]["atomic_rules"] = "sum"
        summed = self._engine(sum_rules).apply_atomic(
            frame.copy(), apply_profiling=False
        )
        summed_signals = summed.attrs["chronosift_sparse"]["signal_map"][0]
        self.assertEqual(summed_signals["auth_success_generic"], 2.0)

        temporal_rule = engine.temporal_rules[0]
        signal_map = {}
        explain_map = {}
        engine._temporal_emit_sparse(
            temporal_rule, signal_map, explain_map, 0, ("alice",)
        )
        engine._temporal_emit_sparse(
            temporal_rule, signal_map, explain_map, 0, ("alice",)
        )
        temporal_name = temporal_rule.emit_signals[0].name
        self.assertEqual(signal_map[0][temporal_name], 1.0)

        sum_rules = deepcopy(BASE_RULES)
        sum_rules["rule_signal_merge"]["temporal_rules"] = "sum"
        sum_engine = self._engine(sum_rules)
        sum_rule = sum_engine.temporal_rules[0]
        signal_map = {}
        explain_map = {}
        sum_engine._temporal_emit_sparse(
            sum_rule, signal_map, explain_map, 0, ("alice",)
        )
        sum_engine._temporal_emit_sparse(
            sum_rule, signal_map, explain_map, 0, ("alice",)
        )
        self.assertEqual(signal_map[0][sum_rule.emit_signals[0].name], 2.0)

    def test_rule_signal_merge_policy_is_strict(self):
        rules = deepcopy(BASE_RULES)
        del rules["rule_signal_merge"]
        with self.assertRaisesRegex(
            ValueError, r"rules configuration: missing required key.*rule_signal_merge"
        ):
            self._engine(rules)

        rules = deepcopy(BASE_RULES)
        rules["rule_signal_merge"]["atomic_rules"] = "replace"
        with self.assertRaisesRegex(
            ValueError,
            r"rule_signal_merge\.atomic_rules: expected one of maximum, sum",
        ):
            self._engine(rules)

    def test_generic_row_policies_are_typed_phased_and_own_their_output_inventory(self):
        engine = self._engine()
        expected = {
            "persistence_configuration": (
                MODULE.OrderedRowRulesPolicy,
                19,
                {
                    "cron_persistence",
                    "firewall_modified",
                    "group_policy_modified",
                    "winlogon_helper_persistence",
                    "com_hijack_persistence",
                    "service_configuration_changed",
                    "defender_disabled",
                    "account_created",
                    "privileged_account_created",
                },
            ),
            "repeated_scheduled_execution": (
                MODULE.GroupedSignalWindowPolicy,
                19,
                {"repeated_scheduled_exec"},
            ),
            "direct_attack_semantics": (
                MODULE.OrderedRowRulesPolicy,
                28,
                {
                    "authorized_keys_root_persistence",
                    "authorized_keys_persistence",
                    "inhibit_system_recovery",
                    "credential_dumping",
                    "password_store_access",
                    "file_and_directory_discovery",
                    "remote_system_discovery",
                    "system_owner_user_discovery",
                    "indicator_removal_on_host",
                    "service_stop",
                    "smb_admin_share",
                    "external_remote_service",
                    "alternate_auth_material",
                    "application_layer_protocol",
                    "account_access_removal",
                },
            ),
        }
        configured_outputs = MODULE._collect_emitted_signals_from_rules(BASE_RULES)
        for detector_id, (policy_type, phase, output_names) in expected.items():
            with self.subTest(detector_id=detector_id):
                definition = engine.detector_policy.definition(detector_id)
                self.assertIsInstance(definition.payload, policy_type)
                self.assertEqual(definition.payload.execution_phase, phase)
                self.assertEqual(
                    {emission.name for emission in definition.emissions},
                    output_names,
                )
                self.assertTrue(output_names <= configured_outputs)
                for emission in definition.emissions:
                    self.assertEqual(
                        engine.rule_emit_signals[emission.rule_id],
                        [emission.name],
                    )

    def test_ordered_row_predicate_and_emission_metadata_are_yaml_authoritative(self):
        rules = deepcopy(BASE_RULES)
        detector = self._detector_config(rules, "persistence_configuration")
        cron_rule = next(
            rule for rule in detector["ordered_rules"]
            if rule["id"] == "cron_path_change"
        )
        cron_rule["when"]["all"][0]["values"] = ["/configured-cron/"]
        cron_rule.update(
            {
                "description": "Configured cron policy matched",
                "confidence": "high",
            }
        )
        detector["emissions"]["cron_persistence"].update(
            {
                "value": 2,
                "rule_id": "CONFIGURED_CRON_POLICY",
                "description": "Configured cron emission",
                "confidence": "high",
            }
        )
        engine = self._engine(rules)
        frame = pd.DataFrame(
            [
                {
                    "filename": "/configured-cron/nightly",
                    "timestamp_desc": "Content Modification Time",
                },
                {
                    "filename": "/etc/crontab",
                    "timestamp_desc": "Content Modification Time",
                },
            ],
            index=pd.date_range("2024-06-16T21:00:00Z", periods=2, freq="min"),
        )
        signal_map = {}
        explain_map = {}

        engine._apply_ordered_row_rules_sparse(
            frame,
            signal_map,
            explain_map,
            None,
            detector_id="persistence_configuration",
        )

        self.assertEqual(signal_map[0]["cron_persistence"], 2.0)
        self.assertNotIn("cron_persistence", signal_map.get(1, {}))
        self.assertEqual(
            explain_map[0][0],
            {
                "rule_id": "CONFIGURED_CRON_POLICY",
                "detector_rule_id": "cron_path_change",
                "description": "Configured cron policy matched",
                "confidence": "high",
                "evidence_type": "direct",
                "signals": ["cron_persistence"],
                "evidence": {
                    "path": "/configured-cron/nightly",
                    "timestamp_desc": "Content Modification Time",
                },
            },
        )
        self.assertEqual(
            engine.rule_emit_signals["CONFIGURED_CRON_POLICY"],
            ["cron_persistence"],
        )
        self.assertNotIn("CRON_PERSISTENCE", engine.rule_emit_signals)

    def test_ordered_row_literals_preserve_meaningful_edge_whitespace(self):
        rules = deepcopy(BASE_RULES)
        detector = self._detector_config(rules, "direct_attack_semantics")
        recovery_rule = next(
            rule for rule in detector["ordered_rules"]
            if rule["id"] == "inhibit_recovery_command"
        )
        recovery_rule["when"]["values"] = [" configured marker "]
        engine = self._engine(rules)
        parsed_rule = next(
            rule for rule in engine.detector_policy.direct_attack_semantics.rules
            if rule.rule_id == "inhibit_recovery_command"
        )
        self.assertEqual(parsed_rule.predicate.values, (" configured marker ",))

        frame = pd.DataFrame(
            [
                {"actor_cmd": "prefix configured marker suffix"},
                {"actor_cmd": "configured marker"},
                {"actor_cmd": "prefixconfigured markersuffix"},
            ],
            index=pd.date_range("2024-06-16T21:10:00Z", periods=3, freq="min"),
        )
        signal_map = {}
        engine._apply_ordered_row_rules_sparse(
            frame,
            signal_map,
            {},
            None,
            detector_id="direct_attack_semantics",
        )
        self.assertEqual(signal_map[0]["inhibit_system_recovery"], 1.0)
        self.assertNotIn("inhibit_system_recovery", signal_map.get(1, {}))
        self.assertNotIn("inhibit_system_recovery", signal_map.get(2, {}))

    def test_ordered_row_same_policy_dependency_follows_declared_rule_order(self):
        engine = self._engine()
        frame = pd.DataFrame(
            [{
                "actor_cmd": r"copy \\server\admin$\payload.exe",
                "auth_outcome": "success",
                "auth_protocol": "windows-network",
            }],
            index=pd.DatetimeIndex([pd.Timestamp("2024-06-16T21:20:00Z")]),
        )
        signal_map = {}
        engine._apply_ordered_row_rules_sparse(
            frame,
            signal_map,
            {},
            None,
            detector_id="direct_attack_semantics",
        )
        self.assertEqual(signal_map[0]["smb_admin_share"], 1.0)
        self.assertEqual(signal_map[0]["external_remote_service"], 1.0)

        rules = deepcopy(BASE_RULES)
        ordered_rules = self._detector_config(
            rules, "direct_attack_semantics"
        )["ordered_rules"]
        consumer = next(
            rule for rule in ordered_rules
            if rule["id"] == "successful_windows_remote_service"
        )
        ordered_rules.remove(consumer)
        first_smb_producer = next(
            index for index, rule in enumerate(ordered_rules)
            if rule["emission"] == "smb_admin_share"
        )
        ordered_rules.insert(first_smb_producer, consumer)
        with self.assertRaisesRegex(
            ValueError,
            r"direct_attack_semantics\.ordered_rules\[14\]\.when: same-policy signal\(s\) are not produced by an earlier ordered rule: smb_admin_share",
        ):
            self._engine(rules)

    def test_grouped_signal_window_threshold_and_lookback_are_yaml_authoritative(self):
        index = pd.DatetimeIndex(
            [
                pd.Timestamp("2024-06-16T22:00:00Z"),
                pd.Timestamp("2024-06-16T22:04:00Z"),
                pd.Timestamp("2024-06-16T22:08:00Z"),
            ]
        )
        frame = pd.DataFrame(
            [
                {"hostname": "HOST1", "actor_cmd": "Nightly Job"},
                {"hostname": "HOST1", "actor_cmd": "Nightly Job"},
                {"hostname": "HOST1", "actor_cmd": "Nightly Job"},
            ],
            index=index,
        )
        source_signals = {
            row_i: {"scheduled_exec": 1.0} for row_i in range(len(frame))
        }
        baseline_signals = deepcopy(source_signals)
        self._engine()._apply_grouped_signal_window_sparse(
            frame,
            baseline_signals,
            {},
            detector_id="repeated_scheduled_execution",
        )
        self.assertEqual(baseline_signals[2]["repeated_scheduled_exec"], 1.0)

        configured_rules = deepcopy(BASE_RULES)
        configured = self._detector_config(
            configured_rules, "repeated_scheduled_execution"
        )
        configured["threshold"] = 2
        configured["lookback"] = "5m"
        configured_signals = deepcopy(source_signals)
        configured_explain = {}
        self._engine(configured_rules)._apply_grouped_signal_window_sparse(
            frame,
            configured_signals,
            configured_explain,
            detector_id="repeated_scheduled_execution",
        )
        self.assertEqual(configured_signals[1]["repeated_scheduled_exec"], 1.0)
        self.assertNotIn("repeated_scheduled_exec", configured_signals[2])
        self.assertEqual(
            configured_explain[1][0]["evidence"],
            {
                "hostname": "host1",
                "command": "nightly job",
                "count_in_window": 2,
                "window_seconds": 300,
            },
        )

        too_short_rules = deepcopy(configured_rules)
        self._detector_config(
            too_short_rules, "repeated_scheduled_execution"
        )["lookback"] = "3m"
        too_short_signals = deepcopy(source_signals)
        self._engine(too_short_rules)._apply_grouped_signal_window_sparse(
            frame,
            too_short_signals,
            {},
            detector_id="repeated_scheduled_execution",
        )
        for signals in too_short_signals.values():
            self.assertNotIn("repeated_scheduled_exec", signals)

    def test_disabling_generic_row_policies_suppresses_all_of_their_outputs(self):
        rules = deepcopy(BASE_RULES)
        for detector in rules["detector_policy"]["detectors"].values():
            if "enabled" in detector:
                detector["enabled"] = False
        engine = self._engine(rules)
        frame = pd.DataFrame(
            [
                {
                    "filename": "/etc/crontab",
                    "timestamp_desc": "Content Modification Time",
                    "actor_cmd": "vssadmin delete shadows",
                    "hostname": "host1",
                }
                for _ in range(3)
            ],
            index=pd.date_range("2024-06-16T22:20:00Z", periods=3, freq="min"),
        )
        signal_map = {
            row_i: {"scheduled_exec": 1.0} for row_i in range(len(frame))
        }
        explain_map = {}
        engine._apply_ordered_row_rules_sparse(
            frame,
            signal_map,
            explain_map,
            None,
            detector_id="persistence_configuration",
        )
        engine._apply_ordered_row_rules_sparse(
            frame,
            signal_map,
            explain_map,
            None,
            detector_id="direct_attack_semantics",
        )
        engine._apply_grouped_signal_window_sparse(
            frame,
            signal_map,
            explain_map,
            detector_id="repeated_scheduled_execution",
        )
        for signals in signal_map.values():
            self.assertEqual(signals, {"scheduled_exec": 1.0})
        self.assertEqual(explain_map, {})
        for rule_id in (
            "CRON_PERSISTENCE",
            "INHIBIT_SYSTEM_RECOVERY",
            "REPEATED_SCHEDULED_EXEC",
        ):
            self.assertNotIn(rule_id, engine.rule_emit_signals)

    def test_generic_row_policy_schema_errors_report_precise_config_paths(self):
        cases = (
            (
                "ordered policy key",
                "persistence_configuration",
                lambda config: config.update({"unexpected": True}),
                r"persistence_configuration: unknown key\(s\): unexpected",
            ),
            (
                "predicate key",
                "direct_attack_semantics",
                lambda config: config["ordered_rules"][2]["when"].update(
                    {"unexpected": True}
                ),
                r"direct_attack_semantics\.ordered_rules\[2\]\.when: unknown key\(s\): unexpected",
            ),
            (
                "grouped key",
                "repeated_scheduled_execution",
                lambda config: config["key"].update({"unexpected": True}),
                r"repeated_scheduled_execution\.key: unknown key\(s\): unexpected",
            ),
            (
                "grouped regex",
                "repeated_scheduled_execution",
                lambda config: config["key"].update({"message_regex": "["}),
                r"repeated_scheduled_execution\.key\.message_regex: invalid regular expression",
            ),
            (
                "fixed executor phase",
                "direct_attack_semantics",
                lambda config: config.update({"phase": 27}),
                r"direct_attack_semantics\.phase: expected fixed executor phase 28",
            ),
        )
        for label, detector_id, mutate, error_path in cases:
            with self.subTest(label=label):
                rules = deepcopy(BASE_RULES)
                mutate(self._detector_config(rules, detector_id))
                with self.assertRaisesRegex(ValueError, error_path):
                    self._engine(rules)

    def test_contextual_signal_adjustments_are_typed_phased_and_own_input_inventory(self):
        engine = self._engine()
        definition = engine.detector_policy.definition(
            "contextual_signal_adjustments"
        )
        policy = definition.payload

        self.assertEqual(
            (definition.stage, definition.executor),
            ("contextual", "ordered_signal_adjustments"),
        )
        self.assertIsInstance(policy, MODULE.OrderedSignalAdjustmentsPolicy)
        self.assertTrue(policy.enabled)
        self.assertEqual(policy.execution_phase, 35)
        self.assertEqual(policy.evidence_type, "contextual")
        self.assertEqual(definition.emissions, ())
        self.assertEqual(
            {
                name: (
                    input_policy.resolver,
                    input_policy.fields,
                    input_policy.normalise,
                )
                for name, input_policy in policy.inputs.items()
            },
            {
                "command": (
                    "concat",
                    ("actor_cmd", "command_line", "message"),
                    "none",
                ),
                "combined_text_lower": (
                    "concat",
                    ("actor_cmd", "command_line", "message"),
                    "lower",
                ),
                "command_path_lower": (
                    "concat",
                    ("actor_cmd", "command_line", "message"),
                    "path_lower",
                ),
            },
        )
        self.assertEqual(
            MODULE._detector_definition_required_fields(definition),
            {"actor_cmd", "command_line", "message"},
        )
        self.assertEqual(
            policy.external_input_signals,
            frozenset(
                {
                    "application_layer_protocol",
                    "credential_dumping",
                    "data_transfer_tool_exec",
                    "exec_archive_tool",
                    "exec_network_tool",
                    "exec_shell_spawn",
                    "execution_lolbin",
                    "file_and_directory_discovery",
                    "lolbin_linux",
                    "lolbin_suspicious_args",
                    "lolbin_windows",
                    "password_store_access",
                    "remote_system_discovery",
                    "sensitive_file_access",
                    "suspicious_execution",
                    "system_owner_user_discovery",
                    "transfer_execution",
                }
            ),
        )
        self.assertEqual(
            tuple(rule.rule_id for rule in policy.rules),
            (
                "DISCOVERY_RECLASSIFICATION",
                "BENIGN_ADMIN_QUERY_DAMPENING",
                "BENIGN_BACKUP_ARCHIVE_DAMPENING",
            ),
        )
        self.assertEqual(
            tuple(
                rule.conditions.minimum_value_exclusive
                for rule in policy.rules
            ),
            (0.0, 0.0, 0.0),
        )
        self.assertEqual(
            {
                name: (evidence.resolver, evidence.input_name)
                for name, evidence in policy.evidence.items()
            },
            {
                "command": ("input", "command"),
                "signals": ("changed_signals", ""),
                "dampened_signals": ("changed_signals", ""),
                "preserved_discovery_signals": (
                    "preserved_positive_signals",
                    "",
                ),
            },
        )

    def test_contextual_adjustment_predicate_and_metadata_are_yaml_authoritative(self):
        rules = deepcopy(BASE_RULES)
        detector = self._detector_config(
            rules, "contextual_signal_adjustments"
        )
        backup_rule = next(
            rule for rule in detector["ordered_rules"]
            if rule["id"] == "benign_backup_archive_dampening"
        )
        backup_rule["when"]["all"][1]["values"] = [
            "/configured-backup/"
        ]
        backup_rule["explanation"] = {
            "rule_id": "CONFIGURED_BACKUP_ADJUSTMENT",
            "description": "Configured backup adjustment matched",
            "confidence": "high",
        }
        engine = self._engine(rules)
        signal_map = {
            0: {"exec_archive_tool": 2.0},
            1: {"exec_archive_tool": 2.0},
        }

        signal_map, explain_map = self._apply_contextual_signal_adjustments(
            engine,
            [
                {
                    "actor_cmd": (
                        "tar -czf /configured-backup/nightly.tgz /srv/data"
                    )
                },
                {
                    "actor_cmd": "tar -czf /var/backups/nightly.tgz /srv/data"
                },
            ],
            signal_map,
        )

        self.assertEqual(signal_map[0]["exec_archive_tool"], 0.0)
        self.assertEqual(signal_map[1]["exec_archive_tool"], 2.0)
        self.assertEqual(
            explain_map[0],
            [
                {
                    "rule_id": "CONFIGURED_BACKUP_ADJUSTMENT",
                    "description": "Configured backup adjustment matched",
                    "confidence": "high",
                    "evidence_type": "contextual",
                    "evidence": {
                        "signals": "exec_archive_tool",
                        "command": (
                            "tar -czf /configured-backup/nightly.tgz /srv/data"
                        ),
                    },
                }
            ],
        )
        self.assertNotIn(1, explain_map)

    def test_contextual_signal_adjustment_disablement_is_authoritative(self):
        rules = deepcopy(BASE_RULES)
        self._detector_config(
            rules, "contextual_signal_adjustments"
        )["enabled"] = False
        engine = self._engine(rules)
        definition = engine.detector_policy.definition(
            "contextual_signal_adjustments"
        )
        signal_map = {
            0: {
                "remote_system_discovery": 1.0,
                "exec_network_tool": 1.0,
            }
        }

        signal_map, explain_map = self._apply_contextual_signal_adjustments(
            engine,
            [{"actor_cmd": "nslookup example.test"}],
            signal_map,
        )

        self.assertFalse(definition.payload.enabled)
        self.assertEqual(
            MODULE._detector_definition_required_fields(definition), set()
        )
        self.assertEqual(
            signal_map,
            {
                0: {
                    "remote_system_discovery": 1.0,
                    "exec_network_tool": 1.0,
                }
            },
        )
        self.assertEqual(explain_map, {})

    def test_contextual_signal_adjustment_minimum_is_yaml_authoritative(self):
        rules = deepcopy(BASE_RULES)
        detector = self._detector_config(
            rules, "contextual_signal_adjustments"
        )
        discovery_rule = next(
            rule
            for rule in detector["ordered_rules"]
            if rule["id"] == "discovery_reclassification"
        )
        discovery_rule["signal_conditions"][
            "minimum_value_exclusive"
        ] = 1
        engine = self._engine(rules)
        source_signals = {
            0: {
                "remote_system_discovery": 1.0,
                "exec_network_tool": 2.0,
            },
            1: {
                "remote_system_discovery": 2.0,
                "exec_network_tool": 1.0,
            },
            2: {
                "remote_system_discovery": 1.0,
                "file_and_directory_discovery": 2.0,
                "exec_network_tool": 2.0,
            },
        }

        adjusted, explained = self._apply_contextual_signal_adjustments(
            engine,
            [
                {"actor_cmd": "nslookup example.test"},
                {"actor_cmd": "nslookup example.test"},
                {"actor_cmd": "nslookup example.test"},
            ],
            deepcopy(source_signals),
        )

        self.assertEqual(adjusted[0], source_signals[0])
        self.assertEqual(adjusted[1], source_signals[1])
        self.assertEqual(adjusted[2]["exec_network_tool"], 0.0)
        self.assertEqual(
            explained[2][0]["evidence"]["preserved_discovery_signals"],
            "file_and_directory_discovery",
        )
        self.assertNotIn(0, explained)
        self.assertNotIn(1, explained)

    def test_contextual_adjustment_of_canonical_auth_is_not_restored(self):
        rules = deepcopy(BASE_RULES)
        detector = self._detector_config(
            rules, "contextual_signal_adjustments"
        )
        backup_rule = next(
            rule
            for rule in detector["ordered_rules"]
            if rule["id"] == "benign_backup_archive_dampening"
        )
        backup_rule["target_signals"] = ["auth_remote_success"]
        engine = self._engine(rules)
        frame = pd.DataFrame(
            [
                {
                    "actor_cmd": "tar -czf /var/backups/nightly.tgz /srv/data",
                    "auth_outcome": "success",
                    "auth_protocol": "ssh",
                    "auth_direction": "remote",
                }
            ],
            index=pd.DatetimeIndex([pd.Timestamp("2024-06-16T22:45:00Z")]),
        )
        atomic = engine.apply_atomic(frame, apply_profiling=False)
        sparse = atomic.attrs["chronosift_sparse"]
        signal_map = sparse["signal_map"]
        explain_map = sparse["explain_map"]
        self.assertEqual(signal_map[0]["auth_remote_success"], 1.0)

        engine._apply_non_temporal_contextual_sparse(
            atomic, signal_map, explain_map, apply_profiling=False
        )

        self.assertEqual(signal_map[0]["auth_remote_success"], 0.0)

    def test_discovery_admin_and_backup_adjustments_are_config_owned(self):
        rows = [
            {"actor_cmd": "nslookup example.test"},
            {"actor_cmd": "tasklist /svc"},
            {"actor_cmd": "tar -czf /var/backups/nightly.tgz /srv/data"},
        ]
        source_signals = {
            0: {
                "remote_system_discovery": 1.0,
                "exec_network_tool": 1.0,
                "suspicious_execution": 0.75,
            },
            1: {
                "exec_shell_spawn": 1.0,
                "system_owner_user_discovery": 1.0,
                "suspicious_execution": 1.0,
            },
            2: {
                "lolbin_linux": 1.0,
                "exec_archive_tool": 1.0,
                "suspicious_execution": 1.0,
            },
        }

        adjusted, explained = self._apply_contextual_signal_adjustments(
            self._engine(), rows, deepcopy(source_signals)
        )
        self.assertEqual(adjusted[0]["remote_system_discovery"], 1.0)
        self.assertEqual(adjusted[0]["exec_network_tool"], 0.0)
        self.assertEqual(adjusted[0]["suspicious_execution"], 0.0)
        self.assertEqual(adjusted[1]["exec_shell_spawn"], 0.0)
        self.assertEqual(adjusted[1]["system_owner_user_discovery"], 0.0)
        self.assertEqual(adjusted[1]["suspicious_execution"], 0.0)
        self.assertEqual(adjusted[2]["lolbin_linux"], 0.0)
        self.assertEqual(adjusted[2]["exec_archive_tool"], 0.0)
        self.assertEqual(adjusted[2]["suspicious_execution"], 0.0)
        self.assertEqual(
            [explained[row_i][0]["rule_id"] for row_i in range(3)],
            [
                "DISCOVERY_RECLASSIFICATION",
                "BENIGN_ADMIN_QUERY_DAMPENING",
                "BENIGN_BACKUP_ARCHIVE_DAMPENING",
            ],
        )
        self.assertEqual(
            explained[0][0]["evidence"]["preserved_discovery_signals"],
            "remote_system_discovery",
        )

        configured_rules = deepcopy(BASE_RULES)
        configured = self._detector_config(
            configured_rules, "contextual_signal_adjustments"
        )
        for index, rule in enumerate(configured["ordered_rules"]):
            rule["when"] = {
                "input": "combined_text_lower",
                "op": "contains_any",
                "values": [f"configured-only-adjustment-{index}"],
            }
        unchanged, unexplained = self._apply_contextual_signal_adjustments(
            self._engine(configured_rules), rows, deepcopy(source_signals)
        )
        self.assertEqual(unchanged, source_signals)
        self.assertEqual(unexplained, {})

    def test_contextual_signal_adjustment_schema_errors_report_precise_paths(self):
        cases = (
            (
                "top-level key",
                lambda config: config.update({"unexpected": True}),
                r"contextual_signal_adjustments: unknown key\(s\): unexpected",
            ),
            (
                "unknown evidence input",
                lambda config: config["evidence"]["command"].update(
                    {"input": "missing_input"}
                ),
                r"contextual_signal_adjustments\.evidence\.command\.input: unknown configured input 'missing_input'",
            ),
            (
                "missing action multiplier",
                lambda config: config["ordered_rules"][2].update(
                    {"action": {"type": "multiply"}}
                ),
                r"contextual_signal_adjustments\.ordered_rules\[2\]\.action: missing required key\(s\): multiplier",
            ),
            (
                "unknown predicate input",
                lambda config: config["ordered_rules"][0].update(
                    {
                        "when": {
                            "input": "missing_input",
                            "op": "contains_any",
                            "values": ["marker"],
                        }
                    }
                ),
                r"contextual_signal_adjustments\.ordered_rules\[0\]\.when\.input: unknown configured input 'missing_input'",
            ),
            (
                "missing signal threshold",
                lambda config: config["ordered_rules"][0][
                    "signal_conditions"
                ].pop("minimum_value_exclusive"),
                r"contextual_signal_adjustments\.ordered_rules\[0\]\.signal_conditions: missing required key\(s\): minimum_value_exclusive",
            ),
            (
                "negative signal threshold",
                lambda config: config["ordered_rules"][0][
                    "signal_conditions"
                ].update({"minimum_value_exclusive": -0.1}),
                r"contextual_signal_adjustments\.ordered_rules\[0\]\.signal_conditions\.minimum_value_exclusive: expected a non-negative finite number",
            ),
        )
        for label, mutate, error_path in cases:
            with self.subTest(label=label):
                rules = deepcopy(BASE_RULES)
                mutate(
                    self._detector_config(
                        rules, "contextual_signal_adjustments"
                    )
                )
                with self.assertRaisesRegex(ValueError, error_path):
                    self._engine(rules)

    def test_atomic_execution_gates_emit_aliases_family_and_matched_source_evidence(self):
        engine = self._engine()
        source_rows = [
            {"lolbin_windows": 1.0},
            {"lolbin_linux": 1.0},
            {"lolbin_suspicious_args": 1.0},
            {"interpreter_exec_linux": 1.0},
            {"scheduled_exec": 1.0},
            {"privileged_scheduled_exec": 1.0},
            {"data_transfer_tool_exec": 1.0},
            {"lolbin_windows": 1.0, "scheduled_exec": 1.0},
        ]
        frame = pd.DataFrame(
            index=pd.date_range("2024-06-16T09:00:00Z", periods=len(source_rows), freq="min")
        )
        signal_map = {row: dict(signals) for row, signals in enumerate(source_rows)}
        explain_map = {row: [] for row in range(len(source_rows))}

        engine._apply_policy_signal_gates_sparse(
            frame,
            signal_map,
            explain_map,
            stage="atomic",
        )

        expected_aliases = [
            "execution_lolbin",
            "execution_lolbin",
            "execution_lolbin_suspicious_args",
            "execution_interpreter",
            "execution_scheduled",
            "execution_privileged_scheduled",
        ]
        for row, alias in enumerate(expected_aliases):
            self.assertEqual(signal_map[row][alias], 1.0)
            self.assertEqual(signal_map[row]["suspicious_execution"], 1.0)
        self.assertNotIn("execution_lolbin", signal_map[6])
        self.assertEqual(signal_map[6]["suspicious_execution"], 1.0)
        self.assertEqual(signal_map[7]["execution_lolbin"], 1.0)
        self.assertEqual(signal_map[7]["execution_scheduled"], 1.0)
        suspicious_explain = next(
            item for item in explain_map[7]
            if item["rule_id"] == "SUSPICIOUS_EXECUTION"
        )
        self.assertEqual(suspicious_explain["confidence"], "medium")
        self.assertEqual(
            suspicious_explain["evidence"],
            {"derived_from": "lolbin_windows,scheduled_exec"},
        )
        alias_explain = next(
            item for item in explain_map[0]
            if item["rule_id"] == "EXECUTION_LOLBIN"
        )
        self.assertEqual(alias_explain["confidence"], "high")
        self.assertEqual(alias_explain["evidence"], {"derived_from": "lolbin_windows"})

    def test_atomic_execution_policy_disable_and_mutation_are_authoritative(self):
        disabled_rules = deepcopy(BASE_RULES)
        self._detector_config(disabled_rules, "execution_lolbin")["enabled"] = False
        disabled_engine = self._engine(disabled_rules)
        frame = pd.DataFrame(
            index=pd.DatetimeIndex([pd.Timestamp("2024-06-16T09:00:00Z")])
        )
        disabled_signals = {0: {"lolbin_windows": 1.0}}
        disabled_engine._apply_policy_signal_gates_sparse(
            frame, disabled_signals, {0: []}, stage="atomic"
        )
        self.assertNotIn("execution_lolbin", disabled_signals[0])
        self.assertEqual(disabled_signals[0]["suspicious_execution"], 1.0)
        self.assertNotIn("EXECUTION_LOLBIN", disabled_engine.rule_emit_signals)

        rules = deepcopy(BASE_RULES)
        weights = deepcopy(BASE_WEIGHTS)
        detector = self._detector_config(rules, "execution_lolbin")
        detector["inputs"]["signals"] = ["usb_device_connected"]
        detector["emissions"][0].update(
            {
                "name": "configured_execution_alias",
                "value": 2,
                "rule_id": "CONFIGURED_EXECUTION_ALIAS",
                "description": "Configured execution alias",
                "confidence": "low",
            }
        )
        download_targets = self._download_config(rules)["target"]["any_signals"]
        download_targets[download_targets.index("execution_lolbin")] = (
            "configured_execution_alias"
        )
        chain_targets = self._web_upload_chain_config(rules)["target"][
            "any_signals"
        ]
        chain_targets[chain_targets.index("execution_lolbin")] = (
            "configured_execution_alias"
        )
        _replace_config_scalar(
            self._detector_config(rules, "contextual_signal_adjustments"),
            "execution_lolbin",
            "configured_execution_alias",
        )
        weights["weights"]["configured_execution_alias"] = 0
        engine = self._engine(rules, weights)
        signal_map = {
            0: {"lolbin_windows": 1.0},
            1: {"usb_device_connected": 1.0},
        }
        explain_map = {0: [], 1: []}
        two_row_frame = pd.DataFrame(
            index=pd.date_range("2024-06-16T09:00:00Z", periods=2, freq="min")
        )
        engine._apply_policy_signal_gates_sparse(
            two_row_frame, signal_map, explain_map, stage="atomic"
        )
        self.assertNotIn("configured_execution_alias", signal_map[0])
        self.assertEqual(signal_map[1]["configured_execution_alias"], 2.0)
        configured = next(
            item for item in explain_map[1]
            if item["rule_id"] == "CONFIGURED_EXECUTION_ALIAS"
        )
        self.assertEqual(configured["description"], "Configured execution alias")
        self.assertEqual(configured["confidence"], "low")
        self.assertEqual(
            engine.rule_emit_signals["CONFIGURED_EXECUTION_ALIAS"],
            ["configured_execution_alias"],
        )
        self.assertNotIn("EXECUTION_LOLBIN", engine.rule_emit_signals)
        self.assertEqual(
            engine._temporal_candidate_base_mask(two_row_frame, signal_map).tolist(),
            [True, True],
        )

    def test_apply_atomic_runs_execution_policy_before_initial_scoring(self):
        frame = pd.DataFrame(
            [
                {
                    "parser": "syslog",
                    "message": "CRON (root) CMD (/usr/bin/python job.py)",
                    "actor_user": "root",
                }
            ],
            index=pd.DatetimeIndex([pd.Timestamp("2024-06-16T09:00:00Z")]),
        )
        out = self._engine().apply_atomic(
            frame,
            apply_profiling=False,
            enforce_required_fields=False,
        )
        signals = out.attrs["chronosift_sparse"]["signal_map"][0]
        self.assertEqual(signals["scheduled_exec"], 1.0)
        self.assertEqual(signals["privileged_scheduled_exec"], 1.0)
        self.assertEqual(signals["execution_scheduled"], 1.0)
        self.assertEqual(signals["execution_privileged_scheduled"], 1.0)
        self.assertEqual(signals["suspicious_execution"], 1.0)

    def test_systemd_artifact_and_persistent_command_fire_but_plain_restart_does_not(self):
        engine = self._engine()
        _, signal_map, explain_map = self._apply_systemd(
            engine,
            [
                {
                    "relative_path": "/etc/systemd/system/evil.service",
                    "timestamp_desc": "Creation Time",
                    "hostname": "server1",
                },
                {
                    "actor_cmd": "systemctl enable evil.service",
                    "message": "enable requested",
                    "hostname": "server1",
                },
                {
                    "command_line": "systemctl restart nginx",
                    "message": "routine restart",
                    "hostname": "server1",
                },
            ],
        )

        self.assertEqual(signal_map[0]["systemd_service_persistence"], 1.0)
        self.assertEqual(signal_map[1]["systemd_service_persistence"], 1.0)
        self.assertEqual(
            explain_map[1][0]["evidence"],
            {
                "command": "systemctl enable evil.service",
                "message": "enable requested",
                "hostname": "server1",
            },
        )
        self.assertNotIn("systemd_service_persistence", signal_map.get(2, {}))

    def test_disabling_systemd_removes_its_output_and_canonical_derivatives(self):
        rules = deepcopy(BASE_RULES)
        self._systemd_config(rules)["enabled"] = False
        engine = self._engine(rules)
        frame, signal_map, explain_map = self._apply_systemd(
            engine,
            [
                {
                    "relative_path": "/etc/systemd/system/evil.service",
                    "timestamp_desc": "Content Modification Time",
                },
                {"message": "systemctl enable evil.service"},
            ],
        )
        engine._apply_policy_signal_projections_sparse(
            signal_map,
            explain_map,
            stage="contextual",
        )

        for row in range(len(frame)):
            signals = signal_map.get(row, {})
            self.assertNotIn("systemd_service_persistence", signals)
            self.assertNotIn("persistence_mechanism", signals)
            self.assertNotIn("persistence_service_install", signals)

    def test_signal_projection_runtime_uses_maximum_strength_and_configured_evidence(self):
        engine = self._engine()
        signal_map = {
            0: {
                "persistence_service": 0.35,
                "authorized_keys_persistence": 0.8,
                "persistence_mechanism": 0.7,
            },
            1: {
                "large_archive_created": 0.25,
                "archive_created": 0.85,
                "data_transfer_tool_exec": 0.6,
                "large_http_transfer": 0.4,
            },
            2: {
                "staging_then_transfer": 0.45,
                "cross_border_transfer": 0.7,
                "sensitive_data_staged": 0.55,
                "archive_after_sensitive_access": 0.9,
            },
            3: {
                "persistence_service": 0.7,
                "persistence_mechanism": 0.95,
            },
        }
        explain_map = {row_i: [] for row_i in signal_map}

        engine._apply_policy_signal_projections_sparse(
            signal_map,
            explain_map,
            stage="contextual",
        )
        engine._apply_policy_signal_projections_sparse(
            signal_map,
            explain_map,
            stage="temporal",
        )

        self.assertEqual(signal_map[0]["persistence_mechanism"], 0.8)
        self.assertEqual(signal_map[0]["persistence_service_install"], 0.35)
        self.assertEqual(signal_map[0]["identity_persistence_change"], 0.8)
        self.assertEqual(signal_map[1]["staging_archive"], 0.85)
        self.assertEqual(signal_map[1]["transfer_execution"], 0.6)
        self.assertEqual(signal_map[1]["transfer_large_http"], 0.4)
        self.assertEqual(signal_map[2]["transfer_exfiltration_pattern"], 0.45)
        self.assertEqual(signal_map[2]["transfer_cross_border"], 0.7)
        self.assertEqual(signal_map[2]["transfer_sensitive_staging"], 0.9)
        self.assertEqual(signal_map[3]["persistence_mechanism"], 0.95)
        self.assertFalse(
            any(
                item["rule_id"] == "PERSISTENCE_MECHANISM"
                for item in explain_map[3]
            )
        )

        persistence = next(
            item
            for item in explain_map[0]
            if item["rule_id"] == "PERSISTENCE_MECHANISM"
        )
        self.assertEqual(persistence["confidence"], "high")
        self.assertEqual(persistence["evidence_type"], "direct")
        self.assertEqual(persistence["signals"], ["persistence_mechanism"])
        self.assertEqual(
            persistence["evidence"],
            {
                "derived_from": (
                    "authorized_keys_persistence,persistence_service"
                )
            },
        )
        sensitive = next(
            item
            for item in explain_map[2]
            if item["rule_id"] == "TRANSFER_SENSITIVE_STAGING"
        )
        self.assertEqual(
            sensitive["evidence"],
            {
                "derived_from": (
                    "archive_after_sensitive_access,sensitive_data_staged"
                )
            },
        )

    def test_signal_projection_mutation_and_disablement_control_runtime(self):
        rules = deepcopy(BASE_RULES)
        weights = deepcopy(BASE_WEIGHTS)
        policy = self._detector_config(rules, "canonical_persistence_projection")
        projection = policy["projections"][0]
        projection["inputs"]["signals"] = ["usb_device_connected"]
        projection["conditions"].update(
            {"match": "all", "minimum_value_exclusive": 0.25}
        )
        projection["emissions"][0].update(
            {
                "name": "configured_projection_output",
                "value": 0.5,
                "rule_id": "CONFIGURED_PROJECTION_OUTPUT",
                "description": "Configured projection metadata reached runtime",
                "confidence": "low",
            }
        )
        policy["evidence"] = {
            "configured_sources": {"resolver": "matched_signals"}
        }
        weights["weights"]["configured_projection_output"] = 0

        engine = self._engine(rules, weights)
        signal_map = {
            0: {"usb_device_connected": 0.8},
            1: {"usb_device_connected": 0.25},
        }
        explain_map = {0: [], 1: []}
        engine._apply_policy_signal_projections_sparse(
            signal_map,
            explain_map,
            stage="contextual",
        )

        self.assertEqual(signal_map[0]["configured_projection_output"], 0.4)
        self.assertNotIn("persistence_mechanism", signal_map[0])
        self.assertNotIn("configured_projection_output", signal_map[1])
        explanation = next(
            item
            for item in explain_map[0]
            if item["rule_id"] == "CONFIGURED_PROJECTION_OUTPUT"
        )
        self.assertEqual(
            explanation,
            {
                "rule_id": "CONFIGURED_PROJECTION_OUTPUT",
                "description": "Configured projection metadata reached runtime",
                "confidence": "low",
                "evidence_type": "direct",
                "signals": ["configured_projection_output"],
                "evidence": {"configured_sources": "usb_device_connected"},
            },
        )

        disabled_rules = deepcopy(rules)
        self._detector_config(
            disabled_rules, "canonical_persistence_projection"
        )["enabled"] = False
        disabled_engine = self._engine(disabled_rules, weights)
        disabled_signals = {0: {"usb_device_connected": 0.8}}
        disabled_explain = {0: []}
        disabled_engine._apply_policy_signal_projections_sparse(
            disabled_signals,
            disabled_explain,
            stage="contextual",
        )
        self.assertNotIn("configured_projection_output", disabled_signals[0])
        self.assertEqual(disabled_explain[0], [])

    def test_canonical_authentication_mutation_and_disablement_control_runtime(self):
        rules = deepcopy(BASE_RULES)
        weights = deepcopy(BASE_WEIGHTS)
        config = self._detector_config(rules, "canonical_authentication")
        config["inputs"]["fields"] = {
            "outcome": "policy_outcome",
            "protocol": "policy_protocol",
            "direction": "policy_direction",
            "logon_type": "policy_logon_type",
            "message": "policy_message",
            "authentication_package": "policy_authentication_package",
        }
        config["inputs"]["source_signals"] = {
            "success": ["usb_device_connected"],
            "failure": ["auth_fail_generic"],
            "minimum_signal_value_exclusive": 0,
        }
        config["outcomes"] = {
            "success": "approved",
            "failure": "denied",
            "outcome_source_match": "any",
            "conflict_resolution": "allow_both",
        }
        config["semantics"]["remote"] = {
            "match": "any",
            "direction_values": ["policy_remote_direction"],
            "protocol_values": ["policy_remote_protocol"],
        }
        config["semantics"]["lateral_movement"]["include_remote"] = False
        config["emissions"]["success"].update(
            {
                "name": "configured_auth_success",
                "value": 0.6,
                "rule_id": "CONFIGURED_AUTH_SUCCESS",
                "description": "Configured authentication metadata reached runtime",
                "confidence": "low",
            }
        )
        _replace_config_scalar(rules, "auth_success", "configured_auth_success")
        weights["weights"]["configured_auth_success"] = 0
        engine = self._engine(rules, weights)
        self.assertTrue(
            {
                "policy_outcome",
                "policy_protocol",
                "policy_direction",
                "policy_logon_type",
                "policy_message",
                "policy_authentication_package",
            }.issubset(engine.required_fields)
        )
        frame = pd.DataFrame(
            [
                {
                    "policy_outcome": "approved",
                    "policy_protocol": "policy_remote_protocol",
                    "policy_direction": "local",
                },
                {},
                {"auth_outcome": "success", "auth_protocol": "ssh"},
                {
                    "policy_outcome": "approved",
                    "policy_protocol": "policy_remote_protocol",
                    "policy_logon_type": "3",
                },
                {
                    "policy_outcome": "approved",
                    "policy_protocol": "policy_remote_protocol",
                    "policy_logon_type": "3",
                    "policy_authentication_package": "ntlm",
                },
            ],
            index=pd.date_range("2024-06-16T10:00:00Z", periods=5, freq="min"),
        )
        signal_map = {1: {"usb_device_connected": 0.75}}
        explain_map = {0: [], 1: [], 2: [], 3: [], 4: []}

        engine._apply_canonical_auth_signals_sparse(
            frame,
            signal_map,
            explain_map,
        )

        self.assertEqual(signal_map[0]["configured_auth_success"], 0.6)
        self.assertEqual(signal_map[1]["configured_auth_success"], 0.6)
        self.assertNotIn("auth_success", signal_map[0])
        self.assertNotIn("configured_auth_success", signal_map.get(2, {}))
        self.assertNotIn("lateral_movement_indicator", signal_map[3])
        self.assertIn("lateral_movement_indicator", signal_map[4])
        explanation = next(
            item
            for item in explain_map[0]
            if item["rule_id"] == "CONFIGURED_AUTH_SUCCESS"
        )
        self.assertEqual(
            explanation,
            {
                "rule_id": "CONFIGURED_AUTH_SUCCESS",
                "description": "Configured authentication metadata reached runtime",
                "confidence": "low",
                "evidence_type": "direct",
                "signals": ["configured_auth_success"],
                "evidence": {"derived_from": "approved"},
            },
        )

    def test_canonical_authentication_eligibility_is_yaml_authoritative(self):
        rules = deepcopy(BASE_RULES)
        self._detector_config(rules, "canonical_authentication")[
            "eligibility"
        ] = {
            "all": ["success", "remote"],
            "any": [],
            "none": [],
        }
        engine = self._engine(rules)
        frame = pd.DataFrame(
            [
                {
                    "auth_outcome": "success",
                    "auth_direction": "local",
                },
                {
                    "auth_outcome": "success",
                    "auth_direction": "remote",
                },
            ],
            index=pd.date_range(
                "2024-06-16T09:58:00Z", periods=2, freq="min"
            ),
        )
        signal_map = {}
        explain_map = {0: [], 1: []}

        engine._apply_canonical_auth_signals_sparse(
            frame, signal_map, explain_map
        )

        self.assertNotIn(0, signal_map)
        self.assertEqual(signal_map[1]["auth_remote_success"], 1.0)

    def test_authentication_and_execution_truth_tables_are_yaml_authoritative(self):
        frame = pd.DataFrame(
            [
                {
                    "auth_outcome": "success",
                    "auth_direction": "local",
                    "auth_protocol": "",
                    "logon_type": "10",
                }
            ],
            index=pd.DatetimeIndex([pd.Timestamp("2024-06-16T10:00:00Z")]),
        )
        engine = self._engine()
        signal_map = {}
        explain_map = {0: []}
        engine._apply_canonical_auth_signals_sparse(
            frame, signal_map, explain_map
        )
        self.assertEqual(signal_map[0]["auth_local_success"], 1.0)
        self.assertNotIn("auth_remote_interactive_success", signal_map[0])

        rules = deepcopy(BASE_RULES)
        decision = self._detector_config(
            rules, "canonical_authentication"
        )["decisions"]["remote_interactive_success"]
        decision["all"].remove("remote")
        engine = self._engine(rules)
        signal_map = {}
        explain_map = {0: []}
        engine._apply_canonical_auth_signals_sparse(
            frame, signal_map, explain_map
        )
        self.assertEqual(
            signal_map[0]["auth_remote_interactive_success"], 1.0
        )

        context_frame = pd.DataFrame(
            [{"image_path": "/tmp/opt/tool"}],
            index=pd.DatetimeIndex([pd.Timestamp("2024-06-16T10:01:00Z")]),
        )
        engine = self._engine()
        signal_map = {}
        explain_map = {0: []}
        engine._derive_execution_context_signals_sparse(
            context_frame, signal_map, explain_map
        )
        self.assertNotIn("exec_suspicious_path", signal_map[0])

        rules = deepcopy(BASE_RULES)
        self._detector_config(
            rules, "execution_context_classifier"
        )["decisions"]["suspicious_path"]["none"] = []
        engine = self._engine(rules)
        signal_map = {}
        explain_map = {0: []}
        engine._derive_execution_context_signals_sparse(
            context_frame, signal_map, explain_map
        )
        self.assertEqual(signal_map[0]["exec_suspicious_path"], 1.0)

        disabled_rules = deepcopy(BASE_RULES)
        self._detector_config(disabled_rules, "canonical_authentication")[
            "enabled"
        ] = False
        self._detector_config(disabled_rules, "geographic_continuity")[
            "enabled"
        ] = False
        self._detector_config(disabled_rules, "impossible_travel")[
            "enabled"
        ] = False
        disabled_engine = self._engine(disabled_rules)
        disabled_signals = {}
        disabled_explain = {0: []}
        disabled_engine._apply_canonical_auth_signals_sparse(
            pd.DataFrame(
                [{"auth_outcome": "success", "auth_protocol": "ssh"}],
                index=pd.DatetimeIndex([pd.Timestamp("2024-06-16T10:10:00Z")]),
            ),
            disabled_signals,
            disabled_explain,
        )
        self.assertEqual(disabled_signals, {})
        self.assertEqual(disabled_explain[0], [])

    def test_auth_and_web_signal_minimums_are_yaml_authoritative(self):
        rules = deepcopy(BASE_RULES)
        auth = self._detector_config(rules, "canonical_authentication")
        auth["inputs"]["source_signals"]["minimum_signal_value_exclusive"] = 0.5
        exploit = self._web_request_config(rules)["exploit"]["branches"][
            "configured_hint"
        ]["conditions"]
        exploit["minimum_signal_value_exclusive"] = 0.5
        mapping = self._correlation_config(rules)["mappings"]["branches"][
            "confirmed_webshell"
        ]["conditions"]
        mapping["minimum_signal_value_exclusive"] = 0.5
        engine = self._engine(rules)

        auth_frame = pd.DataFrame(
            [{}, {}],
            index=pd.date_range("2024-06-16T10:00:00Z", periods=2, freq="min"),
        )
        auth_signals = {
            0: {"auth_success_generic": 0.5},
            1: {"auth_success_generic": 0.75},
        }
        engine._apply_canonical_auth_signals_sparse(
            auth_frame, auth_signals, {0: [], 1: []}
        )
        self.assertNotIn("auth_success", auth_signals[0])
        self.assertEqual(auth_signals[1]["auth_success"], 1.0)

        web = engine.detector_policy.web_request_classification
        web_frame = pd.DataFrame(
            [{
                "chronosift_web_request_target": "/index",
                "chronosift_web_host": "example.test",
                "chronosift_web_response_bytes": 100,
                web.outputs.method_field: "GET",
                web.outputs.endpoint_field: "/index",
                web.outputs.status_field: 200,
                web.outputs.attack_indicators_field: "",
            }],
            index=pd.DatetimeIndex([pd.Timestamp("2024-06-16T11:00:00Z")]),
        )
        for value, expected in ((0.5, False), (0.75, True)):
            signal_map = {0: {"web_exploitation_hint": value}}
            engine._apply_web_request_classifier_sparse(
                web_frame.copy(), signal_map, {0: []}
            )
            self.assertEqual(
                "exploit_public_facing_app" in signal_map[0], expected
            )

        correlation = engine.detector_policy.referenced_file_correlation
        mapping_frame = pd.DataFrame([{
            correlation.web_feature_fields["categories"]: "webshell",
            correlation.attack_indicators_field: "",
            correlation.method_field: "GET",
            correlation.source_ip_field: "192.0.2.1",
        }])
        for value, expected in ((0.5, False), (0.75, True)):
            signal_map = {0: {"web_confirmed_webshell_access": value}}
            engine._apply_web_attack_mapping_sparse(
                mapping_frame.copy(), signal_map, {0: []}
            )
            self.assertEqual("mitre_t1505_003" in signal_map[0], expected)

    def test_execution_context_mutation_and_disablement_control_runtime(self):
        rules = deepcopy(BASE_RULES)
        weights = deepcopy(BASE_WEIGHTS)
        config = self._detector_config(rules, "execution_context_classifier")
        config["inputs"] = {
            "path": {"resolver": "first_nonempty", "fields": ["policy_path"]},
            "command": {
                "resolver": "first_nonempty",
                "fields": ["policy_command"],
            },
            "actor": {"resolver": "first_nonempty", "fields": ["policy_actor"]},
        }
        classification = config["classification"]
        classification.update(
            {
                "temporary_path_contains": ["/configured-tmp/"],
                "user_writable_path_contains": ["/configured-user/"],
                "suspicious_path_contains": ["/configured-suspicious/"],
                "system_binary_names": ["policydaemon"],
                "command_names": {
                    "compiler": ["policycc"],
                    "shell": ["policyshell"],
                    "network": ["policynet"],
                    "archive": ["policyzip"],
                },
                "privileged_actors": ["policyroot"],
                "suid_regex": "(?i)policy-suid",
            }
        )
        config["evidence"] = ["command", "derived_from"]
        config["emissions"]["compiler_activity"].update(
            {
                "name": "configured_compiler_activity",
                "value": 0.4,
                "rule_id": "CONFIGURED_COMPILER_ACTIVITY",
                "description": "Configured execution metadata reached runtime",
                "confidence": "low",
            }
        )
        _replace_config_scalar(
            rules,
            "exec_compiler_activity",
            "configured_compiler_activity",
        )
        weights["weights"]["configured_compiler_activity"] = 0
        engine = self._engine(rules, weights)
        self.assertTrue(
            {"policy_path", "policy_command", "policy_actor"}.issubset(
                engine.required_fields
            )
        )
        frame = pd.DataFrame(
            [
                {
                    "policy_path": "/neutral/tool",
                    "policy_command": "gcc payload.c",
                    "policy_actor": "ordinary",
                },
                {
                    "policy_path": "/neutral/tool",
                    "policy_command": "policycc payload.c",
                    "policy_actor": "ordinary",
                },
            ],
            index=pd.date_range("2024-06-16T11:00:00Z", periods=2, freq="min"),
        )
        signal_map = {}
        explain_map = {0: [], 1: []}

        engine._derive_execution_context_signals_sparse(
            frame,
            signal_map,
            explain_map,
        )

        self.assertNotIn("configured_compiler_activity", signal_map.get(0, {}))
        self.assertEqual(signal_map[1]["configured_compiler_activity"], 0.4)
        self.assertNotIn("exec_compiler_activity", signal_map[1])
        self.assertEqual(
            explain_map[1],
            [
                {
                    "rule_id": "CONFIGURED_COMPILER_ACTIVITY",
                    "description": "Configured execution metadata reached runtime",
                    "confidence": "low",
                    "evidence_type": "direct",
                    "signals": ["configured_compiler_activity"],
                    "evidence": {
                        "command": "policycc payload.c",
                        "derived_from": "policycc payload.c",
                    },
                }
            ],
        )

        disabled_rules = deepcopy(BASE_RULES)
        self._detector_config(disabled_rules, "execution_context_classifier")[
            "enabled"
        ] = False
        self._masquerading_config(disabled_rules)["enabled"] = False
        disabled_engine = self._engine(disabled_rules)
        disabled_signals = {}
        disabled_explain = {0: []}
        disabled_engine._derive_execution_context_signals_sparse(
            pd.DataFrame(
                [{"image_path": "/tmp/bash", "command_line": "gcc payload.c"}],
                index=pd.DatetimeIndex([pd.Timestamp("2024-06-16T11:10:00Z")]),
            ),
            disabled_signals,
            disabled_explain,
        )
        self.assertEqual(disabled_signals, {})
        self.assertEqual(disabled_explain[0], [])

    def test_file_lifecycle_vocabulary_metadata_and_disablement_control_runtime(self):
        rules = deepcopy(BASE_RULES)
        weights = deepcopy(BASE_WEIGHTS)
        config = self._detector_config(rules, "file_lifecycle")
        config["inputs"] = {
            "path": {
                "resolver": "best_effort_file_path",
                "fields": ["policy_path"],
            },
            "timestamp_description_field": "policy_timestamp",
            "host_field": "policy_host",
            "parser_field": "policy_parser",
            "message_field": "policy_message",
            "file_size_field": "policy_size",
            "allocation_field": "policy_allocated",
        }
        classification = config["classification"]
        classification["timestamp_kinds"] = {
            "priority": ["create", "delete", "modify", "access"],
            "contains": {
                "create": ["policy-create"],
                "delete": ["policy-delete"],
                "modify": ["policy-modify"],
                "access": ["policy-access"],
            },
        }
        classification["path_contains"] = {
            "web_root": ["/policy-web/"],
            "sensitive": ["/policy-sensitive/"],
            "database_dump_name": ["policydump"],
            "excluded_update": ["/policy-excluded/"],
        }
        classification["extensions"] = {
            "web_script": [".policyexec"],
            "web_content": [".policycontent"],
            "database_dump": [".policydb"],
            "archive": [".policyarc"],
        }
        classification["suspicious_temp_basename_contains"] = ["policytemp"]
        classification["ransomware_extension_suffixes"] = [".policyransom"]
        config["emissions"]["web_executable_created"].update(
            {
                "name": "configured_web_executable_created",
                "value": 0.6,
                "rule_id": "CONFIGURED_WEB_EXECUTABLE_CREATED",
                "description": "Configured lifecycle metadata reached runtime",
                "confidence": "high",
            }
        )
        config["evidence"]["web_executable_created"] = ["path", "parser"]
        _replace_config_scalar(
            rules,
            "web_executable_file_created",
            "configured_web_executable_created",
        )
        weights["weights"]["configured_web_executable_created"] = 0
        engine = self._engine(rules, weights)
        self.assertTrue(
            {
                "policy_path", "policy_timestamp", "policy_host", "policy_parser",
                "policy_message", "policy_size", "policy_allocated",
            }.issubset(engine.required_fields)
        )
        frame = pd.DataFrame(
            [
                {
                    "policy_path": "/policy-web/shell.policyexec",
                    "policy_timestamp": "policy-create",
                    "policy_parser": "policy-parser",
                    "policy_host": "policy-host",
                },
                {
                    "policy_path": "/var/www/shell.php",
                    "policy_timestamp": "Creation Time",
                },
                {
                    "policy_path": "/policy-sensitive/secret.txt",
                    "policy_timestamp": "policy-access",
                },
                {
                    "policy_path": "/neutral/archive.policyarc",
                    "policy_timestamp": "policy-create",
                    "policy_size": 321,
                },
                {
                    "policy_path": "/neutral/policydump.policydb",
                    "policy_timestamp": "policy-create",
                    "policy_message": "configured dump",
                },
                {
                    "policy_path": "/policy-web/legacy.php",
                    "policy_timestamp": "policy-create",
                },
            ],
            index=pd.date_range("2024-06-16T12:00:00Z", periods=6, freq="min"),
        )
        signal_map = {}
        explain_map = {row_i: [] for row_i in range(len(frame))}

        engine._apply_file_lifecycle_signals_sparse(
            frame,
            signal_map,
            explain_map,
        )

        self.assertEqual(signal_map[0]["configured_web_executable_created"], 0.6)
        self.assertNotIn("web_executable_file_created", signal_map[0])
        self.assertEqual(signal_map[2]["sensitive_file_access"], 1.0)
        self.assertEqual(signal_map[3]["archive_created"], 1.0)
        self.assertEqual(signal_map[4]["database_dump_candidate"], 1.0)
        self.assertEqual(signal_map.get(1, {}), {})
        self.assertNotIn("configured_web_executable_created", signal_map.get(5, {}))
        explanation = next(
            item
            for item in explain_map[0]
            if item["rule_id"] == "CONFIGURED_WEB_EXECUTABLE_CREATED"
        )
        self.assertEqual(
            explanation,
            {
                "rule_id": "CONFIGURED_WEB_EXECUTABLE_CREATED",
                "description": "Configured lifecycle metadata reached runtime",
                "confidence": "high",
                "evidence_type": "direct",
                "signals": ["configured_web_executable_created"],
                "evidence": {
                    "path": "/policy-web/shell.policyexec",
                    "parser": "policy-parser",
                },
            },
        )

        disabled_rules = deepcopy(BASE_RULES)
        self._detector_config(disabled_rules, "file_lifecycle")["enabled"] = False
        disabled_engine = self._engine(disabled_rules)
        disabled_signals = {}
        disabled_explain = {0: []}
        disabled_engine._apply_file_lifecycle_signals_sparse(
            pd.DataFrame(
                [{"filename": "/var/www/shell.php", "timestamp_desc": "Creation Time"}],
                index=pd.DatetimeIndex([pd.Timestamp("2024-06-16T12:10:00Z")]),
            ),
            disabled_signals,
            disabled_explain,
        )
        self.assertEqual(disabled_signals, {})
        self.assertEqual(disabled_explain[0], [])

    def test_file_lifecycle_windows_and_thresholds_are_authoritative(self):
        rules = deepcopy(BASE_RULES)
        config = self._detector_config(rules, "file_lifecycle")
        classification = config["classification"]
        classification["path_contains"]["web_root"] = ["/policy-web/"]
        classification["path_contains"]["excluded_update"] = [
            "/policy-excluded"
        ]
        classification["extensions"]["web_script"] = [".policyexec"]
        classification["suspicious_temp_basename_contains"] = ["policytemp"]
        classification["ransomware_extension_suffixes"] = [".policyransom"]
        windows = config["conditions"]["windows"]
        windows["short_lived_file"]["lookback"] = "1m"
        windows["mass_file_modification"].update(
            {"lookback": "3m", "threshold": 2}
        )
        windows["ransomware_extension_burst"].update(
            {"lookback": "4m", "threshold": 2}
        )
        engine = self._engine(rules)
        start = pd.Timestamp("2024-06-16T13:00:00Z")
        offsets = (0, 1, 2, 4, 5, 7, 8, 9, 10, 13)
        frame = pd.DataFrame(
            [
                {"filename": "/policy-web/policytemp.policyexec", "timestamp_desc": "Creation Time", "hostname": "host1"},
                {"filename": "/policy-web/policytemp.policyexec", "timestamp_desc": "Deletion Time", "hostname": "host1"},
                {"filename": "/policy-web/slowpolicytemp.policyexec", "timestamp_desc": "Creation Time", "hostname": "host1"},
                {"filename": "/policy-web/slowpolicytemp.policyexec", "timestamp_desc": "Deletion Time", "hostname": "host1"},
                {"filename": "/mass/a.txt", "timestamp_desc": "Modification Time", "hostname": "host1"},
                {"filename": "/mass/b.txt", "timestamp_desc": "Modification Time", "hostname": "host1"},
                {"filename": "/policy-excluded/a.txt", "timestamp_desc": "Modification Time", "hostname": "host1"},
                {"filename": "/policy-excluded/b.txt", "timestamp_desc": "Modification Time", "hostname": "host1"},
                {"filename": "/ransom/a.policyransom", "timestamp_desc": "Creation Time", "hostname": "host1"},
                {"filename": "/ransom/b.policyransom", "timestamp_desc": "Creation Time", "hostname": "host1"},
            ],
            index=pd.DatetimeIndex(
                [start + pd.Timedelta(minutes=offset) for offset in offsets]
            ),
        )
        signal_map = {}
        explain_map = {row_i: [] for row_i in range(len(frame))}

        engine._apply_file_lifecycle_signals_sparse(
            frame,
            signal_map,
            explain_map,
        )

        self.assertEqual(signal_map[1]["short_lived_file"], 1.0)
        self.assertNotIn("short_lived_file", signal_map.get(3, {}))
        self.assertEqual(signal_map[5]["mass_file_modification"], 1.0)
        self.assertNotIn("mass_file_modification", signal_map.get(7, {}))
        self.assertEqual(signal_map[9]["ransomware_extension_burst"], 1.0)
        mass = next(
            item
            for item in explain_map[5]
            if item["rule_id"] == "MASS_FILE_MODIFICATION"
        )
        burst = next(
            item
            for item in explain_map[9]
            if item["rule_id"] == "RANSOMWARE_EXTENSION_BURST"
        )
        self.assertEqual(
            (mass["evidence"]["window_seconds"], mass["evidence"]["count_in_window"]),
            (180, 2),
        )
        self.assertEqual(
            (burst["evidence"]["window_seconds"], burst["evidence"]["count_in_window"]),
            (240, 2),
        )

    def test_file_lifecycle_row_decisions_control_runtime(self):
        rules = deepcopy(BASE_RULES)
        decisions = self._detector_config(rules, "file_lifecycle")[
            "conditions"
        ]["row_emissions"]
        decisions["web_executable_created"]["timestamp_kinds"] = ["modify"]
        decisions["deleted"]["match"] = "all"
        engine = self._engine(rules)
        frame = pd.DataFrame(
            [
                {
                    "filename": "/var/www/shell.php",
                    "timestamp_desc": "Creation Time",
                    "is_allocated": True,
                },
                {
                    "filename": "/var/www/shell.php",
                    "timestamp_desc": "Modification Time",
                    "is_allocated": True,
                },
                {
                    "filename": "/tmp/allocated.txt",
                    "timestamp_desc": "Deletion Time",
                    "is_allocated": True,
                },
                {
                    "filename": "/tmp/unallocated.txt",
                    "timestamp_desc": "Access Time",
                    "is_allocated": False,
                },
                {
                    "filename": "/tmp/deleted-unallocated.txt",
                    "timestamp_desc": "Deletion Time",
                    "is_allocated": False,
                },
            ],
            index=pd.date_range("2024-06-16T13:30:00Z", periods=5, freq="min"),
        )
        signal_map = {}
        explain_map = {row_i: [] for row_i in range(len(frame))}

        engine._apply_file_lifecycle_signals_sparse(
            frame, signal_map, explain_map
        )

        self.assertNotIn("web_executable_file_created", signal_map.get(0, {}))
        self.assertEqual(signal_map[1]["web_executable_file_created"], 1.0)
        self.assertNotIn("file_deleted", signal_map.get(2, {}))
        self.assertNotIn("file_deleted", signal_map.get(3, {}))
        self.assertEqual(signal_map[4]["file_deleted"], 1.0)

    def test_file_lifecycle_window_topology_controls_runtime(self):
        rules = deepcopy(BASE_RULES)
        config = self._detector_config(rules, "file_lifecycle")
        config["classification"]["path_contains"]["excluded_update"] = [
            "/policy-excluded/"
        ]
        windows = config["conditions"]["windows"]
        short = windows["short_lived_file"]
        short.update(
            {
                "key_fields": ["path"],
                "source_timestamp_kinds": ["modify"],
                "target_timestamp_kinds": ["access"],
                "emit_on": "source",
                "conditions": {
                    "any": [{"all": ["target_web_script_extension"]}]
                },
            }
        )
        mass = windows["mass_file_modification"]
        mass.update(
            {
                "threshold": 1,
                "threshold_comparison": "greater_than",
                "eligible_timestamp_kinds": ["create"],
                "group_by": ["host"],
                "conditions": {"any": [{"all": ["path_present"]}]},
            }
        )
        ransomware = windows["ransomware_extension_burst"]
        ransomware.update(
            {
                "threshold": 2,
                "eligible_timestamp_kinds": ["delete"],
                "conditions": {"any": [{"all": ["path_present"]}]},
            }
        )
        engine = self._engine(rules)
        frame = pd.DataFrame(
            [
                {
                    "filename": "/tmp/pair.php",
                    "timestamp_desc": "Modification Time",
                    "hostname": "source-host",
                },
                {
                    "filename": "/tmp/pair.php",
                    "timestamp_desc": "Access Time",
                    "hostname": "target-host",
                },
                {
                    "filename": "/policy-excluded/a.txt",
                    "timestamp_desc": "Creation Time",
                    "hostname": "mass-host",
                },
                {
                    "filename": "/another-directory/b.txt",
                    "timestamp_desc": "Creation Time",
                    "hostname": "mass-host",
                },
                {
                    "filename": "/ordinary/a.txt",
                    "timestamp_desc": "Deletion Time",
                    "hostname": "ransom-host",
                },
                {
                    "filename": "/ordinary/b.txt",
                    "timestamp_desc": "Deletion Time",
                    "hostname": "ransom-host",
                },
            ],
            index=pd.date_range("2024-06-16T14:00:00Z", periods=6, freq="min"),
        )
        signal_map = {}
        explain_map = {row_i: [] for row_i in range(len(frame))}

        engine._apply_file_lifecycle_signals_sparse(
            frame, signal_map, explain_map
        )

        self.assertEqual(signal_map[0]["short_lived_file"], 1.0)
        self.assertNotIn("short_lived_file", signal_map.get(1, {}))
        self.assertEqual(signal_map[3]["mass_file_modification"], 1.0)
        self.assertEqual(signal_map[5]["ransomware_extension_burst"], 1.0)

    def test_mft_timestomping_configuration_and_branches_control_runtime(self):
        rules = deepcopy(BASE_RULES)
        weights = deepcopy(BASE_WEIGHTS)
        config = self._detector_config(rules, "mft_timestomping")
        config["inputs"] = {
            "path": {
                "resolver": "best_effort_file_path",
                "fields": ["policy_path"],
            },
            "parser_field": "policy_parser",
            "timestamp_description_field": "policy_timestamp",
        }
        config["conditions"] = {
            "parser_contains": ["policy-mft"],
            "creation_contains": ["policy-create"],
            "attributes": {
                "standard_information_contains": ["policy-si"],
                "file_name_contains": ["policy-fn"],
            },
            "minimum_delta": "3s",
            "excluded_path_contains": ["/policy-excluded/"],
            "bulk_extraction": {
                "group_by": "parent_directory",
                "threshold": 2,
            },
        }
        config["branches"] = {
            "targeted": {
                "description": "Configured targeted timestomp branch",
                "confidence": "medium",
                "evidence": ["path", "delta_seconds"],
            },
            "bulk_extraction_likely": {
                "description": "Configured bulk timestomp branch",
                "confidence": "high",
                "evidence": ["directory_hit_count", "bulk_extraction_dampened"],
            },
        }
        config["emissions"][0].update(
            {
                "name": "configured_timestomping",
                "value": 0.4,
                "rule_id": "CONFIGURED_TIMESTOMPING",
                "description": "Configured timestomp emission",
                "confidence": "medium",
            }
        )
        _replace_config_scalar(rules, "timestomping", "configured_timestomping")
        weights["weights"]["configured_timestomping"] = 0
        engine = self._engine(rules, weights)
        self.assertTrue(
            {"policy_path", "policy_parser", "policy_timestamp"}.issubset(
                engine.required_fields
            )
        )
        start = pd.Timestamp("2024-06-16T14:00:00Z")
        specs = (
            ("/target/a", "policy-mft", "policy-create policy-si", 0),
            ("/target/a", "policy-mft", "policy-create policy-fn", 4),
            ("/target/delta", "policy-mft", "policy-create policy-si", 0),
            ("/target/delta", "policy-mft", "policy-create policy-fn", 2),
            ("/policy-excluded/a", "policy-mft", "policy-create policy-si", 0),
            ("/policy-excluded/a", "policy-mft", "policy-create policy-fn", 10),
            ("/bulk/a", "policy-mft", "policy-create policy-si", 0),
            ("/bulk/a", "policy-mft", "policy-create policy-fn", 5),
            ("/bulk/b", "policy-mft", "policy-create policy-si", 1),
            ("/bulk/b", "policy-mft", "policy-create policy-fn", 6),
            ("/legacy/parser", "mft", "policy-create policy-si", 0),
            ("/legacy/parser", "mft", "policy-create policy-fn", 10),
            ("/legacy/attribute", "policy-mft", "policy-create $standard_information", 0),
            ("/legacy/attribute", "policy-mft", "policy-create $file_name", 10),
        )
        frame = pd.DataFrame(
            [
                {
                    "policy_path": path,
                    "policy_parser": parser,
                    "policy_timestamp": timestamp_desc,
                }
                for path, parser, timestamp_desc, _ in specs
            ],
            index=pd.DatetimeIndex(
                [start + pd.Timedelta(seconds=offset) for *_, offset in specs]
            ),
        )
        signal_map = {}
        explain_map = {row_i: [] for row_i in range(len(frame))}

        engine._apply_timestomping_detection_sparse(
            frame,
            signal_map,
            explain_map,
        )

        self.assertEqual(signal_map[0]["configured_timestomping"], 0.4)
        self.assertNotIn("configured_timestomping", signal_map.get(2, {}))
        self.assertNotIn("configured_timestomping", signal_map.get(4, {}))
        self.assertEqual(signal_map[6]["configured_timestomping"], 0.4)
        self.assertEqual(signal_map[8]["configured_timestomping"], 0.4)
        self.assertNotIn("configured_timestomping", signal_map.get(10, {}))
        self.assertNotIn("configured_timestomping", signal_map.get(12, {}))
        self.assertEqual(
            explain_map[0][0],
            {
                "rule_id": "CONFIGURED_TIMESTOMPING",
                "description": "Configured targeted timestomp branch",
                "confidence": "medium",
                "evidence_type": "direct",
                "signals": ["configured_timestomping"],
                "evidence": {"path": "/target/a", "delta_seconds": 4},
            },
        )
        self.assertEqual(
            explain_map[6][0],
            {
                "rule_id": "CONFIGURED_TIMESTOMPING",
                "description": "Configured bulk timestomp branch",
                "confidence": "high",
                "evidence_type": "direct",
                "signals": ["configured_timestomping"],
                "evidence": {
                    "directory_hit_count": 2,
                    "bulk_extraction_dampened": True,
                },
            },
        )

        disabled_rules = deepcopy(BASE_RULES)
        self._detector_config(disabled_rules, "mft_timestomping")["enabled"] = False
        disabled_engine = self._engine(disabled_rules)
        disabled_signals = {}
        disabled_explain = {0: [], 1: []}
        disabled_engine._apply_timestomping_detection_sparse(
            pd.DataFrame(
                [
                    {"filename": "/target/a", "parser": "mft", "timestamp_desc": "$SI Creation"},
                    {"filename": "/target/a", "parser": "mft", "timestamp_desc": "$FN Creation"},
                ],
                index=pd.DatetimeIndex([start, start + pd.Timedelta(seconds=5)]),
            ),
            disabled_signals,
            disabled_explain,
        )
        self.assertEqual(disabled_signals, {})
        self.assertEqual(disabled_explain, {0: [], 1: []})

    def test_systemd_persistent_token_replacement_changes_runtime_matching(self):
        rules = deepcopy(BASE_RULES)
        command = self._systemd_config(rules)["branches"]["command_activity"]
        command["persistent_tokens"] = ["activate-unit-policy"]
        engine = self._engine(rules)
        _, signal_map, _ = self._apply_systemd(
            engine,
            [
                {"message": "systemctl enable legacy.service"},
                {"message": "activate-unit-policy custom.service"},
            ],
        )

        self.assertNotIn("systemd_service_persistence", signal_map.get(0, {}))
        self.assertEqual(signal_map[1]["systemd_service_persistence"], 1.0)

    def test_systemd_branch_order_mode_and_conditions_control_runtime(self):
        row = {
            "relative_path": "/etc/systemd/system/evil.service",
            "timestamp_desc": "Creation Time",
            "actor_cmd": "systemctl enable evil.service",
            "message": "enable requested",
            "hostname": "server1",
        }
        _, _, baseline_explain = self._apply_systemd(self._engine(), [row])
        self.assertIn("path", baseline_explain[0][0]["evidence"])

        rules = deepcopy(BASE_RULES)
        systemd = self._systemd_config(rules)
        systemd["branch_order"] = ["command_activity", "artifact_change"]
        _, _, ordered_explain = self._apply_systemd(self._engine(rules), [row])
        self.assertIn("command", ordered_explain[0][0]["evidence"])

        systemd["branch_mode"] = "all_matches"
        _, _, all_explain = self._apply_systemd(self._engine(rules), [row])
        self.assertEqual(len(all_explain[0]), 2)
        self.assertIn("command", all_explain[0][0]["evidence"])
        self.assertIn("path", all_explain[0][1]["evidence"])

        systemd["branches"]["artifact_change"]["conditions"] = {
            "any": [{"all": ["persistent_token"]}]
        }
        systemd["branch_mode"] = "first_match"
        systemd["branch_order"] = ["artifact_change", "command_activity"]
        _, _, configured_explain = self._apply_systemd(
            self._engine(rules),
            [{"message": "systemctl enable custom.service"}],
        )
        self.assertIn("path", configured_explain[0][0]["evidence"])

    def test_systemd_configured_input_fields_drive_candidate_selection(self):
        rules = deepcopy(BASE_RULES)
        systemd = self._systemd_config(rules)
        inputs = systemd["inputs"]
        inputs["path"]["fields"] = ["policy_path"]
        inputs["combined_text"]["fields"] = ["policy_text"]
        inputs["combined_text"]["first_existing"] = ["policy_url"]
        systemd["evidence"]["path"]["fields"] = ["policy_path"]
        systemd["evidence"]["command"]["fields"] = ["policy_text"]
        systemd["evidence"]["message"]["fields"] = ["policy_text"]
        systemd["evidence"]["hostname"]["field"] = "policy_host"
        engine = self._engine(rules)

        _, signal_map, explain_map = self._apply_systemd(
            engine,
            [
                {
                    "policy_path": "/etc/systemd/system/from-policy.service",
                    "timestamp_desc": "Creation Time",
                },
                {
                    "policy_text": "systemctl enable from-policy.service",
                    "policy_host": "configured-host",
                },
            ],
        )

        self.assertEqual(signal_map[0]["systemd_service_persistence"], 1.0)
        self.assertEqual(signal_map[1]["systemd_service_persistence"], 1.0)
        self.assertEqual(
            explain_map[1][0]["evidence"],
            {
                "command": "systemctl enable from-policy.service",
                "message": "systemctl enable from-policy.service",
                "hostname": "configured-host",
            },
        )

    def test_specialised_text_inputs_fall_back_per_row(self):
        engine = self._engine()
        _, systemd_signals, _ = self._apply_systemd(
            engine,
            [
                {
                    "actor_url": "",
                    "url": "systemctl enable fallback.service",
                }
            ],
        )
        self.assertEqual(
            systemd_signals[0]["systemd_service_persistence"], 1.0
        )

        frame = pd.DataFrame(
            [
                {
                    "filename": "/var/www/html/neutral.php",
                    "actor_url": "",
                    "url": "/admin?action=upload",
                }
            ],
            index=pd.DatetimeIndex([pd.Timestamp("2024-06-16T10:00:00Z")]),
        )
        signal_map = {}
        explain_map = {}
        engine._apply_webshell_artifact_policy_sparse(
            frame, signal_map, explain_map
        )
        self.assertEqual(signal_map[0]["webshell_artifact"], 1.0)

    def test_disabling_download_to_execution_removes_both_outputs(self):
        rules = deepcopy(BASE_RULES)
        self._download_config(rules)["enabled"] = False
        engine = self._engine(rules)
        signal_map, explain_map = self._apply_download(
            engine,
            self._download_frame(),
            "browser_download",
            "suspicious_execution",
        )

        self.assertNotIn("user_execution_after_download", signal_map[1])
        self.assertNotIn("ingress_tool_transfer", signal_map[1])
        self.assertEqual(explain_map[1], [])

    def test_download_lookback_mutation_changes_a_seven_minute_pair(self):
        short_rules = deepcopy(BASE_RULES)
        self._download_config(short_rules)["lookback"] = "5m"
        short_signals, _ = self._apply_download(
            self._engine(short_rules),
            self._download_frame("7m"),
            "browser_download",
            "suspicious_execution",
        )
        self.assertNotIn("user_execution_after_download", short_signals[1])

        long_rules = deepcopy(BASE_RULES)
        self._download_config(long_rules)["lookback"] = "10m"
        long_signals, _ = self._apply_download(
            self._engine(long_rules),
            self._download_frame("7m"),
            "browser_download",
            "suspicious_execution",
        )
        self.assertEqual(long_signals[1]["user_execution_after_download"], 1.0)
        self.assertEqual(long_signals[1]["ingress_tool_transfer"], 1.0)

    def test_download_source_and_target_mutation_replaces_the_old_signal_pair(self):
        rules = deepcopy(BASE_RULES)
        download = self._download_config(rules)
        download["source"]["any_signals"] = ["usb_device_connected"]
        download["target"]["any_signals"] = ["service_stop"]
        engine = self._engine(rules)
        frame = self._download_frame()

        old_signals, _ = self._apply_download(
            engine,
            frame,
            "browser_download",
            "suspicious_execution",
        )
        self.assertNotIn("user_execution_after_download", old_signals[1])
        self.assertNotIn("ingress_tool_transfer", old_signals[1])

        new_signals, _ = self._apply_download(
            engine,
            frame,
            "usb_device_connected",
            "service_stop",
        )
        self.assertEqual(new_signals[1]["user_execution_after_download"], 1.0)
        self.assertEqual(new_signals[1]["ingress_tool_transfer"], 1.0)

    def test_download_hostname_scope_uses_configured_host_field(self):
        rules = deepcopy(BASE_RULES)
        download = self._download_config(rules)
        download["key"].update(
            {"scope": "hostname", "host_field": "policy_host"}
        )
        engine = self._engine(rules)
        self.assertIn("policy_host", engine.required_fields)

        different_hosts = self._download_frame()
        different_hosts["policy_host"] = ["host-a", "host-b"]
        different_signals, _ = self._apply_download(
            engine,
            different_hosts,
            "browser_download",
            "suspicious_execution",
        )
        self.assertNotIn("user_execution_after_download", different_signals[1])

        same_host = self._download_frame()
        same_host["policy_host"] = ["configured-host", "configured-host"]
        same_signals, same_explain = self._apply_download(
            engine,
            same_host,
            "browser_download",
            "suspicious_execution",
        )
        self.assertEqual(same_signals[1]["user_execution_after_download"], 1.0)
        self.assertEqual(
            same_explain[1][0]["evidence"]["hostname"],
            "configured-host",
        )

    def test_explanations_use_exact_configured_rule_metadata(self):
        rules = deepcopy(BASE_RULES)
        systemd = self._systemd_config(rules)
        systemd["branches"]["artifact_change"]["description"] = "Configured artifact explanation"
        systemd["branches"]["artifact_change"]["confidence"] = "low"
        systemd["emissions"][0]["rule_id"] = "CONFIGURED_SYSTEMD_RULE"

        download = self._download_config(rules)
        download["emissions"][0].update(
            {
                "rule_id": "CONFIGURED_DOWNLOAD_EXECUTION",
                "description": "Configured download execution explanation",
                "confidence": "high",
            }
        )
        download["emissions"][1].update(
            {
                "rule_id": "CONFIGURED_INGRESS_TRANSFER",
                "description": "Configured ingress transfer explanation",
                "confidence": "low",
            }
        )
        engine = self._engine(rules)

        _, systemd_signals, systemd_explain = self._apply_systemd(
            engine,
            [
                {
                    "relative_path": "/etc/systemd/system/evil.service",
                    "timestamp_desc": "Creation Time",
                    "hostname": "server1",
                }
            ],
        )
        self.assertEqual(systemd_signals[0]["systemd_service_persistence"], 1.0)
        self.assertEqual(
            systemd_explain[0],
            [
                {
                    "rule_id": "CONFIGURED_SYSTEMD_RULE",
                    "description": "Configured artifact explanation",
                    "confidence": "low",
                    "evidence_type": "direct",
                    "signals": ["systemd_service_persistence"],
                    "evidence": {
                        "path": "/etc/systemd/system/evil.service",
                        "timestamp_desc": "Creation Time",
                        "hostname": "server1",
                    },
                }
            ],
        )

        frame = self._download_frame("5m")
        download_signals, download_explain = self._apply_download(
            engine,
            frame,
            "browser_download",
            "suspicious_execution",
        )
        self.assertEqual(download_signals[1]["user_execution_after_download"], 1.0)
        self.assertEqual(
            download_explain[1],
            [
                {
                    "rule_id": "CONFIGURED_DOWNLOAD_EXECUTION",
                    "description": "Configured download execution explanation",
                    "confidence": "high",
                    "evidence_type": "contextual",
                    "signals": ["user_execution_after_download"],
                    "evidence": {
                        "filename": "payload.exe",
                        "download_timestamp": frame.index[0].isoformat(),
                        "execution_timestamp": frame.index[1].isoformat(),
                        "hostname": "victim1",
                    },
                },
                {
                    "rule_id": "CONFIGURED_INGRESS_TRANSFER",
                    "description": "Configured ingress transfer explanation",
                    "confidence": "low",
                    "evidence_type": "contextual",
                    "signals": ["ingress_tool_transfer"],
                    "evidence": {
                        "filename": "payload.exe",
                        "download_timestamp": frame.index[0].isoformat(),
                        "execution_timestamp": frame.index[1].isoformat(),
                        "hostname": "victim1",
                    },
                },
            ],
        )

    @staticmethod
    def _temporal_composite_fixture():
        frame = pd.DataFrame(
            {
                "hostname": ["victim1"] * 8,
                "filename": [
                    "/tmp/support.txt",
                    "/tmp/encrypted.bin",
                    "/tmp/transfer-one.bin",
                    "/tmp/transfer-two.bin",
                    "/tmp/lsass.dmp",
                    "/tmp/lsass.dmp.zip",
                    "/home/user/Login Data",
                    "/tmp/staged.txt",
                ],
                "message": ["", "", "", "", "", "", "", "copy Login Data /tmp/loot"],
                "command_line": [""] * 8,
            },
            index=pd.date_range("2024-06-16T13:00:00Z", periods=8, freq="min"),
        )
        signal_map = {
            0: {"defender_disabled": 1.0, "sensitive_file_access": 1.0},
            1: {"mass_file_modification": 1.0},
            2: {"transfer_execution": 1.0},
            3: {"transfer_execution": 1.0},
            4: {"credential_dumping": 1.0},
            5: {"archive_created": 1.0},
            6: {"password_store_access": 1.0},
            7: {},
        }
        return frame, signal_map

    def test_configured_temporal_executors_preserve_all_four_runtime_branches(self):
        engine = self._engine()
        frame, signal_map = self._temporal_composite_fixture()
        signal_map, explain_map = self._apply_temporal_policies(
            engine,
            frame,
            signal_map,
        )

        self.assertEqual(signal_map[1]["ransomware_impact"], 1.0)
        self.assertEqual(signal_map[3]["automated_exfiltration"], 1.0)
        self.assertEqual(signal_map[4]["credential_dump_collection"], 1.0)
        self.assertEqual(signal_map[6]["password_store_exfil_chain"], 1.0)
        self.assertEqual(
            next(
                item for item in explain_map[1]
                if item["rule_id"] == "RANSOMWARE_IMPACT"
            )["evidence"]["support_timestamp"],
            frame.index[0].isoformat(),
        )
        self.assertEqual(
            next(
                item for item in explain_map[3]
                if item["rule_id"] == "AUTOMATED_EXFILTRATION"
            )["evidence"]["count_in_window"],
            2,
        )
        self.assertEqual(
            next(
                item for item in explain_map[4]
                if item["rule_id"] == "CREDENTIAL_DUMP_COLLECTION"
            )["evidence"]["source_timestamp"],
            frame.index[4].isoformat(),
        )

        note_frame = pd.DataFrame(
            {
                "hostname": ["victim1", "victim1"],
                "filename": ["/tmp/encrypted.bin", "/tmp/README_DECRYPT.txt"],
            },
            index=pd.date_range("2024-06-16T14:00:00Z", periods=2, freq="min"),
        )
        note_signals, note_explain = self._apply_temporal_policies(
            engine,
            note_frame,
            {0: {"mass_file_modification": 1.0}, 1: {}},
        )
        self.assertEqual(note_signals[0]["ransomware_impact"], 1.0)
        note_item = next(
            item for item in note_explain[0]
            if item["rule_id"] == "RANSOMWARE_IMPACT"
        )
        self.assertIn("ransom-note creation", note_item["description"])
        self.assertEqual(
            note_item["evidence"]["ransom_note_timestamp"],
            note_frame.index[1].isoformat(),
        )

    def test_temporal_executor_inputs_outputs_metadata_and_evidence_are_authoritative(self):
        rules = deepcopy(BASE_RULES)
        weights = deepcopy(BASE_WEIGHTS)
        ransomware = self._ransomware_config(rules)
        ransomware["source"]["any_signals"] = ["usb_device_connected"]
        ransomware["branches"]["prior_support"]["any_signals"] = ["service_stop"]
        ransomware["branches"]["prior_support"]["description"] = (
            "Configured ransomware support"
        )
        ransomware["emissions"][0].update(
            {
                "name": "configured_ransomware_impact",
                "value": 0.5,
                "rule_id": "CONFIGURED_RANSOMWARE_IMPACT",
                "confidence": "high",
            }
        )
        ransomware["evidence"] = {
            "source_signals": {"resolver": "matched_source_signals"},
            "support_timestamp": {"resolver": "support_timestamp"},
        }
        weights["weights"]["configured_ransomware_impact"] = 0

        automated_exfiltration = self._automated_exfiltration_config(rules)
        automated_exfiltration["count"]["any_signals"] = ["usb_device_connected"]
        automated_exfiltration["support"]["window_any_signals"] = ["service_stop"]
        automated_exfiltration["support"]["current_any_signals"] = [
            "account_access_removal"
        ]
        automated_exfiltration["emissions"][0].update(
            {
                "name": "configured_automated_exfiltration",
                "value": 0.75,
                "rule_id": "CONFIGURED_AUTOMATED_EXFILTRATION",
                "description": "Configured counted-window explanation",
                "confidence": "medium",
            }
        )
        automated_exfiltration["evidence"] = {
            "count_in_window": {"resolver": "count_in_window"},
        }
        weights["weights"]["configured_automated_exfiltration"] = 0

        credential = self._credential_collection_config(rules)
        credential["source"]["any_signals"] = ["usb_device_connected"]
        credential["inputs"]["path"]["fields"] = ["policy_path"]
        credential["inputs"]["combined_text"]["fields"] = ["policy_text"]
        credential["labels"]["contains_any"] = ["artifact-x"]
        credential["copy_stage"]["command_tokens"] = ["configured-copy "]
        credential["copy_stage"]["support_text_tokens"] = ["artifact-x"]
        credential["copy_stage"]["support_signals"] = ["service_stop"]
        credential["follow_on"] = {
            "any_signals": ["account_access_removal"],
            "allow_unlabelled": False,
            "minimum_signal_value_exclusive": 0,
        }
        credential["emissions"][0].update(
            {
                "name": "configured_credential_collection",
                "value": 0.625,
                "rule_id": "CONFIGURED_CREDENTIAL_COLLECTION",
                "description": "Configured artifact follow-on explanation",
                "confidence": "low",
            }
        )
        credential["evidence"] = {
            "source_timestamp": {"resolver": "source_timestamp"},
        }
        weights["weights"]["configured_credential_collection"] = 0

        engine = self._engine(rules, weights)
        frame = pd.DataFrame(
            {
                "hostname": ["victim1", "victim1"],
                "policy_path": ["/tmp/artifact-x", "/tmp/artifact-x.archive"],
                "policy_text": ["", ""],
            },
            index=pd.date_range("2024-06-16T15:00:00Z", periods=2, freq="min"),
        )
        signal_map, explain_map = self._apply_temporal_policies(
            engine,
            frame,
            {
                0: {"usb_device_connected": 1.0, "service_stop": 1.0},
                1: {
                    "usb_device_connected": 1.0,
                    "account_access_removal": 1.0,
                },
            },
        )

        self.assertEqual(signal_map[0]["configured_ransomware_impact"], 0.5)
        self.assertNotIn("ransomware_impact", signal_map[0])
        ransomware_item = next(
            item for item in explain_map[0]
            if item["rule_id"] == "CONFIGURED_RANSOMWARE_IMPACT"
        )
        self.assertEqual(ransomware_item["description"], "Configured ransomware support")
        self.assertEqual(ransomware_item["confidence"], "high")
        self.assertEqual(
            set(ransomware_item["evidence"]),
            {"source_signals", "support_timestamp"},
        )

        self.assertEqual(
            signal_map[1]["configured_automated_exfiltration"],
            0.75,
        )
        self.assertNotIn("automated_exfiltration", signal_map[1])
        counted_item = next(
            item for item in explain_map[1]
            if item["rule_id"] == "CONFIGURED_AUTOMATED_EXFILTRATION"
        )
        self.assertEqual(counted_item["description"], "Configured counted-window explanation")
        self.assertEqual(counted_item["evidence"], {"count_in_window": 2})

        self.assertEqual(signal_map[0]["configured_credential_collection"], 0.625)
        self.assertNotIn("credential_dump_collection", signal_map[0])
        artifact_item = next(
            item for item in explain_map[0]
            if item["rule_id"] == "CONFIGURED_CREDENTIAL_COLLECTION"
        )
        self.assertEqual(
            artifact_item["description"],
            "Configured artifact follow-on explanation",
        )
        self.assertEqual(artifact_item["confidence"], "low")
        self.assertEqual(
            artifact_item["evidence"],
            {"source_timestamp": frame.index[0].isoformat()},
        )

    def test_temporal_signal_minimums_are_yaml_authoritative(self):
        rules = deepcopy(BASE_RULES)
        download = self._download_config(rules)
        download["source"]["minimum_signal_value_exclusive"] = 1
        download["target"]["minimum_signal_value_exclusive"] = 1
        webshell = self._webshell_config(rules)
        webshell["source"]["minimum_signal_value_exclusive"] = 1
        webshell["target"]["minimum_signal_value_exclusive"] = 1
        ransomware = self._ransomware_config(rules)
        ransomware["source"]["minimum_signal_value_exclusive"] = 1
        ransomware["branches"]["prior_support"][
            "minimum_signal_value_exclusive"
        ] = 1
        credential = self._credential_collection_config(rules)
        credential["source"]["minimum_signal_value_exclusive"] = 1
        credential["copy_stage"]["minimum_signal_value_exclusive"] = 1
        credential["follow_on"]["minimum_signal_value_exclusive"] = 1
        engine = self._engine(rules)

        download_frame = self._download_frame()
        for values, expected in (((1, 2), False), ((2, 1), False), ((2, 2), True)):
            signals = {
                0: {"browser_download": values[0]},
                1: {"suspicious_execution": values[1]},
            }
            self._apply_temporal_policies(engine, download_frame, signals)
            self.assertEqual("user_execution_after_download" in signals[1], expected)

        sequence_frame = pd.DataFrame(
            [{}, {}],
            index=pd.date_range("2024-06-16T12:00:00Z", periods=2, freq="min"),
        )
        for values, expected in (((1, 2), False), ((2, 1), False), ((2, 2), True)):
            signals = {
                0: {"webshell_artifact": values[0]},
                1: {"web_exploitation_hint": values[1]},
            }
            self._apply_temporal_policies(engine, sequence_frame, signals)
            self.assertEqual("webshell_activity" in signals[1], expected)

        ransomware_frame = pd.DataFrame(
            [{"filename": "/tmp/support"}, {"filename": "/tmp/encrypted"}],
            index=pd.date_range("2024-06-16T13:00:00Z", periods=2, freq="min"),
        )
        for values, expected in (((1, 2), False), ((2, 1), False), ((2, 2), True)):
            signals = {
                0: {"defender_disabled": values[0]},
                1: {"mass_file_modification": values[1]},
            }
            self._apply_temporal_policies(engine, ransomware_frame, signals)
            self.assertEqual("ransomware_impact" in signals[1], expected)

        follow_frame = pd.DataFrame(
            [
                {"filename": "/tmp/lsass.dmp", "message": ""},
                {"filename": "/tmp/lsass.dmp.zip", "message": ""},
            ],
            index=pd.date_range("2024-06-16T14:00:00Z", periods=2, freq="min"),
        )
        for values, expected in (((1, 2), False), ((2, 1), False), ((2, 2), True)):
            signals = {
                0: {"credential_dumping": values[0]},
                1: {"archive_created": values[1]},
            }
            self._apply_temporal_policies(engine, follow_frame, signals)
            self.assertEqual("credential_dump_collection" in signals[0], expected)

        copy_frame = follow_frame.copy()
        copy_frame.iloc[1, copy_frame.columns.get_loc("message")] = (
            "copy /tmp/lsass.dmp"
        )
        for support_value, expected in ((1, False), (2, True)):
            signals = {
                0: {"credential_dumping": 2},
                1: {"credential_dumping": support_value},
            }
            self._apply_temporal_policies(engine, copy_frame, signals)
            self.assertEqual("credential_dump_collection" in signals[0], expected)

    def test_disabling_each_temporal_policy_suppresses_its_configured_output(self):
        for detector_id, output_name in (
            ("ransomware_impact", "ransomware_impact"),
            ("automated_exfiltration", "automated_exfiltration"),
            ("credential_dump_collection", "credential_dump_collection"),
            ("password_store_exfil_chain", "password_store_exfil_chain"),
        ):
            with self.subTest(detector_id=detector_id):
                rules = deepcopy(BASE_RULES)
                self._detector_config(rules, detector_id)["enabled"] = False
                engine = self._engine(rules)
                frame, signal_map = self._temporal_composite_fixture()
                signal_map, explain_map = self._apply_temporal_policies(
                    engine,
                    frame,
                    signal_map,
                )
                self.assertTrue(
                    all(output_name not in signals for signals in signal_map.values())
                )
                self.assertTrue(
                    all(
                        output_name not in item.get("signals", [])
                        for items in explain_map.values()
                        for item in items
                    )
                )

    def test_masquerading_gate_enablement_threshold_and_evidence_are_authoritative(self):
        index = pd.DatetimeIndex([pd.Timestamp("2024-06-16T14:00:00Z")])
        frame = pd.DataFrame(
            [{
                "relative_path": "/tmp/svchost.exe",
                "actor_cmd": " /tmp/svchost.exe -k demo ",
                "hostname": " victim1 ",
            }],
            index=index,
        )

        engine = self._engine()
        signal_map = {0: {"exec_system_binary_in_user_path": 1.0}}
        explain_map = {0: []}
        engine._apply_policy_signal_gates_sparse(frame, signal_map, explain_map)
        self.assertEqual(signal_map[0]["masquerading"], 1.0)
        self.assertEqual(
            explain_map[0],
            [{
                "rule_id": "MASQUERADING",
                "description": (
                    "Trusted or system binary name executed from an unexpected "
                    "user-writable or suspicious path"
                ),
                "confidence": "medium",
                "evidence_type": "direct",
                "signals": ["masquerading"],
                "evidence": {
                    "path": "/tmp/svchost.exe",
                    "command": "/tmp/svchost.exe -k demo",
                    "hostname": "victim1",
                },
            }],
        )

        threshold_rules = deepcopy(BASE_RULES)
        self._masquerading_config(threshold_rules)["conditions"][
            "minimum_value_exclusive"
        ] = 1
        threshold_engine = self._engine(threshold_rules)
        threshold_signals = {0: {"exec_system_binary_in_user_path": 1.0}}
        threshold_engine._apply_policy_signal_gates_sparse(frame, threshold_signals, {0: []})
        self.assertNotIn("masquerading", threshold_signals[0])

        disabled_rules = deepcopy(BASE_RULES)
        self._masquerading_config(disabled_rules)["enabled"] = False
        disabled_engine = self._engine(disabled_rules)
        disabled_signals = {0: {"exec_system_binary_in_user_path": 1.0}}
        disabled_engine._apply_policy_signal_gates_sparse(frame, disabled_signals, {0: []})
        self.assertNotIn("masquerading", disabled_signals[0])
        self.assertNotIn("MASQUERADING", disabled_engine.rule_emit_signals)

    def test_automated_collection_requires_one_match_from_each_configured_group(self):
        engine = self._engine()
        frame = pd.DataFrame(
            [
                {"hostname": "host0"},
                {"hostname": "host1"},
                {"hostname": "host2"},
                {"hostname": "host3"},
                {"hostname": "host4"},
                {"hostname": "host5"},
            ],
            index=pd.date_range(
                "2024-06-16T14:10:00Z", periods=6, freq="min"
            ),
        )
        signal_map = {
            0: {"sensitive_file_access": 1.0},
            1: {"archive_created": 1.0},
            2: {
                "sensitive_file_access": 1.0,
                "archive_created": 1.0,
            },
            3: {
                "password_store_access": 1.0,
                "repeated_scheduled_exec": 1.0,
            },
            4: {
                "sensitive_file_access": 1.0,
                "password_store_access": 1.0,
            },
            5: {
                "archive_created": 1.0,
                "large_archive_created": 1.0,
                "repeated_scheduled_exec": 1.0,
            },
        }
        explain_map = {row: [] for row in range(len(frame))}

        engine._apply_policy_signal_gates_sparse(frame, signal_map, explain_map)

        self.assertNotIn("automated_collection", signal_map[0])
        self.assertNotIn("automated_collection", signal_map[1])
        self.assertEqual(signal_map[2]["automated_collection"], 1.0)
        self.assertEqual(signal_map[3]["automated_collection"], 1.0)
        self.assertNotIn("automated_collection", signal_map[4])
        self.assertNotIn("automated_collection", signal_map[5])
        self.assertEqual(
            next(
                entry
                for entry in explain_map[2]
                if entry["rule_id"] == "AUTOMATED_COLLECTION"
            ),
            {
                "rule_id": "AUTOMATED_COLLECTION",
                "description": (
                    "Sensitive access combined with archiving or repeated "
                    "scheduled execution suggests automated collection"
                ),
                "confidence": "low",
                "evidence_type": "contextual",
                "signals": ["automated_collection"],
                "evidence": {"hostname": "host2", "path": ""},
            },
        )

    def test_automated_collection_metadata_output_evidence_and_disablement_are_authoritative(self):
        rules = deepcopy(BASE_RULES)
        weights = deepcopy(BASE_WEIGHTS)
        detector = self._automated_collection_config(rules)
        detector["evidence_type"] = "direct"
        detector["emissions"][0].update(
            {
                "name": "configured_automated_collection",
                "value": 2,
                "rule_id": "CONFIGURED_AUTOMATED_COLLECTION",
                "description": "Configured grouped collection evidence",
                "confidence": "high",
            }
        )
        detector["evidence"] = {
            "configured_host": {
                "resolver": "row_field",
                "field": "policy_host",
            },
            "configured_path": {
                "resolver": "best_effort_file_path",
                "fields": ["policy_path"],
            },
            "derived_from": {"resolver": "matched_signals"},
        }
        weights["weights"]["configured_automated_collection"] = 2
        engine = self._engine(rules, weights)
        frame = pd.DataFrame(
            [{"policy_host": " configured-host ", "policy_path": " /tmp/data.zip "}],
            index=pd.DatetimeIndex([pd.Timestamp("2024-06-16T14:20:00Z")]),
        )
        signal_map = {
            0: {
                "password_store_access": 1.0,
                "large_archive_created": 1.0,
            }
        }
        explain_map = {0: []}

        engine._apply_policy_signal_gates_sparse(frame, signal_map, explain_map)

        self.assertNotIn("automated_collection", signal_map[0])
        self.assertEqual(signal_map[0]["configured_automated_collection"], 2.0)
        self.assertEqual(
            explain_map[0],
            [
                {
                    "rule_id": "CONFIGURED_AUTOMATED_COLLECTION",
                    "description": "Configured grouped collection evidence",
                    "confidence": "high",
                    "evidence_type": "direct",
                    "signals": ["configured_automated_collection"],
                    "evidence": {
                        "configured_host": "configured-host",
                        "configured_path": "/tmp/data.zip",
                        "derived_from": (
                            "large_archive_created,password_store_access"
                        ),
                    },
                }
            ],
        )
        self.assertEqual(
            engine.rule_emit_signals["CONFIGURED_AUTOMATED_COLLECTION"],
            ["configured_automated_collection"],
        )
        self.assertNotIn("AUTOMATED_COLLECTION", engine.rule_emit_signals)
        self.assertTrue({"policy_host", "policy_path"}.issubset(engine.required_fields))

        disabled_rules = deepcopy(BASE_RULES)
        self._automated_collection_config(disabled_rules)["enabled"] = False
        disabled_engine = self._engine(disabled_rules)
        disabled_signals = {
            0: {
                "sensitive_file_access": 1.0,
                "archive_created": 1.0,
            }
        }
        disabled_explain = {0: []}
        disabled_engine._apply_policy_signal_gates_sparse(
            frame,
            disabled_signals,
            disabled_explain,
        )
        self.assertNotIn("automated_collection", disabled_signals[0])
        self.assertEqual(disabled_explain[0], [])
        self.assertNotIn("AUTOMATED_COLLECTION", disabled_engine.rule_emit_signals)

    def test_automated_collection_group_validation_reports_precise_paths(self):
        cases = []

        rules = deepcopy(BASE_RULES)
        self._automated_collection_config(rules)["conditions"]["groups"] = []
        cases.append(
            (
                "empty groups",
                rules,
                r"detector_policy\.detectors\.automated_collection\.conditions\.groups: expected a non-empty list",
            )
        )

        rules = deepcopy(BASE_RULES)
        self._automated_collection_config(rules)["conditions"]["groups"][0][
            "signals"
        ] = []
        cases.append(
            (
                "empty group",
                rules,
                r"detector_policy\.detectors\.automated_collection\.conditions\.groups\[0\]\.signals: expected a non-empty list",
            )
        )

        rules = deepcopy(BASE_RULES)
        self._automated_collection_config(rules)["conditions"]["groups"][0][
            "signals"
        ].append("usb_device_connected")
        cases.append(
            (
                "undeclared group member",
                rules,
                r"detector_policy\.detectors\.automated_collection\.conditions\.groups\[0\]\.signals: signal\(s\) are not declared.*usb_device_connected",
            )
        )

        rules = deepcopy(BASE_RULES)
        self._automated_collection_config(rules)["conditions"]["groups"][1][
            "signals"
        ].append("sensitive_file_access")
        cases.append(
            (
                "member in two groups",
                rules,
                r"detector_policy\.detectors\.automated_collection\.conditions\.groups\[1\]\.signals: signal\(s\) already belong to another group.*sensitive_file_access",
            )
        )

        rules = deepcopy(BASE_RULES)
        self._automated_collection_config(rules)["conditions"]["groups"][0][
            "signals"
        ].remove("password_store_access")
        cases.append(
            (
                "unassigned input",
                rules,
                r"detector_policy\.detectors\.automated_collection\.conditions\.groups: input signal\(s\) are not assigned to a group.*password_store_access",
            )
        )

        for label, rules_doc, error_path in cases:
            with self.subTest(label=label):
                with self.assertRaisesRegex(ValueError, error_path):
                    self._engine(rules_doc)

    def test_webshell_sequence_uses_configured_window_global_scope_and_metadata(self):
        start = pd.Timestamp("2024-06-16T15:00:00Z")
        frame = pd.DataFrame(
            [{"hostname": "source-host"}, {"hostname": "target-host"}],
            index=pd.DatetimeIndex([start, start + pd.Timedelta("7m")]),
        )

        short_rules = deepcopy(BASE_RULES)
        self._webshell_config(short_rules)["lookback"] = "5m"
        short_signals = {
            0: {"webshell_artifact": 1.0},
            1: {"web_exploitation_hint": 1.0},
        }
        self._engine(short_rules)._apply_deadbox_temporal_composites_sparse(
            frame, short_signals, {0: [], 1: []}
        )
        self.assertNotIn("webshell_activity", short_signals[1])

        long_rules = deepcopy(BASE_RULES)
        webshell = self._webshell_config(long_rules)
        webshell["lookback"] = "10m"
        webshell["emissions"][0].update(
            {
                "rule_id": "CONFIGURED_WEBSHELL_SEQUENCE",
                "description": "Configured webshell correlation",
                "confidence": "low",
            }
        )
        long_engine = self._engine(long_rules)
        long_signals = {
            0: {"webshell_artifact": 1.0},
            1: {"web_exploitation_hint": 1.0},
        }
        long_explain = {0: [], 1: []}
        long_engine._apply_deadbox_temporal_composites_sparse(
            frame, long_signals, long_explain
        )
        self.assertEqual(long_signals[1]["webshell_activity"], 1.0)
        configured = next(
            item for item in long_explain[1]
            if item["rule_id"] == "CONFIGURED_WEBSHELL_SEQUENCE"
        )
        self.assertEqual(configured["description"], "Configured webshell correlation")
        self.assertEqual(configured["confidence"], "low")
        self.assertEqual(
            configured["evidence"],
            {
                "hostname": "target-host",
                "artifact_timestamp": frame.index[0].isoformat(),
                "request_timestamp": frame.index[1].isoformat(),
            },
        )

    def test_webshell_policy_disablement_does_not_disable_web_upload_chain(self):
        rules = deepcopy(BASE_RULES)
        webshell = self._webshell_config(rules)
        webshell["enabled"] = False
        webshell["source"]["any_signals"] = ["usb_device_connected"]
        webshell["lookback"] = "5m"
        engine = self._engine(rules)
        start = pd.Timestamp("2024-06-16T16:00:00Z")
        frame = pd.DataFrame(
            [
                {"relative_path": "/var/www/shell.php", "hostname": "a"},
                {"relative_path": "/var/www/shell.php", "hostname": "b"},
            ],
            index=pd.DatetimeIndex([start, start + pd.Timedelta("20m")]),
        )
        signal_map = {
            0: {"webshell_artifact": 1.0},
            1: {"suspicious_execution": 1.0},
        }
        engine._apply_deadbox_temporal_composites_sparse(
            frame, signal_map, {0: [], 1: []}
        )
        self.assertEqual(signal_map[1]["web_upload_execution_chain"], 1.0)
        self.assertNotIn("webshell_activity", signal_map[1])

    def test_web_upload_chain_window_context_signals_and_metadata_are_authoritative(self):
        start = pd.Timestamp("2024-06-16T16:30:00Z")
        frame = pd.DataFrame(
            [
                {"policy_context": "source"},
                {"policy_context": "custom-web-context"},
            ],
            index=pd.DatetimeIndex([start, start + pd.Timedelta("7m")]),
        )

        short_rules = deepcopy(BASE_RULES)
        self._web_upload_chain_config(short_rules)["lookback"] = "5m"
        short_signals = {
            0: {"webshell_artifact": 1.0},
            1: {"suspicious_execution": 1.0},
        }
        self._engine(short_rules)._apply_deadbox_temporal_composites_sparse(
            frame, short_signals, {0: [], 1: []}
        )
        self.assertNotIn("web_upload_execution_chain", short_signals[1])

        configured_rules = deepcopy(BASE_RULES)
        chain = self._web_upload_chain_config(configured_rules)
        chain["lookback"] = "10m"
        chain["target"]["any_signals"] = ["service_stop"]
        chain["target"]["where"] = {
            "match": "any",
            "combined_text": {
                "resolver": "concat_lower",
                "fields": ["policy_context"],
                "contains_any": ["custom-web-context"],
            },
        }
        chain["emissions"][0].update(
            {
                "value": 2,
                "rule_id": "CONFIGURED_WEB_UPLOAD_CHAIN",
                "description": "Configured upload execution correlation",
                "confidence": "high",
            }
        )
        configured_engine = self._engine(configured_rules)
        old_signals = {
            0: {"webshell_artifact": 1.0},
            1: {"suspicious_execution": 1.0},
        }
        configured_engine._apply_deadbox_temporal_composites_sparse(
            frame, old_signals, {0: [], 1: []}
        )
        self.assertNotIn("web_upload_execution_chain", old_signals[1])

        configured_signals = {
            0: {"webshell_artifact": 1.0},
            1: {"service_stop": 1.0},
        }
        configured_explain = {0: [], 1: []}
        configured_engine._apply_deadbox_temporal_composites_sparse(
            frame, configured_signals, configured_explain
        )
        self.assertEqual(
            configured_signals[1]["web_upload_execution_chain"], 2.0
        )
        explanation = next(
            item
            for item in configured_explain[1]
            if item["rule_id"] == "CONFIGURED_WEB_UPLOAD_CHAIN"
        )
        self.assertEqual(
            explanation["description"],
            "Configured upload execution correlation",
        )
        self.assertEqual(explanation["confidence"], "high")
        self.assertEqual(
            explanation["evidence"],
            {
                "hostname": "",
                "artifact_timestamp": frame.index[0].isoformat(),
                "execution_timestamp": frame.index[1].isoformat(),
            },
        )

        disabled_rules = deepcopy(configured_rules)
        self._web_upload_chain_config(disabled_rules)["enabled"] = False
        disabled_signals = {
            0: {"webshell_artifact": 1.0},
            1: {"service_stop": 1.0},
        }
        self._engine(disabled_rules)._apply_deadbox_temporal_composites_sparse(
            frame, disabled_signals, {0: [], 1: []}
        )
        self.assertNotIn("web_upload_execution_chain", disabled_signals[1])

    def test_webshell_artifact_inputs_conditions_support_metadata_and_disablement_are_authoritative(self):
        rules = deepcopy(BASE_RULES)
        weights = deepcopy(BASE_WEIGHTS)
        artifact = self._webshell_artifact_config(rules)
        artifact["inputs"]["path"]["fields"] = ["policy_path"]
        artifact["inputs"]["combined_text"]["fields"] = ["policy_text"]
        artifact["inputs"]["combined_text"]["first_existing"] = ["policy_url"]
        conditions = artifact["conditions"]
        conditions["path_contains"] = ["/policy-root/"]
        conditions["extension_in"] = [".policy"]
        support = conditions["support"]
        support["basename_contains"] = ["configured-name"]
        support["combined_text_contains"] = ["configured upload"]
        support["signals_any"] = ["file_created"]
        support["minimum_signal_value_exclusive"] = 1
        artifact["emissions"][0].update(
            {
                "name": "configured_webshell_artifact",
                "value": 2,
                "rule_id": "CONFIGURED_WEBSHELL_ARTIFACT",
                "description": "Configured web-shell artefact",
                "confidence": "high",
            }
        )
        self._webshell_config(rules)["source"]["any_signals"] = [
            "configured_webshell_artifact"
        ]
        self._web_upload_chain_config(rules)["source"]["any_signals"] = [
            "configured_webshell_artifact"
        ]
        weights["weights"]["configured_webshell_artifact"] = 3
        artifact["evidence"]["path"]["fields"] = ["policy_path"]
        artifact["evidence"]["filename"]["field"] = "policy_name"
        artifact["evidence"]["message"]["field"] = "policy_message"
        artifact["evidence"]["message"]["max_chars"] = 10

        engine = self._engine(rules, weights)
        frame = pd.DataFrame(
            [
                {
                    "policy_path": "/policy-root/configured-name.policy",
                    "policy_name": "configured-name.policy",
                },
                {
                    "policy_path": "/policy-root/neutral.policy",
                    "policy_text": "configured upload trail",
                    "policy_message": "configured upload trail",
                },
                {"policy_path": "/policy-root/supported.policy"},
                {"policy_path": "/var/www/html/cmd.php"},
                {"policy_path": "/policy-root/configured-name.txt"},
                {"policy_path": "/policy-root/threshold.policy"},
            ],
            index=pd.date_range("2024-06-16T16:50:00Z", periods=6, freq="s"),
        )
        signal_map = {
            2: {"file_created": 2.0},
            5: {"file_created": 1.0},
        }
        explain_map = {}
        engine._apply_webshell_artifact_policy_sparse(
            frame, signal_map, explain_map
        )

        for row_i in (0, 1, 2):
            self.assertEqual(
                signal_map[row_i]["configured_webshell_artifact"], 2.0
            )
        for row_i in (3, 4, 5):
            self.assertNotIn(
                "configured_webshell_artifact", signal_map.get(row_i, {})
            )
        explanation = explain_map[1][0]
        self.assertEqual(explanation["rule_id"], "CONFIGURED_WEBSHELL_ARTIFACT")
        self.assertEqual(explanation["description"], "Configured web-shell artefact")
        self.assertEqual(explanation["confidence"], "high")
        self.assertEqual(explanation["evidence"]["message"], "configured")
        self.assertTrue(
            {
                "policy_path", "policy_text", "policy_url", "policy_name",
                "policy_message",
            }.issubset(engine.required_fields)
        )
        self.assertEqual(
            engine.rule_emit_signals["CONFIGURED_WEBSHELL_ARTIFACT"],
            ["configured_webshell_artifact"],
        )
        self.assertNotIn("WEBSHELL_ARTIFACT", engine.rule_emit_signals)

        disabled_rules = deepcopy(BASE_RULES)
        self._webshell_artifact_config(disabled_rules)["enabled"] = False
        self._webshell_config(disabled_rules)["enabled"] = False
        self._web_upload_chain_config(disabled_rules)["enabled"] = False
        disabled_engine = self._engine(disabled_rules)
        disabled_signals = {}
        disabled_engine._apply_webshell_artifact_policy_sparse(
            pd.DataFrame(
                [{"relative_path": "/var/www/html/cmd.php"}],
                index=pd.DatetimeIndex(
                    [pd.Timestamp("2024-06-16T16:55:00Z")]
                ),
            ),
            disabled_signals,
            {},
        )
        self.assertEqual(disabled_signals, {})
        self.assertNotIn("WEBSHELL_ARTIFACT", disabled_engine.rule_emit_signals)

    def test_web_request_fields_regex_emission_metadata_and_disablement_are_authoritative(self):
        rules = deepcopy(BASE_RULES)
        web = self._web_request_config(rules)
        web["inputs"]["request"] = "policy_request"
        web["outputs"]["attack_indicators"] = "chronosift_policy_indicators"
        web["indicators"]["sqli"]["prefix"] = "configured:"
        web["outcomes"]["web"]["attempt_when"][
            "indicator_prefixes_any"
        ] = ["configured:"]
        web["indicators"]["sqli"]["patterns"] = [
            {
                "name": "configured_syntax",
                "regex": r"(?i)\bconfigured_marker\b",
            }
        ]
        web["emissions"]["sqli_attempt"].update(
            {
                "value": 2,
                "rule_id": "CONFIGURED_WEB_ATTEMPT",
                "description": "Configured web syntax matched",
                "confidence": "low",
            }
        )
        engine = self._engine(rules)
        frame = pd.DataFrame(
            [
                {
                    "parser": "text/apache_access",
                    "policy_request": (
                        "GET /search?id=configured_marker HTTP/1.1"
                    ),
                    "http_response_code": 500,
                },
                {
                    "parser": "text/apache_access",
                    "policy_request": "GET /search?id=ordinary HTTP/1.1",
                    "http_request": (
                        "GET /search?id=1%27%20UNION%20SELECT%20x HTTP/1.1"
                    ),
                    "http_response_code": 500,
                },
            ],
            index=pd.date_range("2024-06-16T17:00:00Z", periods=2, freq="s"),
        )
        out = engine.apply_atomic(
            frame,
            apply_profiling=False,
            enforce_required_fields=False,
            materialise_event_columns=True,
        )
        first_signals = out.iloc[0]["chronosift_signals"]
        second_signals = out.iloc[1]["chronosift_signals"]
        self.assertEqual(first_signals["web_sqli_attempt"], 2.0)
        self.assertNotIn("web_sqli_attempt", second_signals)
        self.assertEqual(
            out.iloc[0]["chronosift_policy_indicators"],
            "configured:configured_syntax",
        )
        self.assertEqual(
            out.iloc[0]["chronosift_web_attack_indicators"],
            "configured:configured_syntax",
        )
        explanation = next(
            item
            for item in out.iloc[0]["chronosift_explain"]
            if item["rule_id"] == "CONFIGURED_WEB_ATTEMPT"
        )
        self.assertEqual(explanation["description"], "Configured web syntax matched")
        self.assertEqual(explanation["confidence"], "low")
        self.assertNotIn("WEB_SQLI_ATTEMPT", engine.rule_emit_signals)

        disabled_rules = deepcopy(BASE_RULES)
        self._web_request_config(disabled_rules)["enabled"] = False
        self._correlation_config(disabled_rules)["enabled"] = False
        disabled_engine = self._engine(disabled_rules)
        disabled = disabled_engine.apply_atomic(
            pd.DataFrame(
                [{
                    "parser": "text/apache_access",
                    "http_request": (
                        "GET /search?id=1%27%20UNION%20SELECT%20x HTTP/1.1"
                    ),
                    "http_response_code": 500,
                }],
                index=pd.DatetimeIndex(
                    [pd.Timestamp("2024-06-16T17:05:00Z")]
                ),
            ),
            apply_profiling=False,
            enforce_required_fields=False,
            materialise_event_columns=True,
        )
        disabled_signals = (
            disabled.iloc[0]["chronosift_signals"]
            if "chronosift_signals" in disabled.columns
            else {}
        )
        self.assertNotIn("web_sqli_attempt", disabled_signals)
        self.assertNotIn("WEB_SQLI_ATTEMPT", disabled_engine.rule_emit_signals)

    def test_web_upload_mime_pairing_is_yaml_authoritative(self):
        def run(rules):
            return self._engine(rules).apply_atomic(
                pd.DataFrame(
                    [{
                        "parser": "text/apache_access",
                        "http_request": "POST /upload HTTP/1.1",
                        "http_upload_filename": ["photo.jpg", "shell.php"],
                        "http_upload_content_type": ["image/jpeg", "text/plain"],
                        "http_response_code": 200,
                    }],
                    index=pd.DatetimeIndex(
                        [pd.Timestamp("2024-06-16T17:06:00Z")]
                    ),
                ),
                apply_profiling=False,
                enforce_required_fields=False,
                materialise_event_columns=True,
            ).iloc[0]["chronosift_web_attack_indicators"].split("|")

        baseline = run(deepcopy(BASE_RULES))
        self.assertNotIn("upload_mime_extension_mismatch", baseline)

        configured_rules = deepcopy(BASE_RULES)
        self._web_request_config(configured_rules)["upload"][
            "mime_value_pairing"
        ] = "any_pair"
        configured = run(configured_rules)
        self.assertIn("upload_mime_extension_mismatch", configured)

    def test_web_upload_filename_extension_admission_is_yaml_authoritative(self):
        def run(rules):
            return self._engine(rules).apply_atomic(
                pd.DataFrame(
                    [{
                        "parser": "text/apache_access",
                        "http_request": "POST /upload HTTP/1.1",
                        "http_upload_filename": [
                            "extensionless", "trailing.", "shell.php",
                        ],
                        "http_response_code": 200,
                    }],
                    index=pd.DatetimeIndex(
                        [pd.Timestamp("2024-06-16T17:06:30Z")]
                    ),
                ),
                apply_profiling=False,
                enforce_required_fields=False,
                materialise_event_columns=True,
            ).iloc[0]["chronosift_web_upload_names"]

        self.assertEqual(run(deepcopy(BASE_RULES)), "shell.php")

        configured_rules = deepcopy(BASE_RULES)
        self._web_request_config(configured_rules)["upload"][
            "filename_extension_admission"
        ] = "any_nonempty_basename"
        self.assertEqual(
            run(configured_rules),
            "extensionless|trailing.|shell.php",
        )

    def test_web_upload_mime_mismatch_truth_table_is_yaml_authoritative(self):
        def run(rules):
            row = self._engine(rules).apply_atomic(
                pd.DataFrame(
                    [{
                        "parser": "text/apache_access",
                        "http_request": "POST /upload HTTP/1.1",
                        "http_upload_filename": "photo.jpg",
                        "http_upload_content_type": "text/plain",
                        "http_response_code": 200,
                    }],
                    index=pd.DatetimeIndex(
                        [pd.Timestamp("2024-06-16T17:06:45Z")]
                    ),
                ),
                apply_profiling=False,
                enforce_required_fields=False,
                materialise_event_columns=True,
            ).iloc[0]
            return row["chronosift_web_attack_indicators"].split("|")

        self.assertIn(
            "upload_mime_extension_mismatch",
            run(deepcopy(BASE_RULES)),
        )

        configured_rules = deepcopy(BASE_RULES)
        image_branch = self._web_request_config(configured_rules)["upload"][
            "mime_mismatch"
        ]["branches"][0]
        image_branch["all"] = ["image_extension", "image_content_type"]
        image_branch["none"] = []
        self.assertNotIn(
            "upload_mime_extension_mismatch",
            run(configured_rules),
        )

    def test_web_outcome_indicator_promotion_is_yaml_authoritative(self):
        def run(rules):
            return self._engine(rules).apply_atomic(
                pd.DataFrame(
                    [{
                        "parser": "text/apache_access",
                        "http_request": "GET /search?q=%3Bid HTTP/1.1",
                        "http_response_code": 500,
                    }],
                    index=pd.DatetimeIndex(
                        [pd.Timestamp("2024-06-16T17:07:00Z")]
                    ),
                ),
                apply_profiling=False,
                enforce_required_fields=False,
                materialise_event_columns=True,
            ).iloc[0]

        baseline = run(deepcopy(BASE_RULES))
        self.assertIn(
            "command_injection",
            baseline["chronosift_web_attack_indicators"].split("|"),
        )
        self.assertEqual(baseline["chronosift_web_outcome"], "attempt")

        configured_rules = deepcopy(BASE_RULES)
        attempt_when = self._web_request_config(configured_rules)["outcomes"][
            "web"
        ]["attempt_when"]
        attempt_when["indicators_any"] = ["file_upload"]
        attempt_when["indicator_prefixes_any"] = []
        configured = run(configured_rules)
        self.assertIn(
            "command_injection",
            configured["chronosift_web_attack_indicators"].split("|"),
        )
        self.assertEqual(configured["chronosift_web_outcome"], "observed")

    def test_web_outcome_selection_ranks_are_used_at_runtime(self):
        rows = [
            {
                "parser": "text/apache_access",
                "http_request": "GET /products?id=1 HTTP/1.1",
                "http_headers": "Host: shop.example",
                "http_response_code": 200,
                "http_response_bytes": 4700,
            },
            {
                "parser": "text/apache_access",
                "http_request": "GET /products?id=2 HTTP/1.1",
                "http_headers": "Host: shop.example",
                "http_response_code": 200,
                "http_response_bytes": 4750,
            },
            {
                "parser": "text/apache_access",
                "http_request": (
                    "GET /products?id=1%27%20UNION%20SELECT%20x-- HTTP/1.1"
                ),
                "http_headers": "Host: shop.example",
                "http_response_code": 200,
                "http_response_bytes": 27000,
            },
        ]

        def run(rules):
            return self._engine(rules).apply_atomic(
                pd.DataFrame(
                    rows,
                    index=pd.date_range(
                        "2024-06-16T17:08:00Z", periods=3, freq="min"
                    ),
                ),
                apply_profiling=False,
                enforce_required_fields=False,
                materialise_event_columns=True,
            ).iloc[2]["chronosift_web_outcome"]

        self.assertEqual(run(deepcopy(BASE_RULES)), "probable_success")

        configured_rules = deepcopy(BASE_RULES)
        ranks = self._web_request_config(configured_rules)["outcomes"]["web"][
            "selection"
        ]["ranks"]
        ranks["attempt"] = 2
        ranks["probable_success"] = 1
        self.assertEqual(run(configured_rules), "attempt")

    def test_referenced_web_outcome_rank_is_yaml_authoritative(self):
        rules = deepcopy(BASE_RULES)
        ranks = self._correlation_config(rules)["web_outcome_merge"]["ranks"]
        ranks["attempt"] = 3
        ranks["probable_success"] = 1
        ranks["confirmed_follow_on"] = 2
        merge = self._engine(
            rules
        ).detector_policy.referenced_file_correlation.web_outcome_merge
        self.assertEqual(merge.merge("probable_success", "attempt"), "attempt")
        self.assertEqual(
            merge.merge("attempt", "confirmed_follow_on"),
            "attempt",
        )

    def test_sqli_baseline_topology_and_decisions_are_yaml_authoritative(self):
        def request(host, target, status, response_bytes):
            return {
                "parser": "text/apache_access",
                "http_request": f"GET {target} HTTP/1.1",
                "http_headers": f"Host: {host}",
                "http_response_code": status,
                "http_response_bytes": response_bytes,
            }

        def run(rules, rows):
            return self._engine(rules).apply_atomic(
                pd.DataFrame(
                    rows,
                    index=pd.date_range(
                        "2024-06-16T17:10:00Z",
                        periods=len(rows),
                        freq="min",
                    ),
                ),
                apply_profiling=False,
                enforce_required_fields=False,
                materialise_event_columns=True,
            )

        cross_host_rows = [
            request("clean.example", "/products?id=1", 200, 4700),
            request("clean.example", "/products?id=2", 200, 4750),
            request(
                "attack.example",
                "/products?id=1%27%20UNION%20SELECT%20table_name%20FROM%20information_schema.tables--",
                200,
                27000,
            ),
        ]
        baseline = run(deepcopy(BASE_RULES), cross_host_rows)
        self.assertNotIn(
            "web_sqli_probable_success",
            baseline.iloc[2]["chronosift_signals"],
        )

        rules = deepcopy(BASE_RULES)
        rules_baseline = self._web_request_config(rules)["sqli"]["baseline"]
        rules_baseline["key_fields"] = ["method", "endpoint"]
        configured = run(rules, cross_host_rows)
        self.assertEqual(
            configured.iloc[2]["chronosift_signals"][
                "web_sqli_probable_success"
            ],
            1.0,
        )

        future_baseline_rows = [
            request(
                "shop.example",
                "/products?id=1%27%20UNION%20SELECT%20table_name%20FROM%20information_schema.tables--",
                200,
                27000,
            ),
            request("shop.example", "/products?id=1", 200, 4700),
            request("shop.example", "/products?id=2", 200, 4750),
        ]
        partition = run(deepcopy(BASE_RULES), future_baseline_rows)
        self.assertEqual(
            partition.iloc[0]["chronosift_signals"][
                "web_sqli_probable_success"
            ],
            1.0,
        )
        rules = deepcopy(BASE_RULES)
        self._web_request_config(rules)["sqli"]["baseline"]["scope"] = (
            "prior_rows"
        )
        prior_only = run(rules, future_baseline_rows)
        self.assertNotIn(
            "web_sqli_probable_success",
            prior_only.iloc[0]["chronosift_signals"],
        )

        statistic_rows = [
            request("stats.example", "/products?id=1", 200, 100),
            request("stats.example", "/products?id=2", 200, 100),
            request("stats.example", "/products?id=3", 200, 10000),
            request(
                "stats.example",
                "/products?id=1%27%20UNION%20SELECT%20x--",
                200,
                5000,
            ),
        ]
        rules = deepcopy(BASE_RULES)
        baseline_cfg = self._web_request_config(rules)["sqli"]["baseline"]
        baseline_cfg["minimum_samples"] = 3
        median = run(rules, statistic_rows)
        self.assertEqual(
            median.iloc[3]["chronosift_signals"][
                "web_sqli_probable_success"
            ],
            1.0,
        )
        baseline_cfg["statistic"] = "mean"
        mean = run(rules, statistic_rows)
        self.assertNotIn(
            "web_sqli_probable_success",
            mean.iloc[3]["chronosift_signals"],
        )

        rules = deepcopy(BASE_RULES)
        probable_decision = self._web_request_config(rules)["sqli"][
            "decisions"
        ]["probable_success"]
        probable_decision["all"].remove("successful_response")
        redirected_rows = [
            request("redirect.example", "/products?id=1", 200, 4700),
            request("redirect.example", "/products?id=2", 200, 4750),
            request(
                "redirect.example",
                "/products?id=1%27%20UNION%20SELECT%20x--",
                302,
                27000,
            ),
        ]
        configured = run(rules, redirected_rows)
        self.assertEqual(
            configured.iloc[2]["chronosift_signals"][
                "web_sqli_probable_success"
            ],
            1.0,
        )

    def test_additional_generic_detectors_need_no_engine_wiring(self):
        rules = deepcopy(BASE_RULES)
        weights = deepcopy(BASE_WEIGHTS)
        detectors = rules["detector_policy"]["detectors"]
        rules["temporal_rules"] = []
        rules["profile_multipliers"] = []
        rules["engine_config"]["trust_dampening"]["signals"] = [
            "impossible_travel"
        ]
        detectors["download_to_execution"]["enabled"] = False
        for detector_id in (
            "geographic_continuity",
            "impossible_travel",
            "ip_scope_continuity",
            "ransomware_impact",
            "automated_exfiltration",
            "credential_dump_collection",
            "password_store_exfil_chain",
            "canonical_transfer_post_temporal_projection",
        ):
            detectors[detector_id]["enabled"] = False

        gate = deepcopy(detectors["masquerading"])
        gate["inputs"]["signals"] = ["usb_device_connected"]
        gate["evidence"]["hostname"]["field"] = "policy_gate_host"
        gate["emissions"][0].update(
            {
                "name": "configured_extra_gate",
                "rule_id": "CONFIGURED_EXTRA_GATE",
                "description": "Extra configured gate",
            }
        )
        detectors["configured_extra_gate"] = gate
        weights["weights"]["configured_extra_gate"] = 2

        sequence = deepcopy(detectors["webshell_activity"])
        sequence["lookback"] = "45m"
        sequence["source"]["any_signals"] = ["usb_device_connected"]
        sequence["target"]["any_signals"] = ["service_stop"]
        sequence["evidence"]["hostname"]["field"] = "policy_sequence_host"
        sequence["emissions"][0].update(
            {
                "name": "configured_extra_sequence",
                "rule_id": "CONFIGURED_EXTRA_SEQUENCE",
                "description": "Extra configured sequence",
            }
        )
        detectors["configured_extra_sequence"] = sequence
        weights["weights"]["configured_extra_sequence"] = 3

        engine = self._engine(rules, weights)
        start = pd.Timestamp("2024-06-16T17:00:00Z")
        frame = pd.DataFrame(
            [
                {"policy_gate_host": "gate-host"},
                {"policy_sequence_host": "sequence-host"},
            ],
            index=pd.DatetimeIndex([start, start + pd.Timedelta("10m")]),
        )
        signal_map = {
            0: {"usb_device_connected": 1.0},
            1: {"service_stop": 1.0},
        }
        explain_map = {0: [], 1: []}
        engine._apply_policy_signal_gates_sparse(frame, signal_map, explain_map)
        engine._apply_deadbox_temporal_composites_sparse(frame, signal_map, explain_map)

        self.assertEqual(signal_map[0]["configured_extra_gate"], 1.0)
        self.assertEqual(signal_map[1]["configured_extra_sequence"], 1.0)
        self.assertEqual(
            engine.rule_emit_signals["CONFIGURED_EXTRA_GATE"],
            ["configured_extra_gate"],
        )
        self.assertEqual(
            engine.temporal_emit_signals["CONFIGURED_EXTRA_SEQUENCE"],
            ["configured_extra_sequence"],
        )
        self.assertTrue(
            {"policy_gate_host", "policy_sequence_host"}.issubset(
                engine.required_fields
            )
        )
        self.assertEqual(engine._temporal_candidate_window("5m"), timedelta(minutes=45))

    def test_generic_temporal_emission_values_are_not_code_capped(self):
        rules = deepcopy(BASE_RULES)
        rules["rule_signal_merge"]["temporal_rules"] = "sum"
        rules["temporal_rules"][0]["emit"]["signals"][0]["value"] = 2
        engine = self._engine(rules)
        temporal_rule = next(
            rule
            for rule in engine.temporal_rules
            if rule.rule_id == "FAIL_THEN_SUCCESS_USER"
        )
        signal_map = {}
        explain_map = {}

        engine._temporal_emit_sparse(
            temporal_rule,
            signal_map,
            explain_map,
            0,
            ("alice",),
        )
        self.assertEqual(signal_map[0]["fail_then_success_user"], 2.0)

        engine._temporal_emit_sparse(
            temporal_rule,
            signal_map,
            explain_map,
            0,
            ("alice",),
        )
        self.assertEqual(signal_map[0]["fail_then_success_user"], 4.0)

    def test_file_lifecycle_and_timestomping_schemas_are_strict(self):
        lifecycle_cases = (
            (
                "unknown policy key",
                lambda config: config.update({"unexpected": True}),
                r"file_lifecycle: unknown key\(s\): unexpected",
            ),
            (
                "bad path resolver",
                lambda config: config["inputs"]["path"].update(
                    {"resolver": "first_nonempty"}
                ),
                r"file_lifecycle\.inputs\.path\.resolver: expected one of best_effort_file_path",
            ),
            (
                "empty path fields",
                lambda config: config["inputs"]["path"].update({"fields": []}),
                r"file_lifecycle\.inputs\.path\.fields: expected a non-empty list",
            ),
            (
                "incomplete timestamp priority",
                lambda config: config["classification"]["timestamp_kinds"].update(
                    {"priority": ["create", "delete", "modify"]}
                ),
                r"file_lifecycle\.classification\.timestamp_kinds\.priority: expected each of create, delete, modify, access exactly once",
            ),
            (
                "empty timestamp vocabulary",
                lambda config: config["classification"]["timestamp_kinds"][
                    "contains"
                ].update({"create": []}),
                r"file_lifecycle\.classification\.timestamp_kinds\.contains\.create: expected a non-empty list",
            ),
            (
                "missing path class",
                lambda config: config["classification"]["path_contains"].pop(
                    "sensitive"
                ),
                r"file_lifecycle\.classification\.path_contains: missing required key\(s\): sensitive",
            ),
            (
                "extension without dot",
                lambda config: config["classification"]["extensions"].update(
                    {"archive": ["zip"]}
                ),
                r"file_lifecycle\.classification\.extensions\.archive: extension\(s\) must start with '\.'",
            ),
            (
                "invalid row decision match",
                lambda config: config["conditions"]["row_emissions"][
                    "deleted"
                ].update(
                    {"match": "some"}
                ),
                r"file_lifecycle\.conditions\.row_emissions\.deleted\.match: expected one of all, any",
            ),
            (
                "unknown row predicate",
                lambda config: config["conditions"]["row_emissions"][
                    "created"
                ].update(
                    {"derived_predicates": ["unknown"]}
                ),
                r"file_lifecycle\.conditions\.row_emissions\.created\.derived_predicates: unknown predicate",
            ),
            (
                "unknown weight-aware semantic",
                lambda config: config["conditions"].update(
                    {"weight_aware_semantics": ["unknown"]}
                ),
                r"file_lifecycle\.conditions\.weight_aware_semantics: unknown semantic\(s\): unknown",
            ),
            (
                "zero lookback",
                lambda config: config["conditions"]["windows"][
                    "short_lived_file"
                ].update({"lookback": "0s"}),
                r"file_lifecycle\.conditions\.windows\.short_lived_file\.lookback: expected a duration greater than zero",
            ),
            (
                "zero threshold",
                lambda config: config["conditions"]["windows"][
                    "mass_file_modification"
                ].update({"threshold": 0}),
                r"file_lifecycle\.conditions\.windows\.mass_file_modification\.threshold: expected a positive integer",
            ),
            (
                "unknown window timestamp kind",
                lambda config: config["conditions"]["windows"][
                    "mass_file_modification"
                ].update({"eligible_timestamp_kinds": ["rename"]}),
                r"file_lifecycle\.conditions\.windows\.mass_file_modification\.eligible_timestamp_kinds: unknown timestamp kind",
            ),
            (
                "unknown window condition fact",
                lambda config: config["conditions"]["windows"][
                    "ransomware_extension_burst"
                ]["conditions"]["any"][0].update({"all": ["unknown"]}),
                r"ransomware_extension_burst\.conditions\.any\[0\]\.all: unknown fact",
            ),
            (
                "missing semantic emission",
                lambda config: config["emissions"].pop("created"),
                r"file_lifecycle\.emissions: missing required key\(s\): created",
            ),
            (
                "missing semantic evidence",
                lambda config: config["evidence"].pop("created"),
                r"file_lifecycle\.evidence: missing required key\(s\): created",
            ),
            (
                "unsupported evidence",
                lambda config: config["evidence"].update(
                    {"created": ["unknown"]}
                ),
                r"file_lifecycle\.evidence\.created: unsupported value\(s\): unknown",
            ),
        )
        for label, mutate, error_path in lifecycle_cases:
            with self.subTest(policy="file_lifecycle", label=label):
                rules = deepcopy(BASE_RULES)
                mutate(self._detector_config(rules, "file_lifecycle"))
                with self.assertRaisesRegex(ValueError, error_path):
                    self._engine(rules)

        timestomp_cases = (
            (
                "unknown policy key",
                lambda config: config.update({"unexpected": True}),
                r"mft_timestomping: unknown key\(s\): unexpected",
            ),
            (
                "bad path resolver",
                lambda config: config["inputs"]["path"].update(
                    {"resolver": "first_nonempty"}
                ),
                r"mft_timestomping\.inputs\.path\.resolver: expected one of best_effort_file_path",
            ),
            (
                "empty parser tokens",
                lambda config: config["conditions"].update(
                    {"parser_contains": []}
                ),
                r"mft_timestomping\.conditions\.parser_contains: expected a non-empty list",
            ),
            (
                "empty attribute tokens",
                lambda config: config["conditions"]["attributes"].update(
                    {"file_name_contains": []}
                ),
                r"mft_timestomping\.conditions\.attributes\.file_name_contains: expected a non-empty list",
            ),
            (
                "zero minimum delta",
                lambda config: config["conditions"].update({"minimum_delta": "0s"}),
                r"mft_timestomping\.conditions\.minimum_delta: expected a duration greater than zero",
            ),
            (
                "empty exclusions",
                lambda config: config["conditions"].update(
                    {"excluded_path_contains": []}
                ),
                r"mft_timestomping\.conditions\.excluded_path_contains: expected a non-empty list",
            ),
            (
                "unsupported grouping",
                lambda config: config["conditions"]["bulk_extraction"].update(
                    {"group_by": "hostname"}
                ),
                r"mft_timestomping\.conditions\.bulk_extraction\.group_by: expected one of parent_directory",
            ),
            (
                "zero bulk threshold",
                lambda config: config["conditions"]["bulk_extraction"].update(
                    {"threshold": 0}
                ),
                r"mft_timestomping\.conditions\.bulk_extraction\.threshold: expected a positive integer",
            ),
            (
                "missing branch",
                lambda config: config["branches"].pop("targeted"),
                r"mft_timestomping\.branches: missing required key\(s\): targeted",
            ),
            (
                "unsupported branch evidence",
                lambda config: config["branches"]["targeted"].update(
                    {"evidence": ["hostname"]}
                ),
                r"mft_timestomping\.branches\.targeted\.evidence: unsupported value\(s\): hostname",
            ),
            (
                "multiple emissions",
                lambda config: config["emissions"].append(
                    deepcopy(config["emissions"][0])
                ),
                r"mft_timestomping\.emissions: expected a list containing exactly one emission",
            ),
        )
        for label, mutate, error_path in timestomp_cases:
            with self.subTest(policy="mft_timestomping", label=label):
                rules = deepcopy(BASE_RULES)
                mutate(self._detector_config(rules, "mft_timestomping"))
                with self.assertRaisesRegex(ValueError, error_path):
                    self._engine(rules)

    def test_positive_signal_minimum_schema_is_strict_at_each_typed_site(self):
        paths = (
            ("canonical_authentication", "inputs", "source_signals"),
            (
                "web_request_classification", "exploit", "branches",
                "configured_hint", "conditions",
            ),
            (
                "referenced_file_correlation", "mappings", "branches",
                "confirmed_webshell", "conditions",
            ),
            ("ransomware_impact", "source"),
            ("ransomware_impact", "branches", "prior_support"),
            ("credential_dump_collection", "source"),
            ("credential_dump_collection", "copy_stage"),
            ("credential_dump_collection", "follow_on"),
            ("download_to_execution", "source"),
            ("download_to_execution", "target"),
            ("webshell_activity", "source"),
            ("webshell_activity", "target"),
        )
        for path in paths:
            with self.subTest(path=".".join(path)):
                rules = deepcopy(BASE_RULES)
                node = rules["detector_policy"]["detectors"]
                for part in path:
                    node = node[part]
                del node["minimum_signal_value_exclusive"]
                with self.assertRaisesRegex(
                    ValueError, r"minimum_signal_value_exclusive"
                ):
                    self._engine(rules)

        rules = deepcopy(BASE_RULES)
        self._detector_config(rules, "canonical_authentication")["inputs"][
            "source_signals"
        ]["minimum_signal_value_exclusive"] = -0.1
        with self.assertRaisesRegex(ValueError, r"expected a non-negative"):
            self._engine(rules)

        rules = deepcopy(BASE_RULES)
        self._web_request_config(rules)["exploit"]["branches"][
            "executable_upload"
        ]["conditions"]["minimum_signal_value_exclusive"] = 0
        with self.assertRaisesRegex(ValueError, r"not allowed.*signals_any"):
            self._engine(rules)

    def test_authentication_and_execution_context_schemas_are_strict(self):
        auth_cases = (
            (
                "unknown policy key",
                lambda config: config.update({"unexpected": True}),
                r"canonical_authentication: unknown key\(s\): unexpected",
            ),
            (
                "missing field role",
                lambda config: config["inputs"]["fields"].pop("outcome"),
                r"canonical_authentication\.inputs\.fields: missing required key\(s\): outcome",
            ),
            (
                "empty source group",
                lambda config: config["inputs"]["source_signals"].update(
                    {"success": []}
                ),
                r"canonical_authentication\.inputs\.source_signals\.success: expected a non-empty list",
            ),
            (
                "identical outcomes",
                lambda config: config["outcomes"].update({"failure": "success"}),
                r"canonical_authentication\.outcomes: success and failure must differ",
            ),
            (
                "missing eligibility",
                lambda config: config.pop("eligibility"),
                r"canonical_authentication: missing required key\(s\): eligibility",
            ),
            (
                "unknown eligibility fact",
                lambda config: config["eligibility"].update(
                    {"all": ["opaque_fact"], "any": []}
                ),
                r"canonical_authentication\.eligibility\.all\[0\]: unknown fact",
            ),
            (
                "unknown decision fact",
                lambda config: config["decisions"]["success"].update(
                    {"all": ["opaque_fact"]}
                ),
                r"canonical_authentication\.decisions\.success\.all\[0\]: unknown fact",
            ),
            (
                "unknown semantic key",
                lambda config: config["semantics"].update({"unexpected": {}}),
                r"canonical_authentication\.semantics: unknown key\(s\): unexpected",
            ),
            (
                "impossible lateral threshold without remote factor",
                lambda config: config["semantics"]["lateral_movement"].update(
                    {"include_remote": False, "minimum_matches": 3}
                ),
                r"canonical_authentication\.semantics\.lateral_movement\.minimum_matches: maximum is 2",
            ),
            (
                "impossible lateral threshold",
                lambda config: config["semantics"]["lateral_movement"].update(
                    {"minimum_matches": 4}
                ),
                r"canonical_authentication\.semantics\.lateral_movement\.minimum_matches: maximum is 3",
            ),
            (
                "missing semantic emission",
                lambda config: config["emissions"].pop("success"),
                r"canonical_authentication\.emissions: missing required key\(s\): success",
            ),
            (
                "unsupported evidence",
                lambda config: config.update({"evidence": ["path"]}),
                r"canonical_authentication\.evidence: unsupported value\(s\): path",
            ),
        )
        for label, mutate, error_path in auth_cases:
            with self.subTest(policy="authentication", label=label):
                rules = deepcopy(BASE_RULES)
                mutate(self._detector_config(rules, "canonical_authentication"))
                with self.assertRaisesRegex(ValueError, error_path):
                    self._engine(rules)

        context_cases = (
            (
                "unknown policy key",
                lambda config: config.update({"unexpected": True}),
                r"execution_context_classifier: unknown key\(s\): unexpected",
            ),
            (
                "unsupported resolver",
                lambda config: config["inputs"]["path"].update(
                    {"resolver": "concat_lower"}
                ),
                r"execution_context_classifier\.inputs\.path\.resolver: expected one of first_nonempty",
            ),
            (
                "empty field list",
                lambda config: config["inputs"]["command"].update({"fields": []}),
                r"execution_context_classifier\.inputs\.command\.fields: expected a non-empty list",
            ),
            (
                "unknown classification key",
                lambda config: config["classification"].update({"unexpected": []}),
                r"execution_context_classifier\.classification: unknown key\(s\): unexpected",
            ),
            (
                "empty path tokens",
                lambda config: config["classification"].update(
                    {"temporary_path_contains": []}
                ),
                r"execution_context_classifier\.classification\.temporary_path_contains: expected a non-empty list",
            ),
            (
                "empty command names",
                lambda config: config["classification"]["command_names"].update(
                    {"compiler": []}
                ),
                r"execution_context_classifier\.classification\.command_names\.compiler: expected a non-empty list",
            ),
            (
                "invalid regex",
                lambda config: config["classification"].update(
                    {"suid_regex": "["}
                ),
                r"execution_context_classifier\.classification\.suid_regex: invalid regular expression",
            ),
            (
                "contradictory decision fact",
                lambda config: config["decisions"]["from_tmp"].update(
                    {"none": ["temporary_path"]}
                ),
                r"execution_context_classifier\.decisions\.from_tmp: fact\(s\) cannot be both required and excluded",
            ),
            (
                "missing semantic emission",
                lambda config: config["emissions"].pop("compiler_activity"),
                r"execution_context_classifier\.emissions: missing required key\(s\): compiler_activity",
            ),
            (
                "unsupported evidence",
                lambda config: config.update({"evidence": ["hostname"]}),
                r"execution_context_classifier\.evidence: unsupported value\(s\): hostname",
            ),
        )
        for label, mutate, error_path in context_cases:
            with self.subTest(policy="execution_context", label=label):
                rules = deepcopy(BASE_RULES)
                mutate(
                    self._detector_config(rules, "execution_context_classifier")
                )
                with self.assertRaisesRegex(ValueError, error_path):
                    self._engine(rules)

    def test_signal_projection_schema_is_strict_and_typed(self):
        def projection(config):
            return config["projections"][0]

        cases = (
            (
                "unknown policy key",
                lambda config: config.update({"unexpected": True}),
                r"canonical_persistence_projection: unknown key\(s\): unexpected",
            ),
            (
                "empty projections",
                lambda config: config.update({"projections": []}),
                r"canonical_persistence_projection\.projections: expected a non-empty list",
            ),
            (
                "unknown projection key",
                lambda config: projection(config).update({"unexpected": True}),
                r"canonical_persistence_projection\.projections\[0\]: unknown key\(s\): unexpected",
            ),
            (
                "empty inputs",
                lambda config: projection(config)["inputs"].update({"signals": []}),
                r"canonical_persistence_projection\.projections\[0\]\.inputs\.signals: expected a non-empty list",
            ),
            (
                "duplicate inputs",
                lambda config: projection(config)["inputs"].update(
                    {"signals": ["persistence_service", "persistence_service"]}
                ),
                r"canonical_persistence_projection\.projections\[0\]\.inputs\.signals\[1\]: duplicate value",
            ),
            (
                "unsupported match",
                lambda config: projection(config)["conditions"].update(
                    {"match": "xor"}
                ),
                r"canonical_persistence_projection\.projections\[0\]\.conditions\.match: expected one of all, any",
            ),
            (
                "negative threshold",
                lambda config: projection(config)["conditions"].update(
                    {"minimum_value_exclusive": -0.1}
                ),
                r"canonical_persistence_projection\.projections\[0\]\.conditions\.minimum_value_exclusive: expected a non-negative finite number",
            ),
            (
                "unsupported strength",
                lambda config: projection(config).update({"strength": "sum"}),
                r"canonical_persistence_projection\.projections\[0\]\.strength: expected one of maximum_matched_times_emission_value",
            ),
            (
                "multiple emissions",
                lambda config: projection(config)["emissions"].append(
                    deepcopy(projection(config)["emissions"][0])
                ),
                r"canonical_persistence_projection\.projections\[0\]\.emissions: expected a list containing exactly one emission",
            ),
            (
                "empty evidence",
                lambda config: config.update({"evidence": {}}),
                r"canonical_persistence_projection\.evidence: expected a non-empty mapping",
            ),
            (
                "unsupported evidence resolver",
                lambda config: config.update(
                    {"evidence": {"source": {"resolver": "row_field"}}}
                ),
                r"canonical_persistence_projection\.evidence\.source\.resolver: expected one of matched_signals",
            ),
        )
        for label, mutate, error_path in cases:
            with self.subTest(label=label):
                rules = deepcopy(BASE_RULES)
                config = self._detector_config(
                    rules, "canonical_persistence_projection"
                )
                mutate(config)
                with self.assertRaisesRegex(ValueError, error_path):
                    self._engine(rules)

    def test_signal_projection_stage_and_dependency_phase_are_authoritative(self):
        for detector_id, invalid_stage, required_stage in (
            ("canonical_persistence_projection", "temporal", "contextual"),
            ("canonical_transfer_projection", "temporal", "contextual"),
            (
                "canonical_transfer_post_temporal_projection",
                "contextual",
                "temporal",
            ),
        ):
            with self.subTest(detector_id=detector_id):
                rules = deepcopy(BASE_RULES)
                self._detector_config(rules, detector_id)["stage"] = invalid_stage
                with self.assertRaisesRegex(
                    ValueError,
                    rf"detector_policy\.detectors\.{detector_id}\.stage: required canonical projection must use '{required_stage}'",
                ):
                    self._engine(rules)

        contextual_rules = deepcopy(BASE_RULES)
        self._detector_config(
            contextual_rules, "canonical_persistence_projection"
        )["projections"][0]["inputs"]["signals"] = ["staging_then_transfer"]
        with self.assertRaisesRegex(
            ValueError,
            r"canonical_persistence_projection: input signal\(s\) are emitted after the signal_projection executor runs: staging_then_transfer",
        ):
            self._engine(contextual_rules)

        temporal_rules = deepcopy(BASE_RULES)
        temporal = self._detector_config(
            temporal_rules, "canonical_transfer_post_temporal_projection"
        )
        temporal["projections"][0]["inputs"]["signals"] = ["staging_archive"]
        engine = self._engine(temporal_rules)
        signal_map = {0: {"staging_archive": 0.65}}
        explain_map = {0: []}
        engine._apply_policy_signal_projections_sparse(
            signal_map,
            explain_map,
            stage="temporal",
        )
        self.assertEqual(signal_map[0]["transfer_exfiltration_pattern"], 0.65)

    def test_malformed_or_incomplete_policy_fails_with_a_precise_config_path(self):
        cases = []

        rules = deepcopy(BASE_RULES)
        del rules["detector_policy"]
        cases.append(("missing section", rules, deepcopy(BASE_WEIGHTS), r"detector_policy"))

        rules = deepcopy(BASE_RULES)
        rules["detector_policy"]["version"] = 2
        cases.append(("version", rules, deepcopy(BASE_WEIGHTS), r"detector_policy\.version"))

        rules = deepcopy(BASE_RULES)
        self._systemd_config(rules)["unexpected"] = True
        cases.append(
            (
                "unknown key",
                rules,
                deepcopy(BASE_WEIGHTS),
                r"detector_policy\.detectors\.systemd_service_persistence.*unknown key",
            )
        )

        rules = deepcopy(BASE_RULES)
        self._systemd_config(rules)["branch_order"] = [
            "artifact_change", "artifact_change"
        ]
        cases.append(
            (
                "invalid systemd branch order",
                rules,
                deepcopy(BASE_WEIGHTS),
                r"systemd_service_persistence\.branch_order\[1\]: duplicate",
            )
        )

        rules = deepcopy(BASE_RULES)
        self._systemd_config(rules)["branches"]["artifact_change"][
            "conditions"
        ]["any"][0]["all"] = ["opaque_fact"]
        cases.append(
            (
                "unknown systemd condition fact",
                rules,
                deepcopy(BASE_WEIGHTS),
                r"artifact_change\.conditions\.any\[0\]\.all: unknown fact",
            )
        )

        rules = deepcopy(BASE_RULES)
        del rules["detector_policy"]["detectors"]["download_to_execution"]
        cases.append(
            (
                "missing detector",
                rules,
                deepcopy(BASE_WEIGHTS),
                r"detector_policy\.detectors.*download_to_execution",
            )
        )

        for detector_id in (
            "masquerading",
            "webshell_artifact",
            "webshell_activity",
            "web_request_classification",
            "web_upload_execution_chain",
            "canonical_authentication",
            "execution_context_classifier",
            "file_lifecycle",
            "mft_timestomping",
            "automated_collection",
            "canonical_persistence_projection",
            "canonical_transfer_projection",
            "canonical_transfer_post_temporal_projection",
            "ransomware_impact",
            "automated_exfiltration",
            "credential_dump_collection",
            "password_store_exfil_chain",
            "execution_lolbin",
            "suspicious_execution",
        ):
            rules = deepcopy(BASE_RULES)
            del rules["detector_policy"]["detectors"][detector_id]
            cases.append(
                (
                    f"missing {detector_id}",
                    rules,
                    deepcopy(BASE_WEIGHTS),
                    rf"detector_policy\.detectors.*{detector_id}",
                )
            )

        rules = deepcopy(BASE_RULES)
        self._download_config(rules)["lookback"] = "not-a-duration"
        cases.append(
            (
                "bad duration",
                rules,
                deepcopy(BASE_WEIGHTS),
                r"detector_policy\.detectors\.download_to_execution\.lookback",
            )
        )

        weights = deepcopy(BASE_WEIGHTS)
        del weights["weights"]["user_execution_after_download"]
        cases.append(
            (
                "missing weight",
                deepcopy(BASE_RULES),
                weights,
                r"detector_policy\.detectors.*user_execution_after_download",
            )
        )

        rules = deepcopy(BASE_RULES)
        self._download_config(rules)["source"]["any_signals"] = ["no_known_producer"]
        cases.append(
            (
                "unknown input signal",
                rules,
                deepcopy(BASE_WEIGHTS),
                r"detector_policy\.detectors\.download_to_execution.*no_known_producer",
            )
        )

        rules = deepcopy(BASE_RULES)
        self._webshell_config(rules)["key"]["field"] = "hostname"
        cases.append(
            (
                "global sequence field",
                rules,
                deepcopy(BASE_WEIGHTS),
                r"detector_policy\.detectors\.webshell_activity\.key\.field.*not allowed",
            )
        )

        rules = deepcopy(BASE_RULES)
        self._webshell_config(rules)["key"] = {"scope": "field"}
        cases.append(
            (
                "field sequence without field",
                rules,
                deepcopy(BASE_WEIGHTS),
                r"detector_policy\.detectors\.webshell_activity\.key\.field.*required",
            )
        )

        rules = deepcopy(BASE_RULES)
        self._masquerading_config(rules)["inputs"]["signals"] = [
            "impossible_travel"
        ]
        cases.append(
            (
                "gate input emitted after gate phase",
                rules,
                deepcopy(BASE_WEIGHTS),
                r"detector_policy\.detectors\.masquerading.*not available before.*signal_gate",
            )
        )

        rules = deepcopy(BASE_RULES)
        self._webshell_artifact_config(rules)["conditions"]["support"][
            "signals_any"
        ] = ["service_stop"]
        cases.append(
            (
                "webshell support emitted after classifier phase",
                rules,
                deepcopy(BASE_WEIGHTS),
                r"detector_policy\.detectors\.webshell_artifact.*not available before.*webshell_artifact",
            )
        )

        rules = deepcopy(BASE_RULES)
        self._correlation_config(rules)["enabled"] = False
        self._webshell_artifact_config(rules)["conditions"]["support"][
            "match"
        ] = "all"
        cases.append(
            (
                "required webshell signal group has no enabled producer",
                rules,
                deepcopy(BASE_WEIGHTS),
                r"detector_policy\.detectors\.webshell_artifact.*no enabled policy producer path",
            )
        )

        rules = deepcopy(BASE_RULES)
        self._webshell_artifact_config(rules)["conditions"][
            "extension_in"
        ] = ["."]
        cases.append(
            (
                "webshell invalid extension",
                rules,
                deepcopy(BASE_WEIGHTS),
                r"detector_policy\.detectors\.webshell_artifact\.conditions\.extension_in.*unsupported extension",
            )
        )

        for obsolete_key in ("webshell_name_tokens", "web_upload_tokens"):
            rules = deepcopy(BASE_RULES)
            rules["engine_config"]["detection_vocabulary"] = {
                obsolete_key: ["obsolete"]
            }
            cases.append(
                (
                    f"obsolete {obsolete_key}",
                    rules,
                    deepcopy(BASE_WEIGHTS),
                    r"engine_config: obsolete shared rule-logic section.*detection_vocabulary",
                )
            )

        rules = deepcopy(BASE_RULES)
        self._webshell_config(rules)["target"]["any_signals"] = ["ransomware_impact"]
        cases.append(
            (
                "sequence input emitted after sequence phase",
                rules,
                deepcopy(BASE_WEIGHTS),
                r"detector_policy\.detectors\.webshell_activity.*not available before.*signal_sequence",
            )
        )

        rules = deepcopy(BASE_RULES)
        self._masquerading_config(rules)["inputs"]["signals"] = ["webshell_activity"]
        cases.append(
            (
                "policy-to-policy input",
                rules,
                deepcopy(BASE_WEIGHTS),
                r"detector_policy\.detectors\.masquerading.*policy-to-policy.*webshell_activity",
            )
        )

        rules = deepcopy(BASE_RULES)
        self._detector_config(rules, "execution_interpreter")["inputs"][
            "signals"
        ] = ["execution_lolbin"]
        cases.append(
            (
                "same-phase policy dependency",
                rules,
                deepcopy(BASE_WEIGHTS),
                r"detector_policy\.detectors\.execution_interpreter.*policy-to-policy.*execution_lolbin",
            )
        )

        rules = deepcopy(BASE_RULES)
        self._detector_config(rules, "execution_interpreter")["inputs"][
            "signals"
        ] = ["service_stop"]
        cases.append(
            (
                "atomic gate input emitted after atomic phase",
                rules,
                deepcopy(BASE_WEIGHTS),
                r"detector_policy\.detectors\.execution_interpreter.*not available before.*signal_gate",
            )
        )

        rules = deepcopy(BASE_RULES)
        rules["rules"][0]["emit"]["signals"][0]["name"] = "Mixed_Case_Signal"
        cases.append(
            (
                "mixed-case producer",
                rules,
                deepcopy(BASE_WEIGHTS),
                r"rules\[0\]\.emit\.signals\[0\]\.name.*lowercase snake_case",
            )
        )

        rules = deepcopy(BASE_RULES)
        self._systemd_config(rules)["emissions"][0].update(
            {"name": "authorized_keys_persistence", "rule_id": "POLICY_COLLISION"}
        )
        cases.append(
            (
                "output ownership collision",
                rules,
                deepcopy(BASE_WEIGHTS),
                r"detector_policy\.detectors.*authorized_keys_persistence",
            )
        )

        for label, rules_doc, weights_doc, error_path in cases:
            with self.subTest(label=label):
                with self.assertRaisesRegex(ValueError, error_path):
                    ChronoSiftEngine(
                        rules_doc,
                        weights_doc,
                        yara_metadata_path=BASE_YARA_PATH,
                    )

    def test_collectors_derive_policy_outputs_signal_inputs_and_required_fields(self):
        rules = deepcopy(BASE_RULES)
        systemd = self._systemd_config(rules)
        download = self._download_config(rules)
        systemd["emissions"][0].update(
            {"name": "policy_systemd_output", "rule_id": "POLICY_SYSTEMD_OUTPUT"}
        )
        download["emissions"][0].update(
            {"name": "policy_download_output", "rule_id": "POLICY_DOWNLOAD_OUTPUT"}
        )
        download["emissions"][1].update(
            {"name": "policy_ingress_output", "rule_id": "POLICY_INGRESS_OUTPUT"}
        )
        download["source"]["any_signals"] = ["policy_source_signal"]
        download["target"]["any_signals"] = ["policy_target_signal"]
        execution = self._detector_config(rules, "execution_interpreter")
        execution["emissions"][0].update(
            {
                "name": "policy_execution_output",
                "rule_id": "POLICY_EXECUTION_OUTPUT",
            }
        )

        emitted = MODULE._collect_emitted_signals_from_rules(rules)
        self.assertTrue(
            {
                "policy_systemd_output",
                "policy_download_output",
                "policy_ingress_output",
                "policy_execution_output",
            }.issubset(emitted)
        )
        self.assertTrue(
            {
                "systemd_service_persistence",
                "user_execution_after_download",
                "ingress_tool_transfer",
                "execution_interpreter",
            }.isdisjoint(emitted)
        )

        temporal_inputs = MODULE._collect_temporal_input_signals(rules)
        self.assertIn("policy_source_signal", temporal_inputs)
        self.assertIn("policy_target_signal", temporal_inputs)
        self.assertNotIn("browser_download", temporal_inputs)
        self.assertIn("suspicious_execution", temporal_inputs)

        required_rules = deepcopy(BASE_RULES)
        required_systemd = self._systemd_config(required_rules)["inputs"]
        required_systemd["path"]["fields"] = ["policy_path"]
        required_systemd["timestamp_kind"]["field"] = "policy_timestamp"
        required_systemd["combined_text"]["fields"] = ["policy_text"]
        required_systemd["combined_text"]["first_existing"] = ["policy_url"]
        self._download_config(required_rules)["key"]["artifact"]["fields"] = [
            "policy_artifact"
        ]
        required_webshell = self._webshell_artifact_config(required_rules)
        required_webshell["inputs"]["path"]["fields"] = [
            "policy_webshell_path"
        ]
        required_webshell["inputs"]["combined_text"]["fields"] = [
            "policy_webshell_text"
        ]
        required_webshell["inputs"]["combined_text"]["first_existing"] = [
            "policy_webshell_url"
        ]
        required_webshell["evidence"] = {
            "policy_webshell_evidence": {
                "resolver": "row_field",
                "field": "policy_webshell_evidence",
            }
        }
        required = self._engine(required_rules).required_fields
        self.assertTrue(
            {
                "policy_path",
                "policy_timestamp",
                "policy_text",
                "policy_url",
                "policy_artifact",
                "policy_webshell_path",
                "policy_webshell_text",
                "policy_webshell_url",
                "policy_webshell_evidence",
            }.issubset(required)
        )

    def test_contextual_gate_can_consume_an_earlier_atomic_policy_output(self):
        rules = deepcopy(BASE_RULES)
        weights = deepcopy(BASE_WEIGHTS)
        detector = deepcopy(self._masquerading_config(rules))
        detector["inputs"]["signals"] = ["execution_lolbin"]
        detector["evidence"] = {
            "derived_from": {"resolver": "matched_signals"}
        }
        detector["emissions"][0].update(
            {
                "name": "configured_later_phase_gate",
                "rule_id": "CONFIGURED_LATER_PHASE_GATE",
                "description": "Earlier atomic policy output reached a contextual gate",
            }
        )
        rules["detector_policy"]["detectors"]["configured_later_phase_gate"] = detector
        weights["weights"]["configured_later_phase_gate"] = 0
        engine = self._engine(rules, weights)
        frame = pd.DataFrame(
            index=pd.DatetimeIndex([pd.Timestamp("2024-06-16T18:30:00Z")])
        )
        signal_map = {0: {"lolbin_windows": 1.0}}
        explain_map = {0: []}

        engine._apply_policy_signal_gates_sparse(
            frame, signal_map, explain_map, stage="atomic"
        )
        engine._apply_policy_signal_gates_sparse(frame, signal_map, explain_map)

        self.assertEqual(signal_map[0]["execution_lolbin"], 1.0)
        self.assertEqual(signal_map[0]["configured_later_phase_gate"], 1.0)
        later = next(
            item for item in explain_map[0]
            if item["rule_id"] == "CONFIGURED_LATER_PHASE_GATE"
        )
        self.assertEqual(later["evidence"], {"derived_from": "execution_lolbin"})

    def test_candidate_mask_and_window_follow_only_enabled_configured_temporal_inputs(self):
        rules = deepcopy(BASE_RULES)
        rules["temporal_rules"] = []
        rules["profile_multipliers"] = []
        rules["engine_config"]["trust_dampening"]["signals"] = [
            "impossible_travel"
        ]
        for detector_id in (
            "geographic_continuity",
            "impossible_travel",
            "ip_scope_continuity",
        ):
            self._detector_config(rules, detector_id)["enabled"] = False
        for detector_id in (
            "ransomware_impact",
            "automated_exfiltration",
            "credential_dump_collection",
            "password_store_exfil_chain",
            "canonical_transfer_post_temporal_projection",
        ):
            self._detector_config(rules, detector_id)["enabled"] = False
        download = self._download_config(rules)
        download["lookback"] = "37m"
        download["source"]["any_signals"] = ["usb_device_connected"]
        download["target"]["any_signals"] = ["service_stop"]
        engine = self._engine(rules)

        index = pd.date_range("2024-06-16T13:00:00Z", periods=3, freq="min")
        frame = pd.DataFrame(index=index)
        signal_map = {
            0: {"usb_device_connected": 1.0},
            1: {"service_stop": 1.0},
            2: {"unrelated_signal": 1.0},
        }
        self.assertEqual(
            engine._temporal_candidate_base_mask(frame, signal_map).tolist(),
            [True, True, False],
        )
        self.assertEqual(engine._temporal_candidate_window("5m"), timedelta(minutes=37))

        disabled_rules = deepcopy(rules)
        self._download_config(disabled_rules)["enabled"] = False
        self._webshell_config(disabled_rules)["enabled"] = False
        self._web_upload_chain_config(disabled_rules)["enabled"] = False
        disabled_engine = self._engine(disabled_rules)
        self.assertEqual(
            disabled_engine._temporal_candidate_base_mask(frame, signal_map).tolist(),
            [False, False, False],
        )
        self.assertEqual(disabled_engine._temporal_candidate_window("5m"), timedelta(minutes=5))

    def test_signal_gate_can_consume_canonical_persistence_created_in_the_same_stage(self):
        rules = deepcopy(BASE_RULES)
        weights = deepcopy(BASE_WEIGHTS)
        detector = deepcopy(self._masquerading_config(rules))
        detector["inputs"]["signals"] = ["persistence_mechanism"]
        detector["emissions"][0].update(
            {
                "name": "configured_persistence_gate",
                "rule_id": "CONFIGURED_PERSISTENCE_GATE",
                "description": "Canonical persistence reached the configured gate",
            }
        )
        rules["detector_policy"]["detectors"]["configured_persistence_gate"] = detector
        weights["weights"]["configured_persistence_gate"] = 1
        engine = self._engine(rules, weights)
        frame = pd.DataFrame(
            [{"hostname": "server1"}],
            index=pd.DatetimeIndex([pd.Timestamp("2024-06-16T18:00:00Z")]),
        )
        signal_map = {0: {"persistence_service": 1.0}}
        explain_map = {0: []}

        engine._apply_non_temporal_contextual_sparse(
            frame,
            signal_map,
            explain_map,
            apply_profiling=False,
        )

        self.assertEqual(signal_map[0]["persistence_mechanism"], 1.0)
        self.assertEqual(signal_map[0]["configured_persistence_gate"], 1.0)

    def test_clamav_mapping_order_and_digest_are_authoritative(self):
        baseline = self._engine().detector_policy.clamav_classification

        token_rules = deepcopy(BASE_RULES)
        self._clamav_config(token_rules)["category_tokens"]["trojan"] = "exploit"
        token_policy = self._engine(token_rules).detector_policy.clamav_classification
        self.assertNotEqual(token_policy.policy_digest, baseline.policy_digest)
        self.assertEqual(
            MODULE.parse_clamav_signature(
                "Win.Trojan.Agent-1-0",
                token_policy,
            ).forensic_category,
            "exploit",
        )

        order_rules = deepcopy(BASE_RULES)
        self._clamav_config(order_rules)["family_overrides"].insert(
            0,
            {"contains": "agent", "category": "webshell"},
        )
        order_policy = self._engine(order_rules).detector_policy.clamav_classification
        self.assertEqual(
            MODULE.parse_clamav_signature(
                "Win.Trojan.Agent-1-0",
                order_policy,
            ).forensic_category,
            "webshell",
        )
        self.assertEqual(
            MODULE.parse_clamav_signature(
                "Php.Trojan.C99-1-0",
                baseline,
            ).forensic_category,
            "webshell",
        )

        precedence_rules = deepcopy(BASE_RULES)
        precedence_overrides = self._clamav_config(precedence_rules)[
            "family_overrides"
        ]
        for override in precedence_overrides:
            if override["contains"] == "c99shell":
                override["category"] = "ransomware"
            elif override["contains"] == "c99":
                override["category"] = "exploit"
        precedence_policy = self._engine(
            precedence_rules
        ).detector_policy.clamav_classification
        self.assertEqual(
            MODULE.parse_clamav_signature(
                "Php.Trojan.C99shell-1-0",
                precedence_policy,
            ).forensic_category,
            "ransomware",
        )
        c99shell_index = next(
            index for index, value in enumerate(precedence_overrides)
            if value["contains"] == "c99shell"
        )
        c99_index = next(
            index for index, value in enumerate(precedence_overrides)
            if value["contains"] == "c99"
        )
        precedence_overrides[c99shell_index], precedence_overrides[c99_index] = (
            precedence_overrides[c99_index],
            precedence_overrides[c99shell_index],
        )
        reversed_policy = self._engine(
            precedence_rules
        ).detector_policy.clamav_classification
        self.assertEqual(
            MODULE.parse_clamav_signature(
                "Php.Trojan.C99shell-1-0",
                reversed_policy,
            ).forensic_category,
            "exploit",
        )

    def test_clamav_category_registry_add_remove_and_order_are_authoritative(self):
        rules = deepcopy(BASE_RULES)
        weights = deepcopy(BASE_WEIGHTS)
        classifier = self._clamav_config(rules)
        configured_category = deepcopy(classifier["categories"]["malware"])
        configured_category["emission"].update(
            {
                "name": "configured_av_category",
                "rule_id": "CONFIGURED_AV_CATEGORY",
                "description": "Configured AV category",
            }
        )
        classifier["categories"] = {
            "configured_category": configured_category,
            **classifier["categories"],
        }
        classifier["category_tokens"]["configuredtoken"] = "configured_category"
        weights["weights"]["configured_av_category"] = 0

        engine = self._engine(rules, weights)
        policy = engine.detector_policy.clamav_classification
        self.assertEqual(policy.category_order[0], "configured_category")
        self.assertEqual(
            MODULE.parse_clamav_signature(
                "ConfiguredToken.Win.Payload-1-0",
                policy,
            ).forensic_category,
            "configured_category",
        )
        signal_map = {}
        engine._inject_av_signal_sparse(
            pd.DataFrame([{
                "filename": "payload.bin",
                "av_hit": True,
                "av_signature": "ConfiguredToken.Win.Payload-1-0",
            }]),
            signal_map,
            {},
        )
        self.assertEqual(signal_map[0]["configured_av_category"], 1.0)

        removed_rules = deepcopy(BASE_RULES)
        _replace_config_scalar(removed_rules, "pua", "malware")
        del self._clamav_config(removed_rules)["categories"]["pua"]
        removed_policy = self._engine(
            removed_rules
        ).detector_policy.clamav_classification
        self.assertNotIn("pua", removed_policy.category_universe)
        self.assertNotIn(
            "av_pua",
            {emission.name for emission in removed_policy.emissions},
        )

    def test_clamav_emission_metadata_evidence_and_nested_collectors_are_authoritative(self):
        rules = deepcopy(BASE_RULES)
        weights = deepcopy(BASE_WEIGHTS)
        classifier = self._clamav_config(rules)
        classifier["generic"]["emission"].update(
            {
                "name": "configured_av_generic",
                "value": 2,
                "rule_id": "CONFIGURED_AV_GENERIC",
                "description": "Configured antivirus class {forensic_category}",
                "confidence": "medium",
            }
        )
        classifier["categories"]["malware"]["emission"].update(
            {
                "name": "configured_av_malware",
                "value": 3,
                "rule_id": "CONFIGURED_AV_MALWARE",
                "description": "Configured malware category",
                "confidence": "low",
            }
        )
        classifier["categories"]["malware"]["evidence"] = ["family"]
        weights["weights"]["configured_av_generic"] = 0
        weights["weights"]["configured_av_malware"] = 0
        engine = self._engine(rules, weights)
        frame = pd.DataFrame(
            [{
                "filename": "/tmp/payload.exe",
                "av_hit": True,
                "av_signature": "Win.Trojan.Agent-1-0",
            }],
            index=pd.DatetimeIndex([pd.Timestamp("2024-06-16T19:00:00Z")]),
        )
        signal_map = {}
        explain_map = {}
        engine._inject_av_signal_sparse(frame, signal_map, explain_map)

        self.assertEqual(signal_map[0]["configured_av_generic"], 2.0)
        self.assertEqual(signal_map[0]["configured_av_malware"], 3.0)
        self.assertNotIn("av_hit", signal_map[0])
        self.assertNotIn("av_malware", signal_map[0])
        generic = next(
            item for item in explain_map[0]
            if item["rule_id"] == "CONFIGURED_AV_GENERIC"
        )
        category = next(
            item for item in explain_map[0]
            if item["rule_id"] == "CONFIGURED_AV_MALWARE"
        )
        self.assertEqual(generic["description"], "Configured antivirus class malware")
        self.assertEqual(generic["confidence"], "medium")
        self.assertEqual(category["description"], "Configured malware category")
        self.assertEqual(category["confidence"], "low")
        self.assertEqual(category["evidence"], {"family": "Agent"})
        self.assertEqual(
            engine.rule_emit_signals["CONFIGURED_AV_MALWARE"],
            ["configured_av_malware"],
        )
        emitted = MODULE._collect_emitted_signals_from_rules(rules)
        self.assertIn("configured_av_generic", emitted)
        self.assertIn("configured_av_malware", emitted)
        self.assertNotIn("av_hit", emitted)
        self.assertNotIn("av_malware", emitted)
        self.assertTrue({"av_hit", "av_signature", "filename"} <= engine.required_fields)

    def test_clamav_suppression_disablement_and_unclassified_hits_follow_policy(self):
        frame = pd.DataFrame(
            [{"filename": "toolbar.exe", "av_hit": True, "av_signature": "Win.Adware.Toolbar-1-0"}],
            index=pd.DatetimeIndex([pd.Timestamp("2024-06-16T19:10:00Z")]),
        )
        rules = deepcopy(BASE_RULES)
        self._clamav_config(rules)["categories"]["pua"]["suppress_generic"] = False
        enabled_engine = self._engine(rules)
        enabled_signals = {}
        enabled_engine._inject_av_signal_sparse(frame, enabled_signals, {})
        self.assertEqual(enabled_signals[0]["av_hit"], 1.0)
        self.assertEqual(enabled_signals[0]["av_pua"], 1.0)

        disabled_rules = deepcopy(BASE_RULES)
        self._clamav_config(disabled_rules)["enabled"] = False
        disabled_signals = {}
        self._engine(disabled_rules)._inject_av_signal_sparse(
            frame,
            disabled_signals,
            {},
        )
        self.assertEqual(disabled_signals, {})

        unclassified_frame = frame.copy()
        unclassified_frame["av_signature"] = None
        unclassified_signals = {}
        unclassified_explain = {}
        self._engine()._inject_av_signal_sparse(
            unclassified_frame,
            unclassified_signals,
            unclassified_explain,
        )
        self.assertEqual(unclassified_signals[0], {"av_hit": 1.0})
        self.assertEqual(
            unclassified_explain[0][0]["description"],
            "Antivirus hit present",
        )

    def test_clamav_classifier_output_is_available_to_atomic_policy_gates(self):
        rules = deepcopy(BASE_RULES)
        weights = deepcopy(BASE_WEIGHTS)
        detector = _expected_atomic_execution_gate(
            ["av_malware"],
            "configured_av_follow_on",
            "CONFIGURED_AV_FOLLOW_ON",
            description="Configured AV output reached an atomic gate",
        )
        rules["detector_policy"]["detectors"]["configured_av_follow_on"] = detector
        weights["weights"]["configured_av_follow_on"] = 0
        frame = pd.DataFrame(
            [{
                "filename": "/tmp/payload.exe",
                "av_hit": True,
                "av_signature": "Win.Trojan.Agent-1-0",
            }],
            index=pd.DatetimeIndex([pd.Timestamp("2024-06-16T19:20:00Z")]),
        )
        out = self._engine(rules, weights).apply_atomic(
            frame,
            apply_profiling=False,
            materialise_event_columns=True,
        )
        signals = out.iloc[0]["chronosift_signals"]
        self.assertEqual(signals["av_malware"], 1.0)
        self.assertEqual(signals["configured_av_follow_on"], 1.0)

    def test_enabled_policy_cannot_depend_on_disabled_clamav_output(self):
        rules = deepcopy(BASE_RULES)
        weights = deepcopy(BASE_WEIGHTS)
        self._clamav_config(rules)["enabled"] = False
        rules["detector_policy"]["detectors"]["configured_av_follow_on"] = (
            _expected_atomic_execution_gate(
                ["av_malware"],
                "configured_av_follow_on",
                "CONFIGURED_AV_FOLLOW_ON",
            )
        )
        weights["weights"]["configured_av_follow_on"] = 0
        with self.assertRaisesRegex(
            ValueError,
            r"configured_av_follow_on: input signal\(s\) have no enabled policy producer path: av_malware",
        ):
            self._engine(rules, weights)

        alternative_rules = deepcopy(BASE_RULES)
        alternative_weights = deepcopy(BASE_WEIGHTS)
        self._clamav_config(alternative_rules)["enabled"] = False
        alternative_detector = _expected_atomic_execution_gate(
            ["av_malware", "yara_malware"],
            "configured_av_or_yara_follow_on",
            "CONFIGURED_AV_OR_YARA_FOLLOW_ON",
        )
        alternative_rules["detector_policy"]["detectors"][
            "configured_av_or_yara_follow_on"
        ] = alternative_detector
        alternative_weights["weights"]["configured_av_or_yara_follow_on"] = 0
        alternative_engine = self._engine(
            alternative_rules,
            alternative_weights,
        )
        alternative_signals = {0: {"yara_malware": 1.0}}
        alternative_engine._apply_policy_signal_gates_sparse(
            pd.DataFrame(
                index=pd.DatetimeIndex([pd.Timestamp("2024-06-16T19:30:00Z")])
            ),
            alternative_signals,
            {0: []},
            stage="atomic",
        )
        self.assertEqual(
            alternative_signals[0]["configured_av_or_yara_follow_on"],
            1.0,
        )

    def test_classifier_output_rename_requires_downstream_temporal_reference_update(self):
        rules = deepcopy(BASE_RULES)
        weights = deepcopy(BASE_WEIGHTS)
        self._clamav_config(rules)["categories"]["ransomware"]["emission"][
            "name"
        ] = "configured_av_ransomware"
        weights["weights"]["configured_av_ransomware"] = 0

        with self.assertRaisesRegex(
            ValueError,
            r"detector_policy\.detectors\.ransomware_impact.*av_ransomware",
        ):
            self._engine(rules, weights)

    def test_renamed_clamav_categories_feed_candidates_and_temporal_composites(self):
        rules = deepcopy(BASE_RULES)
        weights = deepcopy(BASE_WEIGHTS)
        classifier = self._clamav_config(rules)
        classifier["categories"]["ransomware"]["emission"]["name"] = (
            "configured_av_ransomware"
        )
        classifier["categories"]["offensive_tool"]["emission"]["name"] = (
            "configured_av_offensive_tool"
        )
        ransomware_sources = self._ransomware_config(rules)["source"][
            "any_signals"
        ]
        ransomware_sources[ransomware_sources.index("av_ransomware")] = (
            "configured_av_ransomware"
        )
        credential_sources = self._credential_collection_config(rules)["source"][
            "any_signals"
        ]
        credential_sources[credential_sources.index("av_offensive_tool")] = (
            "configured_av_offensive_tool"
        )
        weights["weights"]["configured_av_ransomware"] = 0
        weights["weights"]["configured_av_offensive_tool"] = 0
        engine = self._engine(rules, weights)
        frame = pd.DataFrame(
            {
                "hostname": ["host1"] * 4,
                "filename": [
                    "/tmp/support.txt",
                    "/tmp/ransomware.exe",
                    "/tmp/tool.exe",
                    "/tmp/archive.zip",
                ],
                "av_hit": [False, True, True, False],
                "av_signature": [
                    None,
                    "Win.Trojan.Lockbit-1-0",
                    "Win.Trojan.Mimikatz-1-0",
                    None,
                ],
            },
            index=pd.date_range("2024-06-16T20:00:00Z", periods=4, freq="min"),
        )
        atomic = engine.apply_atomic(
            frame,
            apply_profiling=False,
            enforce_required_fields=False,
        )
        sparse = atomic.attrs["chronosift_sparse"]
        signal_map = sparse["signal_map"]
        explain_map = sparse["explain_map"]
        signal_map.setdefault(0, {})["defender_disabled"] = 1.0
        signal_map.setdefault(3, {})["archive_created"] = 1.0
        explain_map.setdefault(0, [])
        explain_map.setdefault(3, [])
        self.assertEqual(signal_map[1]["configured_av_ransomware"], 1.0)
        self.assertEqual(signal_map[2]["configured_av_offensive_tool"], 1.0)
        self.assertNotIn("av_ransomware", signal_map[1])
        self.assertNotIn("av_offensive_tool", signal_map[2])
        candidate_mask = engine._temporal_candidate_base_mask(atomic, signal_map)
        self.assertTrue(candidate_mask.iloc[1])
        self.assertTrue(candidate_mask.iloc[2])

        engine._apply_deadbox_temporal_composites_sparse(
            atomic,
            signal_map,
            explain_map,
        )
        self.assertEqual(signal_map[1]["ransomware_impact"], 1.0)
        self.assertEqual(signal_map[2]["credential_dump_collection"], 1.0)
        ransomware_evidence = next(
            item["evidence"] for item in explain_map[1]
            if item["rule_id"] == "RANSOMWARE_IMPACT"
        )
        self.assertIn(
            "configured_av_ransomware",
            ransomware_evidence["source_signals"].split(","),
        )

    def test_yara_ordered_classification_and_digest_are_authoritative(self):
        baseline = self._engine().detector_policy.yara_classification
        overlapping_name = "TEST_Ransomware_Mimikatz"
        self.assertEqual(
            MODULE._classify_yara_rule(overlapping_name, baseline),
            "offensive_tool",
        )
        self.assertEqual(
            MODULE._classify_yara_rule(
                overlapping_name,
                baseline,
                meta_tc_detection_type="ransomware",
            ),
            "ransomware",
        )

        reordered_rules = deepcopy(BASE_RULES)
        ordered = self._yara_config(reordered_rules)["classification"][
            "ordered_rules"
        ]
        ransomware_rule = next(
            rule for rule in ordered if rule["id"] == "ransomware_name"
        )
        ordered.remove(ransomware_rule)
        offensive_index = next(
            index
            for index, rule in enumerate(ordered)
            if rule["id"] == "offensive_tool_name"
        )
        ordered.insert(offensive_index, ransomware_rule)
        reordered = self._engine(
            reordered_rules
        ).detector_policy.yara_classification
        self.assertNotEqual(reordered.policy_digest, baseline.policy_digest)
        self.assertEqual(
            MODULE._classify_yara_rule(overlapping_name, reordered),
            "ransomware",
        )

    def test_yara_category_registry_add_remove_and_order_are_authoritative(self):
        rules = deepcopy(BASE_RULES)
        weights = deepcopy(BASE_WEIGHTS)
        classifier = self._yara_config(rules)
        configured_category = deepcopy(classifier["categories"]["malware"])
        configured_category["emission"].update(
            {
                "name": "configured_yara_category",
                "rule_id": "CONFIGURED_YARA_CATEGORY",
                "description": "Configured YARA category",
            }
        )
        classifier["categories"] = {
            "configured_category": configured_category,
            **classifier["categories"],
        }
        classifier["classification"]["ordered_rules"].insert(
            0,
            {
                "id": "configured_category_name",
                "category": "configured_category",
                "all": [{
                    "field": "rule_name",
                    "op": "contains_any",
                    "values": ["configured_rule"],
                }],
            },
        )
        weights["weights"]["configured_yara_category"] = 0

        engine = self._engine(rules, weights)
        policy = engine.detector_policy.yara_classification
        self.assertEqual(policy.category_order[0], "configured_category")
        self.assertEqual(
            MODULE._classify_yara_rule("CONFIGURED_RULE", policy),
            "configured_category",
        )
        engine._yara_metadata_index = {
            "CONFIGURED_RULE": MODULE.YaraRuleMeta(
                score=90,
                quality=90,
                category="configured_category",
            )
        }
        engine._yara_metadata_available = True
        signal_map = {}
        engine._inject_yara_signal_sparse(
            pd.DataFrame([{
                "yara_match": '["CONFIGURED_RULE"]',
                "yara_match_count": 1,
            }]),
            signal_map,
            {},
        )
        self.assertEqual(signal_map[0]["configured_yara_category"], 1.0)

        removed_rules = deepcopy(BASE_RULES)
        removed_classifier = self._yara_config(removed_rules)
        for rule in removed_classifier["classification"]["ordered_rules"]:
            if rule["category"] == "certificate":
                rule["category"] = "malware"
        del removed_classifier["categories"]["certificate"]
        removed_policy = self._engine(
            removed_rules
        ).detector_policy.yara_classification
        self.assertNotIn("certificate", removed_policy.category_universe)
        self.assertNotIn(
            "yara_certificate_blocklist",
            {emission.name for emission in removed_policy.emissions},
        )

    def test_yara_indexed_strength_category_confidence_and_disablement_follow_policy(self):
        engine = self._engine()
        engine._yara_metadata_index = {
            "CERT": MODULE.YaraRuleMeta(
                score=100,
                quality=100,
                category="certificate",
            ),
            "LOW": MODULE.YaraRuleMeta(
                score=50,
                quality=60,
                category="malware",
            ),
            "HIGH": MODULE.YaraRuleMeta(
                score=90,
                quality=80,
                category="ransomware",
            ),
        }
        engine._yara_metadata_available = True
        frame = pd.DataFrame(
            [{
                "yara_match": '["CERT", "LOW", "HIGH", "HIGH"]',
                "yara_match_count": 4,
            }],
            index=pd.DatetimeIndex([pd.Timestamp("2024-06-16T19:40:00Z")]),
        )
        signal_map = {}
        explain_map = {}
        engine._inject_yara_signal_sparse(frame, signal_map, explain_map)

        self.assertAlmostEqual(signal_map[0]["yara_hit_strength"], 0.6)
        self.assertEqual(signal_map[0]["yara_certificate_blocklist"], 1.0)
        self.assertEqual(signal_map[0]["yara_malware"], 1.0)
        self.assertEqual(signal_map[0]["yara_ransomware"], 1.0)
        strength = next(
            item for item in explain_map[0]
            if item["rule_id"] == "YARA_HIT_STRENGTH"
        )
        certificate = next(
            item for item in explain_map[0]
            if item["rule_id"] == "YARA_CERTIFICATE"
        )
        malware = next(
            item for item in explain_map[0]
            if item["rule_id"] == "YARA_MALWARE"
        )
        ransomware = next(
            item for item in explain_map[0]
            if item["rule_id"] == "YARA_RANSOMWARE"
        )
        self.assertEqual(strength["confidence"], "medium")
        self.assertEqual(strength["evidence"]["contributing_rule_count"], 2)
        self.assertEqual(strength["evidence"]["best_score"], 90)
        self.assertEqual(certificate["confidence"], "high")
        self.assertEqual(malware["confidence"], "medium")
        self.assertEqual(malware["evidence"]["best_score"], 50)
        self.assertEqual(ransomware["confidence"], "high")
        self.assertEqual(ransomware["evidence"]["best_score"], 90)

        disabled_rules = deepcopy(BASE_RULES)
        self._yara_config(disabled_rules)["enabled"] = False
        disabled_engine = self._engine(disabled_rules)
        disabled_signals = {}
        disabled_engine._inject_yara_signal_sparse(frame, disabled_signals, {})
        self.assertEqual(disabled_signals, {})
        self.assertNotIn("yara_match", disabled_engine.required_fields)

    def test_renamed_yara_categories_feed_candidates_and_temporal_composites(self):
        rules = deepcopy(BASE_RULES)
        weights = deepcopy(BASE_WEIGHTS)
        classifier = self._yara_config(rules)
        classifier["categories"]["ransomware"]["emission"]["name"] = (
            "configured_yara_ransomware"
        )
        classifier["categories"]["offensive_tool"]["emission"]["name"] = (
            "configured_yara_offensive_tool"
        )
        ransomware_sources = self._ransomware_config(rules)["source"][
            "any_signals"
        ]
        ransomware_sources[ransomware_sources.index("yara_ransomware")] = (
            "configured_yara_ransomware"
        )
        credential_sources = self._credential_collection_config(rules)["source"][
            "any_signals"
        ]
        credential_sources[credential_sources.index("yara_offensive_tool")] = (
            "configured_yara_offensive_tool"
        )
        weights["weights"]["configured_yara_ransomware"] = 0
        weights["weights"]["configured_yara_offensive_tool"] = 0
        engine = self._engine(rules, weights)
        engine._yara_metadata_index = {
            "RANSOM": MODULE.YaraRuleMeta(
                score=90,
                quality=90,
                category="ransomware",
            ),
            "TOOL": MODULE.YaraRuleMeta(
                score=90,
                quality=90,
                category="offensive_tool",
            ),
        }
        engine._yara_metadata_available = True
        frame = pd.DataFrame(
            {
                "hostname": ["host1"] * 4,
                "filename": [
                    "/tmp/support.txt",
                    "/tmp/ransomware.exe",
                    "/tmp/tool.exe",
                    "/tmp/archive.zip",
                ],
                "yara_match": [None, '["RANSOM"]', '["TOOL"]', None],
            },
            index=pd.date_range("2024-06-16T20:10:00Z", periods=4, freq="min"),
        )
        atomic = engine.apply_atomic(
            frame,
            apply_profiling=False,
            enforce_required_fields=False,
        )
        sparse = atomic.attrs["chronosift_sparse"]
        signal_map = sparse["signal_map"]
        explain_map = sparse["explain_map"]
        signal_map.setdefault(0, {})["defender_disabled"] = 1.0
        signal_map.setdefault(3, {})["archive_created"] = 1.0
        explain_map.setdefault(0, [])
        explain_map.setdefault(3, [])
        self.assertEqual(signal_map[1]["configured_yara_ransomware"], 1.0)
        self.assertEqual(signal_map[2]["configured_yara_offensive_tool"], 1.0)
        self.assertNotIn("yara_ransomware", signal_map[1])
        self.assertNotIn("yara_offensive_tool", signal_map[2])
        candidate_mask = engine._temporal_candidate_base_mask(atomic, signal_map)
        self.assertTrue(candidate_mask.iloc[1])
        self.assertTrue(candidate_mask.iloc[2])

        engine._apply_deadbox_temporal_composites_sparse(
            atomic,
            signal_map,
            explain_map,
        )
        self.assertEqual(signal_map[1]["ransomware_impact"], 1.0)
        self.assertEqual(signal_map[2]["credential_dump_collection"], 1.0)
        ransomware_evidence = next(
            item["evidence"] for item in explain_map[1]
            if item["rule_id"] == "RANSOMWARE_IMPACT"
        )
        self.assertIn(
            "configured_yara_ransomware",
            ransomware_evidence["source_signals"].split(","),
        )

    def test_clamav_policy_validation_reports_precise_paths(self):
        cases = []

        rules = deepcopy(BASE_RULES)
        self._clamav_config(rules)["unexpected"] = True
        cases.append((rules, deepcopy(BASE_WEIGHTS), r"clamav_classification: unknown key"))

        rules = deepcopy(BASE_RULES)
        del self._clamav_config(rules)["categories"]["webshell"]
        cases.append((rules, deepcopy(BASE_WEIGHTS), r"family_overrides\[10\]\.category: expected one of"))

        rules = deepcopy(BASE_RULES)
        self._clamav_config(rules)["default_category"] = "unknown"
        cases.append((rules, deepcopy(BASE_WEIGHTS), r"default_category: expected one of"))

        rules = deepcopy(BASE_RULES)
        classifier = self._clamav_config(rules)
        classifier["family_overrides"].append(deepcopy(classifier["family_overrides"][0]))
        cases.append((rules, deepcopy(BASE_WEIGHTS), r"family_overrides\[28\]\.contains: duplicate"))

        rules = deepcopy(BASE_RULES)
        self._clamav_config(rules)["category_tokens"]["trojan "] = "exploit"
        cases.append((rules, deepcopy(BASE_WEIGHTS), r"trojan: duplicate normalised category token"))

        rules = deepcopy(BASE_RULES)
        self._clamav_config(rules)["generic"]["evidence"].append("unknown_evidence")
        cases.append((rules, deepcopy(BASE_WEIGHTS), r"generic\.evidence: unsupported value"))

        rules = deepcopy(BASE_RULES)
        self._clamav_config(rules)["generic"]["emission"]["description"] = "Bad {placeholder}"
        cases.append((rules, deepcopy(BASE_WEIGHTS), r"description: only the .* placeholder"))

        rules = deepcopy(BASE_RULES)
        self._clamav_config(rules)["categories"]["malware"]["emission"]["name"] = (
            "unweighted_av_output"
        )
        cases.append((rules, deepcopy(BASE_WEIGHTS), r"emissions missing weights: unweighted_av_output"))

        for rules_doc, weights_doc, pattern in cases:
            with self.subTest(pattern=pattern):
                with self.assertRaisesRegex(ValueError, pattern):
                    self._engine(rules_doc, weights_doc)

    def test_yara_policy_validation_reports_precise_paths(self):
        cases = []

        rules = deepcopy(BASE_RULES)
        self._yara_config(rules)["unexpected"] = True
        cases.append((rules, r"yara_classification: unknown key"))

        rules = deepcopy(BASE_RULES)
        del self._yara_config(rules)["metadata"]["defaults"]
        cases.append((rules, r"metadata: missing required key.*defaults"))

        rules = deepcopy(BASE_RULES)
        del self._yara_config(rules)["categories"]["certificate"]
        cases.append((rules, r"ordered_rules\[4\]\.category: expected one of"))

        rules = deepcopy(BASE_RULES)
        self._yara_config(rules)["classification"]["ordered_rules"][-1]["all"][0][
            "pattern"
        ] = "["
        cases.append((rules, r"pattern: invalid regular expression"))

        rules = deepcopy(BASE_RULES)
        self._yara_config(rules)["categories"]["malware"]["emission"]["name"] = (
            "unweighted_yara_output"
        )
        cases.append((rules, r"emissions missing weights: unweighted_yara_output"))

        for rules_doc, pattern in cases:
            with self.subTest(pattern=pattern):
                with self.assertRaisesRegex(ValueError, pattern):
                    self._engine(rules_doc)

    def test_referenced_file_policy_registries_and_order_are_authoritative(self):
        baseline = self._engine().detector_policy.referenced_file_correlation
        rules = deepcopy(BASE_RULES)
        correlation = self._correlation_config(rules)

        configured_yara = correlation["emissions"].pop("referenced_yara")
        correlation["emissions"]["configured_yara_slot"] = configured_yara
        correlation["propagation"]["yara"]["emission"] = (
            "configured_yara_slot"
        )
        correlation["web"] = {
            ("configured_access_branch" if branch_id == "file_access" else branch_id): value
            for branch_id, value in correlation["web"].items()
        }
        outputs = correlation["mappings"]["outputs"]
        correlation["mappings"]["outputs"] = {
            ("configured_t1190_slot" if output_id == "t1190" else output_id): value
            for output_id, value in outputs.items()
        }
        for branch in correlation["mappings"]["branches"].values():
            branch["emissions"] = [
                "configured_t1190_slot" if output_id == "t1190" else output_id
                for output_id in branch["emissions"]
            ]
        correlation["mappings"]["branches"] = {
            (
                "configured_exploit_branch"
                if branch_id == "exploit_syntax"
                else branch_id
            ): value
            for branch_id, value in correlation["mappings"]["branches"].items()
        }

        configured = self._engine(rules).detector_policy.referenced_file_correlation
        self.assertIn("configured_yara_slot", configured.emissions_by_id)
        self.assertEqual(
            configured.propagation["yara"].emission_id,
            "configured_yara_slot",
        )
        self.assertIn(
            "configured_access_branch",
            {branch.branch_id for branch in configured.web_branches},
        )
        self.assertIn("configured_t1190_slot", configured.mapping_outputs)
        self.assertIn(
            "configured_exploit_branch",
            {branch.branch_id for branch in configured.mapping_branches},
        )
        self.assertNotEqual(configured.policy_digest, baseline.policy_digest)

        reordered_rules = deepcopy(BASE_RULES)
        reordered = self._correlation_config(reordered_rules)
        reordered["web"] = dict(reversed(tuple(reordered["web"].items())))
        reordered_policy = self._engine(
            reordered_rules
        ).detector_policy.referenced_file_correlation
        self.assertEqual(
            set(branch.branch_id for branch in reordered_policy.web_branches),
            set(branch.branch_id for branch in baseline.web_branches),
        )
        self.assertNotEqual(
            reordered_policy.policy_digest,
            baseline.policy_digest,
        )

    def test_web_request_policy_validation_rejects_ambiguous_or_dead_config(self):
        cases = []

        rules = deepcopy(BASE_RULES)
        self._web_request_config(rules)["exploit"]["branches"][
            "exploit_syntax"
        ]["conditions"]["indicators_any"].append("misspelled_indicator")
        cases.append((rules, r"unknown indicator\(s\): misspelled_indicator"))

        rules = deepcopy(BASE_RULES)
        self._web_request_config(rules)["exploit"]["branches"][
            "exploit_syntax"
        ]["conditions"]["indicator_prefixes_any"] = ["never-matches:"]
        cases.append((rules, r"prefix\(es\) match no configured indicator"))

        rules = deepcopy(BASE_RULES)
        self._web_request_config(rules)["outcomes"]["redirect_status"][
            "minimum"
        ] = 250
        cases.append((rules, r"success_status and redirect_status ranges must not overlap"))

        rules = deepcopy(BASE_RULES)
        web = self._web_request_config(rules)
        web["sqli"]["emissions"]["response_anomaly"] = web["sqli"][
            "emissions"
        ]["attempt"]
        cases.append((rules, r"SQLi emission roles must reference distinct emissions"))

        rules = deepcopy(BASE_RULES)
        self._web_request_config(rules)["sqli"]["baseline"]["key_fields"] = [
            "opaque_role"
        ]
        cases.append((rules, r"sqli\.baseline\.key_fields: unknown role"))

        rules = deepcopy(BASE_RULES)
        self._web_request_config(rules)["sqli"]["baseline"][
            "threshold_terms"
        ] = ["opaque_term"]
        cases.append((rules, r"sqli\.baseline\.threshold_terms: unknown term"))

        rules = deepcopy(BASE_RULES)
        self._web_request_config(rules)["sqli"]["decisions"]["attempt"][
            "all"
        ] = ["opaque_fact"]
        cases.append((rules, r"sqli\.decisions\.attempt\.all\[0\]: unknown fact"))

        rules = deepcopy(BASE_RULES)
        web = self._web_request_config(rules)
        web["exploit"]["emission"] = web["sqli"]["emissions"]["attempt"]
        cases.append((rules, r"exploit and SQLi roles must reference distinct emissions"))

        rules = deepcopy(BASE_RULES)
        probe = self._web_request_config(rules)["indicators"]["injection_probe"]
        probe["minimum_metacharacters"] = 2
        probe["minimum_distinct_metacharacters"] = 3
        cases.append(
            (
                rules,
                r"minimum_distinct_metacharacters.*less than or equal",
            )
        )

        rules = deepcopy(BASE_RULES)
        self._web_request_config(rules)["outcomes"]["web"]["attempt_when"][
            "indicators_any"
        ] = ["misspelled_indicator"]
        cases.append((rules, r"attempt_when\.indicators_any: unknown indicator"))

        rules = deepcopy(BASE_RULES)
        attempt_when = self._web_request_config(rules)["outcomes"]["web"][
            "attempt_when"
        ]
        attempt_when["indicators_any"] = []
        attempt_when["indicator_prefixes_any"] = ["never-matches:"]
        cases.append(
            (rules, r"attempt_when\.indicator_prefixes_any: prefix\(es\) match no")
        )

        rules = deepcopy(BASE_RULES)
        self._web_request_config(rules)["upload"]["mime_value_pairing"] = (
            "opaque_strategy"
        )
        cases.append((rules, r"upload\.mime_value_pairing"))

        rules = deepcopy(BASE_RULES)
        del self._web_request_config(rules)["upload"][
            "filename_extension_admission"
        ]
        cases.append(
            (rules, r"upload: missing required key\(s\): filename_extension_admission")
        )

        rules = deepcopy(BASE_RULES)
        self._web_request_config(rules)["upload"][
            "require_filename_extension"
        ] = True
        cases.append((rules, r"upload: unknown key\(s\): require_filename_extension"))

        rules = deepcopy(BASE_RULES)
        self._web_request_config(rules)["upload"][
            "filename_extension_admission"
        ] = "dot_somewhere"
        cases.append((rules, r"filename_extension_admission: expected one of"))

        rules = deepcopy(BASE_RULES)
        self._web_request_config(rules)["upload"]["mime_mismatch"][
            "branches"
        ][0]["all"] = ["opaque_fact"]
        cases.append((rules, r"mime_mismatch\.branches\[0\]\.all\[0\]: unknown fact"))

        rules = deepcopy(BASE_RULES)
        del self._web_request_config(rules)["outcomes"]["web"]["selection"]
        cases.append((rules, r"outcomes\.web: missing required key\(s\): selection"))

        rules = deepcopy(BASE_RULES)
        outcome_ranks = self._web_request_config(rules)["outcomes"]["web"][
            "selection"
        ]["ranks"]
        outcome_ranks["probable_success"] = outcome_ranks["attempt"]
        cases.append((rules, r"selection\.ranks: rank values must be distinct"))

        for rules_doc, pattern in cases:
            with self.subTest(pattern=pattern):
                with self.assertRaisesRegex(ValueError, pattern):
                    self._engine(rules_doc)

    def test_referenced_file_policy_can_disable_individual_match_routes(self):
        rules = deepcopy(BASE_RULES)
        correlation = self._correlation_config(rules)
        correlation["propagation"].pop("luhn")
        correlation["emissions"].pop("referenced_luhn")
        rules["engine_config"]["temporal_signal_policy"][
            "ineligible_signals"
        ].remove("referenced_file_luhn_hit")
        correlation["matching"]["web_document_roots"] = []
        web = self._web_request_config(rules)
        web["matching"]["web_log_parser_tokens"] = []
        web["upload"]["methods"] = []
        web["upload"]["nameless_methods"] = []
        policy = self._engine(rules).detector_policy.referenced_file_correlation
        self.assertNotIn("luhn", policy.propagation)
        self.assertEqual(policy.document_roots, ())
        self.assertEqual(policy.web_log_parser_tokens, ())
        self.assertEqual(policy.upload_methods, frozenset())

    def test_referenced_file_policy_validation_reports_precise_paths(self):
        cases = []

        rules = deepcopy(BASE_RULES)
        del rules["detector_policy"]["detectors"]["referenced_file_correlation"]
        cases.append((rules, r"missing required key.*referenced_file_correlation"))

        rules = deepcopy(BASE_RULES)
        self._correlation_config(rules)["propagation"]["av"]["emission"] = (
            "missing_slot"
        )
        cases.append((rules, r"propagation\.av\.emission: unknown emission"))

        rules = deepcopy(BASE_RULES)
        web_outputs = self._web_request_config(rules)["outputs"]
        web_outputs["endpoint"] = web_outputs["method"]
        cases.append((rules, r"canonical role collision"))

        rules = deepcopy(BASE_RULES)
        self._web_request_config(rules)["outputs"]["method"] = "configured_method"
        cases.append((rules, r"must use the 'chronosift_' sidecar namespace"))

        rules = deepcopy(BASE_RULES)
        self._web_request_config(rules)["outputs"]["method"] = (
            "chronosift_hour_rarity_score"
        )
        cases.append((rules, r"reserved field chronosift_hour_rarity_score"))

        rules = deepcopy(BASE_RULES)
        web = self._web_request_config(rules)
        web["inputs"]["parser"] = web["outputs"]["method"]
        cases.append((rules, r"raw input field chronosift_web_method"))

        rules = deepcopy(BASE_RULES)
        self._correlation_config(rules)["mappings"]["branches"][
            "exploit_syntax"
        ]["conditions"]["signals_any"].append("mitre_t1190")
        cases.append((rules, r"policy-to-policy input signal.*not available"))

        rules = deepcopy(BASE_RULES)
        exploit_conditions = self._correlation_config(rules)["mappings"][
            "branches"
        ]["exploit_syntax"]["conditions"]
        exploit_conditions["signals_any"].append("staging_then_transfer")
        cases.append((rules, r"input signal\(s\) are emitted after"))

        rules = deepcopy(BASE_RULES)
        rules["engine_config"]["referenced_file_hit_propagation"] = {}
        cases.append((rules, r"referenced_file_hit_propagation: obsolete"))

        rules = deepcopy(BASE_RULES)
        self._correlation_config(rules)["web_outcome_merge"]["ranks"].pop(
            "probable_success"
        )
        cases.append((rules, r"web_outcome_merge\.ranks: missing rank"))

        for rules_doc, pattern in cases:
            with self.subTest(pattern=pattern):
                with self.assertRaisesRegex(ValueError, pattern):
                    self._engine(rules_doc)

    def test_yara_metadata_bytes_invalidate_manifest_source_digest(self):
        referenced_file_policy = (
            self._engine().detector_policy.referenced_file_correlation
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            root = pathlib.Path(tmpdir) / "dataset"
            root.mkdir()
            metadata_path = pathlib.Path(tmpdir) / "rules.yar"
            metadata_path.write_text("rule ALPHA { condition: true }\n", encoding="utf-8")
            original_stat = metadata_path.stat()
            first = MODULE._referenced_file_manifest_source_digest(
                str(root),
                referenced_file_policy=referenced_file_policy,
                yara_metadata_path=str(metadata_path),
            )
            metadata_path.write_text("rule BRAVO { condition: true }\n", encoding="utf-8")
            os.utime(
                metadata_path,
                ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns),
            )
            changed_stat = metadata_path.stat()
            self.assertEqual(changed_stat.st_size, original_stat.st_size)
            self.assertEqual(changed_stat.st_mtime_ns, original_stat.st_mtime_ns)
            second = MODULE._referenced_file_manifest_source_digest(
                str(root),
                referenced_file_policy=referenced_file_policy,
                yara_metadata_path=str(metadata_path),
            )
            self.assertNotEqual(first, second)

            index_one = {
                "RULE": MODULE.YaraRuleMeta(
                    score=90,
                    quality=80,
                    category="webshell",
                )
            }
            index_two = {
                "RULE": MODULE.YaraRuleMeta(
                    score=60,
                    quality=80,
                    category="webshell",
                )
            }
            indexed_first = MODULE._referenced_file_manifest_source_digest(
                str(root),
                referenced_file_policy=referenced_file_policy,
                yara_metadata_path=str(metadata_path),
                yara_metadata_index=index_one,
            )
            indexed_second = MODULE._referenced_file_manifest_source_digest(
                str(root),
                referenced_file_policy=referenced_file_policy,
                yara_metadata_path=str(metadata_path),
                yara_metadata_index=index_two,
            )
            self.assertNotEqual(indexed_first, indexed_second)

    def test_manifest_uses_configured_current_path_field(self):
        rules = deepcopy(BASE_RULES)
        self._correlation_config(rules)["inputs"]["current_path"] = (
            "artifact_path"
        )
        engine = self._engine(rules)
        with tempfile.TemporaryDirectory() as tmpdir:
            root = pathlib.Path(tmpdir) / "dataset"
            part = root / "year=2024" / "month=6"
            part.mkdir(parents=True)
            configured_path = "/var/www/html/configured.php"
            pd.DataFrame([{
                "artifact_path": configured_path,
                "av_hit": True,
                "av_signature": "Php.Trojan.C99-1-0",
            }]).to_parquet(part / "part-00000.parquet", index=False)

            manifest = MODULE.build_global_referenced_file_hit_manifest(
                str(root),
                referenced_file_policy=(
                    engine.detector_policy.referenced_file_correlation
                ),
                yara_metadata_path=BASE_YARA_PATH,
                clamav_classifier_policy=(
                    engine.detector_policy.clamav_classification
                ),
                yara_classifier_policy=(
                    engine.detector_policy.yara_classification
                ),
            )

        self.assertEqual(manifest["hit_map"][configured_path], {"av"})
        self.assertEqual(
            manifest["file_identity_map"][configured_path]["av_categories"],
            {"webshell"},
        )

    def test_disabled_yara_keeps_raw_manifest_identity_but_blocks_aliases(self):
        disabled_rules = deepcopy(BASE_RULES)
        self._yara_config(disabled_rules)["enabled"] = False
        disabled_engine = self._engine(disabled_rules)
        with tempfile.TemporaryDirectory() as tmpdir:
            root = pathlib.Path(tmpdir) / "dataset"
            part = root / "year=2024" / "month=6"
            part.mkdir(parents=True)
            file_hash = "F" * 64
            path = "/var/www/html/shell.php"
            pd.DataFrame(
                [{
                    "filename": path,
                    "sha256_hash": file_hash,
                    "yara_match": '["strong_shell"]',
                }]
            ).to_parquet(part / "part-00000.parquet", index=False)
            metadata_path = pathlib.Path(tmpdir) / "rules.yar"
            metadata_path.write_text("// synthetic test provenance\n", encoding="utf-8")
            manifest = MODULE.build_global_referenced_file_hit_manifest(
                str(root),
                referenced_file_policy=(
                    disabled_engine.detector_policy.referenced_file_correlation
                ),
                yara_metadata_index={
                    "strong_shell": MODULE.YaraRuleMeta(
                        score=90,
                        quality=80,
                        category="webshell",
                    )
                },
                yara_metadata_path=str(metadata_path),
                clamav_classifier_policy=(
                    disabled_engine.detector_policy.clamav_classification
                ),
                yara_classifier_policy=(
                    disabled_engine.detector_policy.yara_classification
                ),
            )
            changed_index_manifest = MODULE.build_global_referenced_file_hit_manifest(
                str(root),
                referenced_file_policy=(
                    disabled_engine.detector_policy.referenced_file_correlation
                ),
                yara_metadata_index={
                    "strong_shell": MODULE.YaraRuleMeta(
                        score=89,
                        quality=80,
                        category="webshell",
                    )
                },
                yara_metadata_path=str(metadata_path),
                clamav_classifier_policy=(
                    disabled_engine.detector_policy.clamav_classification
                ),
                yara_classifier_policy=(
                    disabled_engine.detector_policy.yara_classification
                ),
            )

        self.assertEqual(manifest["hit_map"][path], {"yara"})
        raw_identity = manifest["file_identity_map"][path]
        self.assertEqual(raw_identity["hit_types"], {"yara"})
        self.assertEqual(raw_identity["yara_rules"], set())
        self.assertEqual(raw_identity["yara_categories"], set())
        self.assertEqual(raw_identity["yara_rule_metadata"], {})
        self.assertNotIn("/shell.php", manifest["web_path_map"])
        self.assertNotIn(file_hash, manifest["hash_hit_map"])
        self.assertNotEqual(
            manifest["source_digest"],
            changed_index_manifest["source_digest"],
        )

    def test_yara_allow_unnamed_qualifies_materialised_count_by_path_and_hash(self):
        rules = deepcopy(BASE_RULES)
        self._yara_config(rules)["referenced_file_gate"]["allow_unnamed"] = True
        engine = self._engine(rules)
        with tempfile.TemporaryDirectory() as tmpdir:
            root = pathlib.Path(tmpdir) / "dataset"
            part = root / "year=2024" / "month=6"
            part.mkdir(parents=True)
            file_hash = "1" * 64
            path = "/var/www/html/unnamed.bin"
            pd.DataFrame(
                [{
                    "filename": path,
                    "sha256_hash": file_hash,
                    "yara_match_count": 1,
                }]
            ).to_parquet(part / "part-00000.parquet", index=False)
            metadata_path = pathlib.Path(tmpdir) / "rules.yar"
            metadata_path.write_text("// no indexed rules\n", encoding="utf-8")
            manifest = MODULE.build_global_referenced_file_hit_manifest(
                str(root),
                referenced_file_policy=(
                    engine.detector_policy.referenced_file_correlation
                ),
                yara_metadata_index={},
                yara_metadata_path=str(metadata_path),
                clamav_classifier_policy=(
                    engine.detector_policy.clamav_classification
                ),
                yara_classifier_policy=engine.detector_policy.yara_classification,
            )

        self.assertEqual(manifest["web_path_map"]["/unnamed.bin"], {"yara"})
        self.assertEqual(manifest["hash_hit_map"][file_hash], {"yara"})
        self.assertEqual(
            manifest["hash_identity_map"][file_hash]["yara_rules"],
            set(),
        )

    def test_clamav_manifest_uses_policy_for_csv_signatures_and_preserves_digest(self):
        engine = self._engine()
        policy = engine.detector_policy.clamav_classification
        yara_policy = engine.detector_policy.yara_classification
        referenced_file_policy = engine.detector_policy.referenced_file_correlation
        csv_only_hash = "A" * 64
        existing_only_hash = "B" * 64
        combined_hash = "C" * 64
        with tempfile.TemporaryDirectory() as tmpdir:
            root = pathlib.Path(tmpdir) / "dataset"
            part = root / "year=2024" / "month=6"
            part.mkdir(parents=True)
            pd.DataFrame(
                [
                    {
                        "filename": "/var/www/html/csv-only.exe",
                        "sha256_hash": csv_only_hash,
                        "av_hit": False,
                        "av_signature": "Php.Trojan.C99-1-0",
                    },
                    {
                        "filename": "/var/www/html/existing-only.exe",
                        "sha256_hash": existing_only_hash,
                        "av_hit": True,
                        "av_signature": "Win.Trojan.Agent-1-0",
                    },
                    {
                        "filename": "/var/www/html/combined.php",
                        "sha256_hash": combined_hash,
                        "av_hit": True,
                        "av_signature": "Win.Trojan.Agent-1-0",
                    },
                ]
            ).to_parquet(part / "part-00000.parquet", index=False)
            av_csv = pathlib.Path(tmpdir) / "av.csv"
            av_csv.write_text(
                "sha256,av_signature,av_hit\n"
                f"{csv_only_hash},Win.Trojan.Lockbit-1-0,True\n"
                f"{existing_only_hash},Win.Trojan.Lockbit-1-0,False\n"
                f"{combined_hash},Php.Trojan.C99-1-0,True\n",
                encoding="utf-8",
            )
            manifest = MODULE.build_global_referenced_file_hit_manifest(
                str(root),
                av_csv_path=str(av_csv),
                referenced_file_policy=referenced_file_policy,
                yara_metadata_path=BASE_YARA_PATH,
                clamav_classifier_policy=policy,
                yara_classifier_policy=yara_policy,
            )
            identity = manifest["file_identity_map"]["/var/www/html/csv-only.exe"]
            self.assertEqual(
                manifest["schema_version"],
                MODULE.REFERENCED_FILE_HIT_MANIFEST_SCHEMA_VERSION,
            )
            self.assertEqual(manifest["clamav_policy_digest"], policy.policy_digest)
            self.assertEqual(
                manifest["yara_policy_digest"],
                yara_policy.policy_digest,
            )
            self.assertEqual(
                manifest["correlation_policy_digest"],
                referenced_file_policy.policy_digest,
            )
            self.assertEqual(len(manifest["source_digest"]), 64)
            self.assertEqual(identity["av_categories"], {"ransomware"})
            self.assertEqual(identity["av_families"], {"Lockbit"})
            self.assertEqual(identity["av_signatures"], {"Win.Trojan.Lockbit-1-0"})

            existing_identity = manifest["file_identity_map"][
                "/var/www/html/existing-only.exe"
            ]
            self.assertEqual(existing_identity["av_categories"], {"malware"})
            self.assertEqual(existing_identity["av_families"], {"Agent"})
            self.assertEqual(
                existing_identity["av_signatures"],
                {"Win.Trojan.Agent-1-0"},
            )

            combined_identity = manifest["file_identity_map"][
                "/var/www/html/combined.php"
            ]
            self.assertEqual(
                combined_identity["av_categories"],
                {"malware", "webshell"},
            )
            self.assertEqual(combined_identity["av_families"], {"Agent", "C99"})
            self.assertEqual(
                combined_identity["av_signatures"],
                {"Win.Trojan.Agent-1-0", "Php.Trojan.C99-1-0"},
            )
            self.assertEqual(
                MODULE._deserialise_file_hit_manifest(
                    MODULE._serialise_file_hit_manifest(manifest)
                ),
                manifest,
            )

            disabled_rules = deepcopy(BASE_RULES)
            self._clamav_config(disabled_rules)["enabled"] = False
            disabled_engine = self._engine(disabled_rules)
            disabled_policy = disabled_engine.detector_policy.clamav_classification
            disabled_manifest = MODULE.build_global_referenced_file_hit_manifest(
                str(root),
                av_csv_path=str(av_csv),
                referenced_file_policy=(
                    disabled_engine.detector_policy.referenced_file_correlation
                ),
                yara_metadata_path=BASE_YARA_PATH,
                clamav_classifier_policy=disabled_policy,
                yara_classifier_policy=yara_policy,
            )
            disabled_identity = disabled_manifest["file_identity_map"][
                "/var/www/html/csv-only.exe"
            ]
            self.assertEqual(disabled_identity["hit_types"], {"av"})
            self.assertEqual(disabled_identity["av_categories"], set())
            self.assertEqual(disabled_identity["av_families"], set())
            self.assertEqual(
                disabled_identity["av_signatures"],
                {"Win.Trojan.Lockbit-1-0"},
            )

            self.assertIsNone(
                MODULE._file_hit_manifest_stale_reason(
                    manifest,
                    expected_clamav_policy_digest=policy.policy_digest,
                    expected_yara_policy_digest=yara_policy.policy_digest,
                    expected_correlation_policy_digest=(
                        referenced_file_policy.policy_digest
                    ),
                    expected_source_digest=manifest["source_digest"],
                )
            )
            forward_schema = deepcopy(manifest)
            forward_schema["schema_version"] += 1
            self.assertRegex(
                MODULE._file_hit_manifest_stale_reason(
                    forward_schema,
                    expected_clamav_policy_digest=policy.policy_digest,
                    expected_yara_policy_digest=yara_policy.policy_digest,
                    expected_correlation_policy_digest=(
                        referenced_file_policy.policy_digest
                    ),
                    expected_source_digest=manifest["source_digest"],
                ),
                r"schema 8 != 7",
            )

            non_integer_schema = deepcopy(manifest)
            non_integer_schema["schema_version"] = 7.0
            self.assertRegex(
                MODULE._file_hit_manifest_stale_reason(
                    non_integer_schema,
                    expected_clamav_policy_digest=policy.policy_digest,
                    expected_yara_policy_digest=yara_policy.policy_digest,
                    expected_correlation_policy_digest=(
                        referenced_file_policy.policy_digest
                    ),
                ),
                r"schema 7\.0 != 7",
            )

            original_csv_stat = av_csv.stat()
            av_csv.write_text(
                av_csv.read_text(encoding="utf-8").replace("Lockbit", "AgentXX"),
                encoding="utf-8",
            )
            os.utime(
                av_csv,
                ns=(original_csv_stat.st_atime_ns, original_csv_stat.st_mtime_ns),
            )
            changed_csv_stat = av_csv.stat()
            self.assertEqual(changed_csv_stat.st_size, original_csv_stat.st_size)
            self.assertEqual(
                changed_csv_stat.st_mtime_ns,
                original_csv_stat.st_mtime_ns,
            )
            changed_source_digest = MODULE._referenced_file_manifest_source_digest(
                str(root),
                av_csv_path=str(av_csv),
                referenced_file_policy=referenced_file_policy,
                yara_metadata_path=BASE_YARA_PATH,
            )
            self.assertNotEqual(changed_source_digest, manifest["source_digest"])
            self.assertEqual(
                MODULE._file_hit_manifest_stale_reason(
                    manifest,
                    expected_clamav_policy_digest=policy.policy_digest,
                    expected_yara_policy_digest=yara_policy.policy_digest,
                    expected_correlation_policy_digest=(
                        referenced_file_policy.policy_digest
                    ),
                    expected_source_digest=changed_source_digest,
                ),
                "manifest source digest differs",
            )
            changed_manifest = MODULE.build_global_referenced_file_hit_manifest(
                str(root),
                av_csv_path=str(av_csv),
                referenced_file_policy=referenced_file_policy,
                yara_metadata_path=BASE_YARA_PATH,
                clamav_classifier_policy=policy,
                yara_classifier_policy=yara_policy,
            )
            changed_identity = changed_manifest["file_identity_map"][
                "/var/www/html/csv-only.exe"
            ]
            self.assertEqual(changed_manifest["source_digest"], changed_source_digest)
            self.assertEqual(changed_identity["av_categories"], {"malware"})
            self.assertEqual(changed_identity["av_families"], {"AgentXX"})
            self.assertEqual(
                changed_identity["av_signatures"],
                {"Win.Trojan.AgentXX-1-0"},
            )

            stale_policy_manifest = deepcopy(manifest)
            stale_policy_manifest["clamav_policy_digest"] = "stale"
            frame = pd.DataFrame(
                [{"filename": "/var/www/html/csv-only.exe"}],
                index=pd.DatetimeIndex([pd.Timestamp("2024-06-16T20:00:00Z")]),
            )
            atomic = engine.apply_atomic(
                frame,
                apply_profiling=False,
                enforce_required_fields=False,
            )
            with self.assertRaisesRegex(
                ValueError,
                r"manifest is incompatible.*ClamAV classifier digest differs",
            ):
                engine.apply_contextual(
                    atomic,
                    apply_temporal=False,
                    file_hit_manifest=stale_policy_manifest,
                )

            stale_yara_policy_manifest = deepcopy(manifest)
            stale_yara_policy_manifest["yara_policy_digest"] = "stale"
            with self.assertRaisesRegex(
                ValueError,
                r"manifest is incompatible.*YARA classifier digest differs",
            ):
                engine.apply_contextual(
                    atomic,
                    apply_temporal=False,
                    file_hit_manifest=stale_yara_policy_manifest,
                )

            stale_correlation_manifest = deepcopy(manifest)
            stale_correlation_manifest["correlation_policy_digest"] = "stale"
            with self.assertRaisesRegex(
                ValueError,
                r"manifest is incompatible.*correlation policy digest differs",
            ):
                engine.apply_contextual(
                    atomic,
                    apply_temporal=False,
                    file_hit_manifest=stale_correlation_manifest,
                )

            materialised_root = pathlib.Path(tmpdir) / "materialised-dataset"
            materialised_part = materialised_root / "year=2024" / "month=6"
            materialised_part.mkdir(parents=True)
            pd.DataFrame(
                [{
                    "filename": "/var/www/html/materialised.php",
                    "av_hit": True,
                    "av_signature": "Php.Trojan.C99-1-0",
                }]
            ).to_parquet(materialised_part / "part-00000.parquet", index=False)
            materialised_manifest = MODULE.build_global_referenced_file_hit_manifest(
                str(materialised_root),
                referenced_file_policy=referenced_file_policy,
                yara_metadata_path=BASE_YARA_PATH,
                clamav_classifier_policy=policy,
                yara_classifier_policy=yara_policy,
            )
            materialised_identity = materialised_manifest["file_identity_map"][
                "/var/www/html/materialised.php"
            ]
            self.assertEqual(materialised_identity["hit_types"], {"av"})
            self.assertEqual(materialised_identity["av_categories"], {"webshell"})
            self.assertEqual(materialised_identity["av_families"], {"C99"})

    def test_partition_overlap_must_cover_the_longest_enabled_policy_lookback(self):
        engine = self._engine()
        with self.assertRaisesRegex(
            ValueError,
            r"Partition overlap.*ip_scope_continuity\.lookback",
        ):
            engine.process_parquet_dataset_partitioned(
                "unused-input",
                "unused-output",
                overlap="119m",
            )

        rules = deepcopy(BASE_RULES)
        self._detector_config(rules, "ip_scope_continuity")["lookback"][
            "duration"
        ] = "2h"
        self._download_config(rules)["lookback"] = "90m"
        self._webshell_config(rules)["lookback"] = "3h"
        with self.assertRaisesRegex(
            ValueError,
            r"Partition overlap.*webshell_activity\.lookback",
        ):
            self._engine(rules).process_parquet_dataset_partitioned(
                "unused-input",
                "unused-output",
                overlap="179m",
            )


if __name__ == "__main__":
    unittest.main()
