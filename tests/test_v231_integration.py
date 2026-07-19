"""
Integration tests for ChronoSift v2.31 dead-box ATT&CK additions.
"""
import importlib.util
import pathlib
import sys
import unittest

import pandas as pd


MODULE_PATH = pathlib.Path(__file__).resolve().parents[1] / "chronoSIFT_v2_31.py"
SPEC = importlib.util.spec_from_file_location("chronosift_v2_31_integration", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)
ChronoSiftEngine = MODULE.ChronoSiftEngine

RULES_PATH = "rules/rules_profiled_audited_nsrl_updates_baseline_yara_fixed_v10.yaml"
WEIGHTS_PATH = "rules/weights_profiled_audited_nsrl_updates_baseline_yara_fixed_v8.yaml"
YARA_METADATA_PATH = str(pathlib.Path(__file__).resolve().parents[1] / "rules" / "yara-rules-extended_20260215.yar")


def _build_timeline():
    base_ts = pd.Timestamp("2024-06-16T10:00:00Z")
    rows = [
        {
            "parser": "filestat",
            "filename": "/etc/systemd/system/evil.service",
            "display_name": "evil.service",
            "relative_path": "/etc/systemd/system/evil.service",
            "timestamp_desc": "Creation Time",
            "message": None,
        },
        {
            "parser": "filestat",
            "filename": "/root/.ssh/authorized_keys",
            "display_name": "authorized_keys",
            "relative_path": "/root/.ssh/authorized_keys",
            "timestamp_desc": "Content Modification Time",
            "message": None,
        },
        {
            "parser": "filestat",
            "filename": "/var/www/html/cmd.php",
            "display_name": "cmd.php",
            "relative_path": "/var/www/html/cmd.php",
            "timestamp_desc": "Creation Time",
            "message": None,
        },
        {
            "parser": "bash_history",
            "command_line": "vssadmin delete shadows /all /quiet",
            "message": "vssadmin delete shadows /all /quiet",
            "filename": None,
            "display_name": None,
            "file_path": None,
            "timestamp_desc": "Content Modification Time",
        },
        {
            "parser": "bash_history",
            "command_line": "wevtutil cl Security",
            "message": "wevtutil cl Security",
            "filename": None,
            "display_name": None,
            "file_path": None,
            "timestamp_desc": "Content Modification Time",
        },
        {
            "parser": "bash_history",
            "command_line": "rundll32.exe C:\\Users\\Public\\svchost.exe,Entry",
            "message": "rundll32.exe C:\\Users\\Public\\svchost.exe,Entry",
            "filename": "C:\\Users\\Public\\svchost.exe",
            "display_name": "svchost.exe",
            "file_path": "C:\\Users\\Public\\svchost.exe",
            "timestamp_desc": "Content Modification Time",
        },
        {
            "parser": "bash_history",
            "command_line": "reg save HKLM\\SAM C:\\Temp\\sam.save",
            "message": "reg save HKLM\\SAM C:\\Temp\\sam.save",
            "filename": None,
            "display_name": None,
            "file_path": None,
            "timestamp_desc": "Content Modification Time",
        },
        {
            "parser": "filestat",
            "filename": "/home/alice/.config/google-chrome/Default/Login Data",
            "display_name": "Login Data",
            "relative_path": "/home/alice/.config/google-chrome/Default/Login Data",
            "timestamp_desc": "Access Time",
            "message": None,
        },
        {
            "parser": "bash_history",
            "command_line": "cp /home/alice/.config/google-chrome/Default/Login\\ Data /tmp/login-data.db",
            "message": "cp /home/alice/.config/google-chrome/Default/Login\\ Data /tmp/login-data.db",
            "filename": None,
            "display_name": None,
            "file_path": None,
            "timestamp_desc": "Content Modification Time",
        },
        {
            "parser": "bash_history",
            "command_line": "dir C:\\Users && whoami && net view",
            "message": "dir C:\\Users && whoami && net view",
            "filename": None,
            "display_name": None,
            "file_path": None,
            "timestamp_desc": "Content Modification Time",
        },
        {
            "parser": "winevtx",
            "xml_string": "<Event><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4624</EventID><Channel>Security</Channel></System><EventData><Data Name='TargetUserName'>alice</Data><Data Name='LogonType'>3</Data><Data Name='IpAddress'>10.0.0.8</Data><Data Name='AuthenticationPackageName'>NTLM</Data></EventData></Event>",
            "message": "Successful network logon using \\\\server\\C$",
            "filename": None,
            "display_name": None,
            "file_path": None,
            "timestamp_desc": "Event Recorded",
        },
        {
            "parser": "winevtx",
            "xml_string": "<Event><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4624</EventID><Channel>Security</Channel></System><EventData><Data Name='TargetUserName'>svc-backup</Data><Data Name='LogonType'>3</Data><Data Name='IpAddress'>10.0.0.9</Data><Data Name='AuthenticationPackageName'>NTLM</Data><Data Name='WorkstationName'>WS01</Data></EventData></Event>",
            "message": "An account was successfully logged on.",
            "filename": None,
            "display_name": None,
            "file_path": None,
            "timestamp_desc": "Event Recorded",
        },
        {
            "parser": "winevtx",
            "xml_string": "<Event><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>5140</EventID><Channel>Security</Channel></System><EventData><Data Name='ShareName'>\\\\server\\ADMIN$</Data><Data Name='ShareLocalPath'>C:\\Windows</Data><Data Name='RelativeTargetName'>Temp\\tool.exe</Data><Data Name='SubjectUserName'>alice</Data></EventData></Event>",
            "message": "A network share object was accessed.",
            "filename": None,
            "display_name": None,
            "file_path": None,
            "timestamp_desc": "Event Recorded",
        },
        {
            "parser": "winevtx",
            "xml_string": "<Event><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4648</EventID><Channel>Security</Channel></System><EventData><Data Name='TargetUserName'>admin</Data><Data Name='ProcessName'>C:\\Windows\\System32\\runas.exe</Data><Data Name='IpAddress'>10.0.0.10</Data></EventData></Event>",
            "message": "A logon was attempted using explicit credentials.",
            "filename": None,
            "display_name": None,
            "file_path": None,
            "timestamp_desc": "Event Recorded",
        },
        {
            "parser": "apache_access",
            "url": "http://victim.example/cmd.php?cmd=id",
            "message": "GET /cmd.php?cmd=id HTTP/1.1",
            "filename": None,
            "display_name": None,
            "file_path": None,
            "timestamp_desc": "Entry Written",
        },
        {
            "parser": "apache_access",
            "url": "http://victim.example/upload.php",
            "message": "POST /upload.php multipart/form-data; filename=shell.php",
            "filename": None,
            "display_name": None,
            "file_path": None,
            "timestamp_desc": "Entry Written",
        },
        {
            "parser": "iis_w3c",
            "message": "date=2024-06-16 time=10:14:00 cs-method=PUT cs-uri-stem=/shell.aspx cs-uri-query=- sc-status=201 cs(User-Agent)=curl/8.0",
            "filename": None,
            "display_name": None,
            "file_path": None,
            "timestamp_desc": "Entry Written",
        },
        {
            "parser": "iis_w3c",
            "http_request": "PUT /shell.aspx HTTP/1.1",
            "message": "cs-method=PUT cs-uri-stem=/shell.aspx sc-status=201",
            "filename": None,
            "display_name": None,
            "file_path": None,
            "timestamp_desc": "Entry Written",
        },
        {
            "parser": "winevtx",
            "xml_string": "<Event><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4725</EventID><Channel>Security</Channel></System><EventData><Data Name='TargetUserName'>bob</Data></EventData></Event>",
            "message": "User account was disabled",
            "filename": None,
            "display_name": None,
            "file_path": None,
            "timestamp_desc": "Event Recorded",
        },
        {
            "parser": "winevtx",
            "xml_string": "<Event><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4729</EventID><Channel>Security</Channel></System><EventData><Data Name='TargetUserName'>alice</Data><Data Name='GroupName'>Domain Admins</Data><Data Name='MemberName'>alice</Data></EventData></Event>",
            "message": "A member was removed from a security-enabled global group.",
            "filename": None,
            "display_name": None,
            "file_path": None,
            "timestamp_desc": "Event Recorded",
        },
    ]
    ts = pd.to_datetime([base_ts + pd.Timedelta(minutes=i) for i in range(len(rows))], utc=True)
    df = pd.DataFrame(rows, index=ts)
    df["chronosift_row_id"] = list(range(len(rows)))
    return df


class ChronoSiftV231IntegrationTest(unittest.TestCase):
    def setUp(self):
        self.engine = ChronoSiftEngine.from_yaml(RULES_PATH, WEIGHTS_PATH, yara_metadata_path=YARA_METADATA_PATH)

    def test_direct_deadbox_signals_fire(self):
        df = _build_timeline()
        out = self.engine.apply_atomic(df.copy())
        out = self.engine.apply_contextual(out)

        self.assertGreater(float(out.iloc[0]["chronosift_signals"].get("systemd_service_persistence", 0)), 0)
        self.assertGreater(float(out.iloc[1]["chronosift_signals"].get("authorized_keys_root_persistence", 0)), 0)
        self.assertGreater(float(out.iloc[2]["chronosift_signals"].get("webshell_artifact", 0)), 0)
        self.assertGreater(float(out.iloc[3]["chronosift_signals"].get("inhibit_system_recovery", 0)), 0)
        self.assertGreater(float(out.iloc[4]["chronosift_signals"].get("indicator_removal_on_host", 0)), 0)
        self.assertGreater(float(out.iloc[5]["chronosift_signals"].get("masquerading", 0)), 0)
        self.assertGreater(float(out.iloc[6]["chronosift_signals"].get("credential_dumping", 0)), 0)
        self.assertGreater(float(out.iloc[7]["chronosift_signals"].get("password_store_access", 0)), 0)
        self.assertGreater(float(out.iloc[8]["chronosift_signals"].get("password_store_access", 0)), 0)
        self.assertGreater(float(out.iloc[9]["chronosift_signals"].get("file_and_directory_discovery", 0)), 0)
        self.assertGreater(float(out.iloc[9]["chronosift_signals"].get("remote_system_discovery", 0)), 0)
        self.assertGreater(float(out.iloc[9]["chronosift_signals"].get("system_owner_user_discovery", 0)), 0)
        self.assertGreater(float(out.iloc[10]["chronosift_signals"].get("smb_admin_share", 0)), 0)
        self.assertGreater(float(out.iloc[10]["chronosift_signals"].get("alternate_auth_material", 0)), 0)
        self.assertGreater(float(out.iloc[11]["chronosift_signals"].get("smb_admin_share", 0)), 0)
        self.assertGreater(float(out.iloc[11]["chronosift_signals"].get("external_remote_service", 0)), 0)
        self.assertGreater(float(out.iloc[12]["chronosift_signals"].get("smb_admin_share", 0)), 0)
        self.assertGreater(float(out.iloc[12]["chronosift_signals"].get("external_remote_service", 0)), 0)
        self.assertGreater(float(out.iloc[13]["chronosift_signals"].get("alternate_auth_material", 0)), 0)
        self.assertGreater(float(out.iloc[14]["chronosift_signals"].get("exploit_public_facing_app", 0)), 0)
        self.assertGreater(float(out.iloc[15]["chronosift_signals"].get("exploit_public_facing_app", 0)), 0)
        self.assertGreater(float(out.iloc[16]["chronosift_signals"].get("exploit_public_facing_app", 0)), 0)
        self.assertGreater(float(out.iloc[18]["chronosift_signals"].get("account_access_removal", 0)), 0)
        self.assertGreater(float(out.iloc[19]["chronosift_signals"].get("account_access_removal", 0)), 0)

    def test_false_positive_controls_hold(self):
        ts = pd.to_datetime([
            "2024-06-16T11:00:00Z",
            "2024-06-16T11:01:00Z",
            "2024-06-16T11:02:00Z",
            "2024-06-16T11:03:00Z",
        ], utc=True)
        df = pd.DataFrame([
            {
                "parser": "apache_access",
                "url": "http://victim.example/upload.php",
                "message": "POST /upload.php multipart/form-data; filename=photo.jpg",
                "timestamp_desc": "Entry Written",
            },
            {
                "parser": "iis_w3c",
                "message": "date=2024-06-16 time=11:01:00 cs-method=GET cs-uri-stem=/index.html cs-uri-query=- sc-status=200",
                "timestamp_desc": "Entry Written",
            },
            {
                "parser": "winevtx",
                "xml_string": "<Event><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4624</EventID><Channel>Security</Channel></System><EventData><Data Name='TargetUserName'>alice</Data><Data Name='LogonType'>3</Data><Data Name='IpAddress'>10.0.0.8</Data></EventData></Event>",
                "message": "An account was successfully logged on.",
                "timestamp_desc": "Event Recorded",
            },
            {
                "parser": "winevtx",
                "xml_string": "<Event><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4624</EventID><Channel>Security</Channel></System><EventData><Data Name='TargetUserName'>alice</Data><Data Name='LogonType'>3</Data><Data Name='IpAddress'>10.0.0.9</Data><Data Name='AuthenticationPackageName'>Kerberos</Data><Data Name='WorkstationName'>WS02</Data></EventData></Event>",
                "message": "An account was successfully logged on.",
                "timestamp_desc": "Event Recorded",
            },
        ], index=ts)
        df["chronosift_row_id"] = list(range(len(df)))

        out = self.engine.apply_contextual(self.engine.apply_atomic(df.copy()))

        self.assertEqual(float((out.iloc[0]["chronosift_signals"] or {}).get("exploit_public_facing_app", 0)), 0.0)
        self.assertEqual(float((out.iloc[1]["chronosift_signals"] or {}).get("exploit_public_facing_app", 0)), 0.0)
        self.assertEqual(float((out.iloc[2]["chronosift_signals"] or {}).get("alternate_auth_material", 0)), 0.0)
        self.assertEqual(float((out.iloc[3]["chronosift_signals"] or {}).get("smb_admin_share", 0)), 0.0)
        self.assertEqual(float((out.iloc[3]["chronosift_signals"] or {}).get("external_remote_service", 0)), 0.0)

    def test_query_style_web_uploads_trigger_exploit_detection(self):
        ts = pd.to_datetime([
            "2024-06-16T11:10:00Z",
            "2024-06-16T11:11:00Z",
        ], utc=True)
        df = pd.DataFrame([
            {
                "parser": "apache_access",
                "url": "http://victim.example/upload.php?name=shell.php",
                "message": '192.0.2.10 - - [16/Jun/2024:11:10:00 +0000] "POST /upload.php?name=shell.php HTTP/1.1" 201 128 "-" "curl/8.0"',
                "timestamp_desc": "Entry Written",
            },
            {
                "parser": "iis_w3c",
                "message": "date=2024-06-16 time=11:11:00 cs-method=POST cs-uri-stem=/connector.php cs-uri-query=filename=cmd.aspx sc-status=200 cs(User-Agent)=curl/8.0",
                "timestamp_desc": "Entry Written",
            },
        ], index=ts)
        df["chronosift_row_id"] = list(range(len(df)))

        out = self.engine.apply_contextual(self.engine.apply_atomic(df.copy()))

        self.assertGreater(float((out.iloc[0]["chronosift_signals"] or {}).get("exploit_public_facing_app", 0)), 0.0)
        self.assertGreater(float((out.iloc[1]["chronosift_signals"] or {}).get("exploit_public_facing_app", 0)), 0.0)

    def test_non_upload_query_params_do_not_trigger_web_upload_exploit(self):
        ts = pd.to_datetime([
            "2024-06-16T11:20:00Z",
        ], utc=True)
        df = pd.DataFrame([
            {
                "parser": "apache_access",
                "url": "http://victim.example/login.php?name=shell.php",
                "message": '192.0.2.10 - - [16/Jun/2024:11:20:00 +0000] "POST /login.php?name=shell.php HTTP/1.1" 200 256 "-" "Mozilla/5.0"',
                "timestamp_desc": "Entry Written",
            },
        ], index=ts)
        df["chronosift_row_id"] = list(range(len(df)))

        out = self.engine.apply_contextual(self.engine.apply_atomic(df.copy()))

        self.assertEqual(float((out.iloc[0]["chronosift_signals"] or {}).get("exploit_public_facing_app", 0)), 0.0)

    def test_windows_share_access_events_drive_remote_service_inference(self):
        ts = pd.to_datetime([
            "2024-06-16T11:30:00Z",
            "2024-06-16T11:31:00Z",
        ], utc=True)
        df = pd.DataFrame([
            {
                "parser": "winevtx",
                "xml_string": "<Event><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>5145</EventID><Channel>Security</Channel></System><EventData><Data Name='ShareName'>\\\\server\\IPC$</Data><Data Name='ShareLocalPath'></Data><Data Name='RelativeTargetName'>svcctl</Data><Data Name='SubjectUserName'>alice</Data></EventData></Event>",
                "message": "A network share object was checked to see whether client can be granted desired access.",
                "timestamp_desc": "Event Recorded",
            },
            {
                "parser": "winevtx",
                "xml_string": "<Event><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>5140</EventID><Channel>Security</Channel></System><EventData><Data Name='ShareName'>\\\\server\\Public</Data><Data Name='ShareLocalPath'>D:\\Public</Data><Data Name='RelativeTargetName'>Docs\\readme.txt</Data><Data Name='SubjectUserName'>alice</Data></EventData></Event>",
                "message": "A network share object was accessed.",
                "timestamp_desc": "Event Recorded",
            },
        ], index=ts)
        df["chronosift_row_id"] = list(range(len(df)))

        out = self.engine.apply_contextual(self.engine.apply_atomic(df.copy()))

        self.assertGreater(float((out.iloc[0]["chronosift_signals"] or {}).get("smb_admin_share", 0)), 0.0)
        self.assertGreater(float((out.iloc[0]["chronosift_signals"] or {}).get("external_remote_service", 0)), 0.0)
        self.assertEqual(float((out.iloc[1]["chronosift_signals"] or {}).get("smb_admin_share", 0)), 0.0)
        self.assertEqual(float((out.iloc[1]["chronosift_signals"] or {}).get("external_remote_service", 0)), 0.0)

    def test_privileged_group_removal_uses_higher_account_removal_confidence(self):
        ts = pd.to_datetime([
            "2024-06-16T11:40:00Z",
        ], utc=True)
        df = pd.DataFrame([
            {
                "parser": "winevtx",
                "xml_string": "<Event><System><Provider Name='Microsoft-Windows-Security-Auditing'/><EventID>4733</EventID><Channel>Security</Channel></System><EventData><Data Name='TargetUserName'>alice</Data><Data Name='GroupName'>Remote Desktop Users</Data><Data Name='MemberName'>alice</Data></EventData></Event>",
                "message": "A member was removed from a security-enabled local group.",
                "timestamp_desc": "Event Recorded",
            },
        ], index=ts)
        df["chronosift_row_id"] = list(range(len(df)))

        out = self.engine.apply_contextual(self.engine.apply_atomic(df.copy()))

        self.assertGreater(float((out.iloc[0]["chronosift_signals"] or {}).get("account_access_removal", 0)), 0.0)
        explain = (out.iloc[0]["chronosift_explain"] or []) if "chronosift_explain" in out.columns else []
        removal_entries = [
            item for item in explain
            if isinstance(item, dict) and item.get("rule_id") == "ACCOUNT_ACCESS_REMOVAL"
        ]
        self.assertTrue(removal_entries)
        self.assertEqual(removal_entries[0].get("confidence"), "medium")

    def test_routine_single_command_discovery_stays_quiet(self):
        ts = pd.to_datetime([
            "2024-06-16T12:00:00Z",
            "2024-06-16T12:01:00Z",
            "2024-06-16T12:02:00Z",
        ], utc=True)
        df = pd.DataFrame([
            {
                "parser": "bash_history",
                "command_line": "whoami",
                "message": "whoami",
                "timestamp_desc": "Content Modification Time",
            },
            {
                "parser": "bash_history",
                "command_line": "hostname",
                "message": "hostname",
                "timestamp_desc": "Content Modification Time",
            },
            {
                "parser": "bash_history",
                "command_line": "dir C:\\Users",
                "message": "dir C:\\Users",
                "timestamp_desc": "Content Modification Time",
            },
        ], index=ts)
        df["chronosift_row_id"] = list(range(len(df)))

        out = self.engine.apply_contextual(self.engine.apply_atomic(df.copy()))

        if "chronosift_signals" not in out.columns:
            return

        self.assertEqual(float((out.iloc[0]["chronosift_signals"] or {}).get("system_owner_user_discovery", 0)), 0.0)
        self.assertEqual(float((out.iloc[1]["chronosift_signals"] or {}).get("system_owner_user_discovery", 0)), 0.0)
        self.assertEqual(float((out.iloc[2]["chronosift_signals"] or {}).get("file_and_directory_discovery", 0)), 0.0)

    def test_benign_service_restart_and_single_scheduled_access_stay_quiet(self):
        ts = pd.to_datetime([
            "2024-06-16T13:00:00Z",
            "2024-06-16T13:01:00Z",
            "2024-06-16T13:02:00Z",
        ], utc=True)
        df = pd.DataFrame([
            {
                "parser": "bash_history",
                "command_line": "systemctl restart nginx",
                "message": "systemctl restart nginx",
                "timestamp_desc": "Content Modification Time",
            },
            {
                "parser": "filestat",
                "filename": "/home/alice/.config/google-chrome/Default/Login Data",
                "relative_path": "/home/alice/.config/google-chrome/Default/Login Data",
                "display_name": "Login Data",
                "timestamp_desc": "Access Time",
            },
            {
                "parser": "cron",
                "message": "CMD (/usr/local/bin/backup-login-data)",
                "timestamp_desc": "Entry Written",
            },
        ], index=ts)
        df["chronosift_row_id"] = list(range(len(df)))
        df.attrs["chronosift_sparse"] = {
            "signal_map": {
                1: {"password_store_access": 1.0},
                2: {"scheduled_exec": 1.0},
            },
            "explain_map": {},
        }

        out = self.engine.apply_contextual(df.copy())
        row0_signals = out.iloc[0]["chronosift_signals"] if "chronosift_signals" in out.columns else None
        row2_signals = out.iloc[2]["chronosift_signals"] if "chronosift_signals" in out.columns else None
        row0_signals = row0_signals if isinstance(row0_signals, dict) else {}
        row2_signals = row2_signals if isinstance(row2_signals, dict) else {}

        self.assertEqual(float(row0_signals.get("systemd_service_persistence", 0)), 0.0)
        self.assertEqual(float(row2_signals.get("automated_collection", 0)), 0.0)

    def test_query_only_windows_admin_command_is_dampened(self):
        ts = pd.to_datetime(["2024-06-16T14:00:00Z"], utc=True)
        df = pd.DataFrame([
            {
                "parser": "winevtx",
                "actor_cmd": "schtasks /query /tn Microsoft\\Windows\\Defrag\\ScheduledDefrag",
                "command_line": "schtasks /query /tn Microsoft\\Windows\\Defrag\\ScheduledDefrag",
                "message": "schtasks /query /tn Microsoft\\Windows\\Defrag\\ScheduledDefrag",
                "timestamp_desc": "Event Recorded",
            },
        ], index=ts)
        df["chronosift_row_id"] = [0]

        out = self.engine.apply_contextual(self.engine.apply_atomic(df.copy()))
        signals = out.iloc[0]["chronosift_signals"] if "chronosift_signals" in out.columns else {}
        signals = signals if isinstance(signals, dict) else {}

        self.assertEqual(float(signals.get("lolbin_windows", 0)), 0.0)
        self.assertEqual(float(signals.get("execution_lolbin", 0)), 0.0)
        self.assertEqual(float(signals.get("suspicious_execution", 0)), 0.0)

    def test_routine_backup_archive_is_dampened(self):
        ts = pd.to_datetime(["2024-06-16T15:00:00Z"], utc=True)
        df = pd.DataFrame([
            {
                "parser": "bash_history",
                "actor_cmd": "tar -czf /var/backups/system.tgz /etc",
                "command_line": "tar -czf /var/backups/system.tgz /etc",
                "message": "tar -czf /var/backups/system.tgz /etc",
                "timestamp_desc": "Content Modification Time",
            },
        ], index=ts)
        df["chronosift_row_id"] = [0]

        out = self.engine.apply_contextual(self.engine.apply_atomic(df.copy()))
        signals = out.iloc[0]["chronosift_signals"] if "chronosift_signals" in out.columns else {}
        signals = signals if isinstance(signals, dict) else {}

        self.assertEqual(float(signals.get("lolbin_linux", 0)), 0.0)
        self.assertEqual(float(signals.get("execution_lolbin", 0)), 0.0)
        self.assertEqual(float(signals.get("exec_archive_tool", 0)), 0.0)
        self.assertEqual(float(signals.get("suspicious_execution", 0)), 0.0)

    def test_read_only_service_and_defender_registry_observation_stay_quiet(self):
        ts = pd.to_datetime([
            "2024-06-16T16:00:00Z",
            "2024-06-16T16:01:00Z",
            "2024-06-16T16:02:00Z",
        ], utc=True)
        df = pd.DataFrame([
            {
                "parser": "winreg/windows_services",
                "filename": r"HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Services\\Spooler",
                "message": "Service registry key enumerated",
                "timestamp_desc": "Access Time",
            },
            {
                "parser": "winreg",
                "filename": r"HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows Defender",
                "message": "DisableRealtimeMonitoring=0",
                "timestamp_desc": "Access Time",
            },
            {
                "parser": "winevtx",
                "actor_cmd": "powershell Get-MpPreference",
                "command_line": "powershell Get-MpPreference",
                "message": "powershell Get-MpPreference",
                "timestamp_desc": "Event Recorded",
            },
        ], index=ts)
        df["chronosift_row_id"] = [0, 1, 2]

        out = self.engine.apply_contextual(self.engine.apply_atomic(df.copy()))
        row0_signals = out.iloc[0]["chronosift_signals"] if "chronosift_signals" in out.columns else {}
        row1_signals = out.iloc[1]["chronosift_signals"] if "chronosift_signals" in out.columns else {}
        row2_signals = out.iloc[2]["chronosift_signals"] if "chronosift_signals" in out.columns else {}
        row0_signals = row0_signals if isinstance(row0_signals, dict) else {}
        row1_signals = row1_signals if isinstance(row1_signals, dict) else {}
        row2_signals = row2_signals if isinstance(row2_signals, dict) else {}

        self.assertEqual(float(row0_signals.get("service_configuration_changed", 0)), 0.0)
        self.assertEqual(float(row1_signals.get("defender_disabled", 0)), 0.0)
        self.assertEqual(float(row2_signals.get("lolbin_windows", 0)), 0.0)
        self.assertEqual(float(row2_signals.get("execution_lolbin", 0)), 0.0)
        self.assertEqual(float(row2_signals.get("exec_shell_spawn", 0)), 0.0)
        self.assertEqual(float(row2_signals.get("suspicious_execution", 0)), 0.0)

    def test_service_status_command_is_not_shell_execution(self):
        ts = pd.to_datetime(["2024-06-16T17:00:00Z"], utc=True)
        df = pd.DataFrame([
            {
                "parser": "bash_history",
                "actor_cmd": "service ssh status",
                "command_line": "service ssh status",
                "message": "service ssh status",
                "timestamp_desc": "Content Modification Time",
            },
        ], index=ts)
        df["chronosift_row_id"] = [0]

        out = self.engine.apply_contextual(self.engine.apply_atomic(df.copy()))
        signals = out.iloc[0]["chronosift_signals"] if "chronosift_signals" in out.columns else {}
        signals = signals if isinstance(signals, dict) else {}

        self.assertEqual(float(signals.get("interpreter_exec_linux", 0)), 0.0)
        self.assertEqual(float(signals.get("execution_interpreter", 0)), 0.0)
        self.assertEqual(float(signals.get("suspicious_execution", 0)), 0.0)

    def test_admin_status_queries_are_dampened(self):
        rows = [
            {
                "parser": "winevtx",
                "actor_cmd": "powershell Get-ScheduledTask",
                "command_line": "powershell Get-ScheduledTask",
                "message": "powershell Get-ScheduledTask",
                "timestamp_desc": "Event Recorded",
            },
            {
                "parser": "winevtx",
                "actor_cmd": "powershell Get-NetTCPConnection",
                "command_line": "powershell Get-NetTCPConnection",
                "message": "powershell Get-NetTCPConnection",
                "timestamp_desc": "Event Recorded",
            },
            {
                "parser": "winevtx",
                "actor_cmd": "cmd.exe /c sc qc spooler",
                "command_line": "cmd.exe /c sc qc spooler",
                "message": "cmd.exe /c sc qc spooler",
                "timestamp_desc": "Event Recorded",
            },
            {
                "parser": "bash_history",
                "actor_cmd": "ps aux | grep sshd",
                "command_line": "ps aux | grep sshd",
                "message": "ps aux | grep sshd",
                "timestamp_desc": "Content Modification Time",
            },
            {
                "parser": "winevtx",
                "actor_cmd": "powershell Get-Process lsass",
                "command_line": "powershell Get-Process lsass",
                "message": "powershell Get-Process lsass",
                "timestamp_desc": "Event Recorded",
            },
            {
                "parser": "winevtx",
                "actor_cmd": "powershell Get-CimInstance Win32_Service",
                "command_line": "powershell Get-CimInstance Win32_Service",
                "message": "powershell Get-CimInstance Win32_Service",
                "timestamp_desc": "Event Recorded",
            },
            {
                "parser": "winevtx",
                "actor_cmd": "cmd.exe /c tasklist /svc",
                "command_line": "cmd.exe /c tasklist /svc",
                "message": "cmd.exe /c tasklist /svc",
                "timestamp_desc": "Event Recorded",
            },
            {
                "parser": "winevtx",
                "actor_cmd": "cmd.exe /c netstat -ano",
                "command_line": "cmd.exe /c netstat -ano",
                "message": "cmd.exe /c netstat -ano",
                "timestamp_desc": "Event Recorded",
            },
            {
                "parser": "winevtx",
                "actor_cmd": "cmd.exe /c ipconfig /all",
                "command_line": "cmd.exe /c ipconfig /all",
                "message": "cmd.exe /c ipconfig /all",
                "timestamp_desc": "Event Recorded",
            },
            {
                "parser": "winevtx",
                "actor_cmd": "cmd.exe /c route print",
                "command_line": "cmd.exe /c route print",
                "message": "cmd.exe /c route print",
                "timestamp_desc": "Event Recorded",
            },
            {
                "parser": "winevtx",
                "actor_cmd": "cmd.exe /c arp -a",
                "command_line": "cmd.exe /c arp -a",
                "message": "cmd.exe /c arp -a",
                "timestamp_desc": "Event Recorded",
            },
            {
                "parser": "winevtx",
                "actor_cmd": "cmd.exe /c qwinsta",
                "command_line": "cmd.exe /c qwinsta",
                "message": "cmd.exe /c qwinsta",
                "timestamp_desc": "Event Recorded",
            },
            {
                "parser": "winevtx",
                "actor_cmd": "cmd.exe /c quser",
                "command_line": "cmd.exe /c quser",
                "message": "cmd.exe /c quser",
                "timestamp_desc": "Event Recorded",
            },
            {
                "parser": "winevtx",
                "actor_cmd": "cmd.exe /c net user alice",
                "command_line": "cmd.exe /c net user alice",
                "message": "cmd.exe /c net user alice",
                "timestamp_desc": "Event Recorded",
            },
            {
                "parser": "winevtx",
                "actor_cmd": "cmd.exe /c net localgroup administrators",
                "command_line": "cmd.exe /c net localgroup administrators",
                "message": "cmd.exe /c net localgroup administrators",
                "timestamp_desc": "Event Recorded",
            },
        ]
        ts = pd.date_range("2024-06-16T18:00:00Z", periods=len(rows), freq="min")
        df = pd.DataFrame(rows, index=ts)
        df["chronosift_row_id"] = list(range(len(df)))

        out = self.engine.apply_contextual(self.engine.apply_atomic(df.copy()))
        for row_i in range(len(out)):
            signals = out.iloc[row_i]["chronosift_signals"] if "chronosift_signals" in out.columns else {}
            signals = signals if isinstance(signals, dict) else {}
            self.assertEqual(float(signals.get("lolbin_windows", 0)), 0.0)
            self.assertEqual(float(signals.get("execution_lolbin", 0)), 0.0)
            self.assertEqual(float(signals.get("exec_shell_spawn", 0)), 0.0)
            self.assertEqual(float(signals.get("suspicious_execution", 0)), 0.0)
        row1_signals = out.iloc[1]["chronosift_signals"] if "chronosift_signals" in out.columns else {}
        row1_signals = row1_signals if isinstance(row1_signals, dict) else {}
        row7_signals = out.iloc[7]["chronosift_signals"] if "chronosift_signals" in out.columns else {}
        row7_signals = row7_signals if isinstance(row7_signals, dict) else {}
        row3_signals = out.iloc[3]["chronosift_signals"] if "chronosift_signals" in out.columns else {}
        row3_signals = row3_signals if isinstance(row3_signals, dict) else {}
        row8_signals = out.iloc[8]["chronosift_signals"] if "chronosift_signals" in out.columns else {}
        row8_signals = row8_signals if isinstance(row8_signals, dict) else {}
        row9_signals = out.iloc[9]["chronosift_signals"] if "chronosift_signals" in out.columns else {}
        row9_signals = row9_signals if isinstance(row9_signals, dict) else {}
        row10_signals = out.iloc[10]["chronosift_signals"] if "chronosift_signals" in out.columns else {}
        row10_signals = row10_signals if isinstance(row10_signals, dict) else {}
        row11_signals = out.iloc[11]["chronosift_signals"] if "chronosift_signals" in out.columns else {}
        row11_signals = row11_signals if isinstance(row11_signals, dict) else {}
        row12_signals = out.iloc[12]["chronosift_signals"] if "chronosift_signals" in out.columns else {}
        row12_signals = row12_signals if isinstance(row12_signals, dict) else {}
        row13_signals = out.iloc[13]["chronosift_signals"] if "chronosift_signals" in out.columns else {}
        row13_signals = row13_signals if isinstance(row13_signals, dict) else {}
        row14_signals = out.iloc[14]["chronosift_signals"] if "chronosift_signals" in out.columns else {}
        row14_signals = row14_signals if isinstance(row14_signals, dict) else {}
        self.assertEqual(float(row1_signals.get("data_transfer_tool_exec", 0)), 0.0)
        self.assertEqual(float(row1_signals.get("transfer_execution", 0)), 0.0)
        self.assertEqual(float(row1_signals.get("application_layer_protocol", 0)), 0.0)
        self.assertEqual(float(row3_signals.get("file_and_directory_discovery", 0)), 0.0)
        self.assertEqual(float(row7_signals.get("application_layer_protocol", 0)), 0.0)
        self.assertEqual(float(row8_signals.get("system_owner_user_discovery", 0)), 0.0)
        self.assertEqual(float(row9_signals.get("remote_system_discovery", 0)), 0.0)
        self.assertEqual(float(row10_signals.get("remote_system_discovery", 0)), 0.0)
        self.assertEqual(float(row11_signals.get("remote_system_discovery", 0)), 0.0)
        self.assertEqual(float(row12_signals.get("remote_system_discovery", 0)), 0.0)
        self.assertEqual(float(row13_signals.get("system_owner_user_discovery", 0)), 0.0)
        self.assertEqual(float(row14_signals.get("system_owner_user_discovery", 0)), 0.0)

    def test_additional_read_only_windows_status_commands_are_dampened(self):
        rows = [
            {
                "parser": "winevtx",
                "actor_cmd": "cmd.exe /c net accounts",
                "command_line": "cmd.exe /c net accounts",
                "message": "cmd.exe /c net accounts",
                "timestamp_desc": "Event Recorded",
            },
            {
                "parser": "winevtx",
                "actor_cmd": "cmd.exe /c gpresult /r",
                "command_line": "cmd.exe /c gpresult /r",
                "message": "cmd.exe /c gpresult /r",
                "timestamp_desc": "Event Recorded",
            },
            {
                "parser": "winevtx",
                "actor_cmd": "cmd.exe /c whoami /groups",
                "command_line": "cmd.exe /c whoami /groups",
                "message": "cmd.exe /c whoami /groups",
                "timestamp_desc": "Event Recorded",
            },
            {
                "parser": "winevtx",
                "actor_cmd": "cmd.exe /c whoami /priv",
                "command_line": "cmd.exe /c whoami /priv",
                "message": "cmd.exe /c whoami /priv",
                "timestamp_desc": "Event Recorded",
            },
            {
                "parser": "winevtx",
                "actor_cmd": "cmd.exe /c klist",
                "command_line": "cmd.exe /c klist",
                "message": "cmd.exe /c klist",
                "timestamp_desc": "Event Recorded",
            },
            {
                "parser": "winevtx",
                "actor_cmd": "powershell Get-ComputerInfo",
                "command_line": "powershell Get-ComputerInfo",
                "message": "powershell Get-ComputerInfo",
                "timestamp_desc": "Event Recorded",
            },
            {
                "parser": "winevtx",
                "actor_cmd": "powershell Get-LocalUser",
                "command_line": "powershell Get-LocalUser",
                "message": "powershell Get-LocalUser",
                "timestamp_desc": "Event Recorded",
            },
            {
                "parser": "winevtx",
                "actor_cmd": "powershell Get-LocalGroup",
                "command_line": "powershell Get-LocalGroup",
                "message": "powershell Get-LocalGroup",
                "timestamp_desc": "Event Recorded",
            },
            {
                "parser": "winevtx",
                "actor_cmd": "powershell Get-HotFix",
                "command_line": "powershell Get-HotFix",
                "message": "powershell Get-HotFix",
                "timestamp_desc": "Event Recorded",
            },
            {
                "parser": "winevtx",
                "actor_cmd": "powershell Get-NetIPAddress",
                "command_line": "powershell Get-NetIPAddress",
                "message": "powershell Get-NetIPAddress",
                "timestamp_desc": "Event Recorded",
            },
            {
                "parser": "winevtx",
                "actor_cmd": "cmd.exe /c netsh interface ip show config",
                "command_line": "cmd.exe /c netsh interface ip show config",
                "message": "cmd.exe /c netsh interface ip show config",
                "timestamp_desc": "Event Recorded",
            },
        ]
        ts = pd.date_range("2024-06-16T19:00:00Z", periods=len(rows), freq="min")
        df = pd.DataFrame(rows, index=ts)
        df["chronosift_row_id"] = list(range(len(df)))

        out = self.engine.apply_contextual(self.engine.apply_atomic(df.copy()))
        for row_i in range(len(out)):
            signals = out.iloc[row_i]["chronosift_signals"] if "chronosift_signals" in out.columns else {}
            signals = signals if isinstance(signals, dict) else {}
            self.assertEqual(float(signals.get("lolbin_windows", 0)), 0.0)
            self.assertEqual(float(signals.get("execution_lolbin", 0)), 0.0)
            self.assertEqual(float(signals.get("exec_shell_spawn", 0)), 0.0)
            self.assertEqual(float(signals.get("suspicious_execution", 0)), 0.0)

    def test_linux_status_commands_are_dampened(self):
        rows = [
            {
                "parser": "bash_history",
                "actor_cmd": "uname -a",
                "command_line": "uname -a",
                "message": "uname -a",
                "timestamp_desc": "Content Modification Time",
            },
            {
                "parser": "bash_history",
                "actor_cmd": "hostnamectl status",
                "command_line": "hostnamectl status",
                "message": "hostnamectl status",
                "timestamp_desc": "Content Modification Time",
            },
            {
                "parser": "bash_history",
                "actor_cmd": "cat /etc/os-release",
                "command_line": "cat /etc/os-release",
                "message": "cat /etc/os-release",
                "timestamp_desc": "Content Modification Time",
            },
        ]
        ts = pd.date_range("2024-06-16T20:00:00Z", periods=len(rows), freq="min")
        df = pd.DataFrame(rows, index=ts)
        df["chronosift_row_id"] = list(range(len(df)))

        out = self.engine.apply_contextual(self.engine.apply_atomic(df.copy()))
        for row_i in range(len(out)):
            signals = out.iloc[row_i]["chronosift_signals"] if "chronosift_signals" in out.columns else {}
            signals = signals if isinstance(signals, dict) else {}
            self.assertEqual(float(signals.get("system_owner_user_discovery", 0)), 0.0)
            self.assertEqual(float(signals.get("suspicious_execution", 0)), 0.0)

    def test_read_only_network_status_commands_are_dampened(self):
        rows = [
            {
                "parser": "winevtx",
                "actor_cmd": "powershell Get-NetRoute",
                "command_line": "powershell Get-NetRoute",
                "message": "powershell Get-NetRoute",
                "timestamp_desc": "Event Recorded",
            },
            {
                "parser": "winevtx",
                "actor_cmd": "powershell Get-DnsClientCache",
                "command_line": "powershell Get-DnsClientCache",
                "message": "powershell Get-DnsClientCache",
                "timestamp_desc": "Event Recorded",
            },
            {
                "parser": "winevtx",
                "actor_cmd": "powershell Get-NetNeighbor",
                "command_line": "powershell Get-NetNeighbor",
                "message": "powershell Get-NetNeighbor",
                "timestamp_desc": "Event Recorded",
            },
            {
                "parser": "bash_history",
                "actor_cmd": "ifconfig -a",
                "command_line": "ifconfig -a",
                "message": "ifconfig -a",
                "timestamp_desc": "Content Modification Time",
            },
        ]
        ts = pd.date_range("2024-06-16T21:00:00Z", periods=len(rows), freq="min")
        df = pd.DataFrame(rows, index=ts)
        df["chronosift_row_id"] = list(range(len(df)))

        out = self.engine.apply_contextual(self.engine.apply_atomic(df.copy()))
        for row_i in range(len(out)):
            signals = out.iloc[row_i]["chronosift_signals"] if "chronosift_signals" in out.columns else {}
            signals = signals if isinstance(signals, dict) else {}
            self.assertEqual(float(signals.get("lolbin_windows", 0)), 0.0)
            self.assertEqual(float(signals.get("execution_lolbin", 0)), 0.0)
            self.assertEqual(float(signals.get("exec_shell_spawn", 0)), 0.0)
            self.assertEqual(float(signals.get("suspicious_execution", 0)), 0.0)
            self.assertEqual(float(signals.get("system_owner_user_discovery", 0)), 0.0)

    def test_discovery_commands_are_reclassified_from_generic_exec(self):
        rows = [
            {
                "parser": "winevtx",
                "actor_cmd": "cmd.exe /c net view",
                "command_line": "cmd.exe /c net view",
                "message": "cmd.exe /c net view",
                "timestamp_desc": "Event Recorded",
            },
            {
                "parser": "winevtx",
                "actor_cmd": "cmd.exe /c nslookup dc01",
                "command_line": "cmd.exe /c nslookup dc01",
                "message": "cmd.exe /c nslookup dc01",
                "timestamp_desc": "Event Recorded",
            },
            {
                "parser": "winevtx",
                "actor_cmd": "cmd.exe /c ping -n 1 dc01",
                "command_line": "cmd.exe /c ping -n 1 dc01",
                "message": "cmd.exe /c ping -n 1 dc01",
                "timestamp_desc": "Event Recorded",
            },
            {
                "parser": "winevtx",
                "actor_cmd": "cmd.exe /c nltest /dclist:contoso",
                "command_line": "cmd.exe /c nltest /dclist:contoso",
                "message": "cmd.exe /c nltest /dclist:contoso",
                "timestamp_desc": "Event Recorded",
            },
            {
                "parser": "winevtx",
                "actor_cmd": "powershell Resolve-DnsName dc01",
                "command_line": "powershell Resolve-DnsName dc01",
                "message": "powershell Resolve-DnsName dc01",
                "timestamp_desc": "Event Recorded",
            },
        ]
        ts = pd.date_range("2024-06-16T22:00:00Z", periods=len(rows), freq="min")
        df = pd.DataFrame(rows, index=ts)
        df["chronosift_row_id"] = list(range(len(df)))

        out = self.engine.apply_contextual(self.engine.apply_atomic(df.copy()))
        for row_i in range(len(out)):
            signals = out.iloc[row_i]["chronosift_signals"] if "chronosift_signals" in out.columns else {}
            signals = signals if isinstance(signals, dict) else {}
            self.assertGreater(float(signals.get("remote_system_discovery", 0)), 0.0)
            self.assertEqual(float(signals.get("lolbin_windows", 0)), 0.0)
            self.assertEqual(float(signals.get("execution_lolbin", 0)), 0.0)
            self.assertEqual(float(signals.get("exec_shell_spawn", 0)), 0.0)
            self.assertEqual(float(signals.get("suspicious_execution", 0)), 0.0)

    def test_discovery_commands_fire_from_command_line_without_actor_cmd(self):
        rows = [
            {
                "parser": "winevtx",
                "actor_cmd": "",
                "command_line": "cmd.exe /c dir c:\\ && net view && whoami",
                "message": "",
                "timestamp_desc": "Event Recorded",
            },
        ]
        ts = pd.date_range("2024-06-16T22:30:00Z", periods=len(rows), freq="min")
        df = pd.DataFrame(rows, index=ts)
        df["chronosift_row_id"] = list(range(len(df)))

        out = self.engine.apply_contextual(self.engine.apply_atomic(df.copy()))
        signals = out.iloc[0]["chronosift_signals"] if "chronosift_signals" in out.columns else {}
        signals = signals if isinstance(signals, dict) else {}
        explain = out.iloc[0]["chronosift_explain"] if "chronosift_explain" in out.columns else []
        explain = explain if isinstance(explain, list) else []

        self.assertGreater(float(signals.get("file_and_directory_discovery", 0)), 0.0)
        self.assertGreater(float(signals.get("remote_system_discovery", 0)), 0.0)
        self.assertGreater(float(signals.get("system_owner_user_discovery", 0)), 0.0)

        expected_rule_ids = {
            "FILE_AND_DIRECTORY_DISCOVERY",
            "REMOTE_SYSTEM_DISCOVERY",
            "SYSTEM_OWNER_USER_DISCOVERY",
        }
        rule_ids = {entry.get("rule_id") for entry in explain if isinstance(entry, dict)}
        self.assertIn("FILE_AND_DIRECTORY_DISCOVERY", rule_ids)
        self.assertIn("REMOTE_SYSTEM_DISCOVERY", rule_ids)
        self.assertIn("SYSTEM_OWNER_USER_DISCOVERY", rule_ids)
        for entry in explain:
            if isinstance(entry, dict) and entry.get("rule_id") in expected_rule_ids:
                evidence = entry.get("evidence") or {}
                self.assertEqual(evidence.get("command"), "cmd.exe /c dir c:\\ && net view && whoami")


class ChronoSiftV231ConfigAlignmentTest(unittest.TestCase):
    """Verify signal/weight configuration is internally consistent."""

    def test_no_unused_weights_warning(self):
        """All weighted signals must be registered as emittable — no 'weights defined but not currently emitted' warning."""
        import io, contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            ChronoSiftEngine.from_yaml(RULES_PATH, WEIGHTS_PATH, yara_metadata_path=YARA_METADATA_PATH)
        output = buf.getvalue()
        self.assertNotIn(
            "weights defined but not currently emitted",
            output,
            f"Config warning emitted — unregistered signals: {output.strip()}",
        )


class ChronoSiftV231ATTCKExpansionTest(unittest.TestCase):
    """Tests for T1547.004, T1546.015, T1489, T1070.006 signals."""

    def setUp(self):
        self.engine = ChronoSiftEngine.from_yaml(RULES_PATH, WEIGHTS_PATH, yara_metadata_path=YARA_METADATA_PATH)

    # ── T1547.004 Winlogon Helper DLL ──────────────────────────────

    def test_winlogon_shell_registry_modification_fires(self):
        ts = pd.to_datetime(["2024-06-16T20:00:00Z"], utc=True)
        df = pd.DataFrame([
            {
                "parser": "winreg",
                "filename": r"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon",
                "message": "Shell value set to explorer.exe,evil.exe",
                "timestamp_desc": "Content Modification Time",
            },
        ], index=ts)
        df["chronosift_row_id"] = [0]

        out = self.engine.apply_contextual(self.engine.apply_atomic(df.copy()))
        signals = out.iloc[0]["chronosift_signals"] if "chronosift_signals" in out.columns else {}
        signals = signals if isinstance(signals, dict) else {}

        self.assertGreater(float(signals.get("winlogon_helper_persistence", 0)), 0.0)

    def test_winlogon_userinit_modification_fires(self):
        ts = pd.to_datetime(["2024-06-16T20:01:00Z"], utc=True)
        df = pd.DataFrame([
            {
                "parser": "winreg",
                "filename": r"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit",
                "message": "Registry value modified",
                "timestamp_desc": "Content Modification Time",
            },
        ], index=ts)
        df["chronosift_row_id"] = [0]

        out = self.engine.apply_contextual(self.engine.apply_atomic(df.copy()))
        signals = out.iloc[0]["chronosift_signals"] if "chronosift_signals" in out.columns else {}
        signals = signals if isinstance(signals, dict) else {}

        self.assertGreater(float(signals.get("winlogon_helper_persistence", 0)), 0.0)

    def test_winlogon_read_access_does_not_fire(self):
        ts = pd.to_datetime(["2024-06-16T20:02:00Z"], utc=True)
        df = pd.DataFrame([
            {
                "parser": "winreg",
                "filename": r"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon",
                "message": "Shell value is explorer.exe",
                "timestamp_desc": "Access Time",
            },
        ], index=ts)
        df["chronosift_row_id"] = [0]

        out = self.engine.apply_contextual(self.engine.apply_atomic(df.copy()))
        signals = out.iloc[0]["chronosift_signals"] if "chronosift_signals" in out.columns else {}
        signals = signals if isinstance(signals, dict) else {}

        self.assertEqual(float(signals.get("winlogon_helper_persistence", 0)), 0.0)

    # ── T1546.015 COM Hijacking ────────────────────────────────────

    def test_com_hijack_inprocserver32_modification_fires(self):
        ts = pd.to_datetime(["2024-06-16T20:10:00Z"], utc=True)
        df = pd.DataFrame([
            {
                "parser": "winreg",
                "filename": r"HKEY_CURRENT_USER\Software\Classes\CLSID\{00000001-0000-0000-0000-000000000000}\InprocServer32",
                "message": "Registry value modified",
                "timestamp_desc": "Content Modification Time",
            },
        ], index=ts)
        df["chronosift_row_id"] = [0]

        out = self.engine.apply_contextual(self.engine.apply_atomic(df.copy()))
        signals = out.iloc[0]["chronosift_signals"] if "chronosift_signals" in out.columns else {}
        signals = signals if isinstance(signals, dict) else {}

        self.assertGreater(float(signals.get("com_hijack_persistence", 0)), 0.0)

    def test_com_hijack_treatas_modification_fires(self):
        ts = pd.to_datetime(["2024-06-16T20:11:00Z"], utc=True)
        df = pd.DataFrame([
            {
                "parser": "winreg",
                "filename": r"HKEY_LOCAL_MACHINE\Software\Classes\CLSID\{DEADBEEF-1234-5678-ABCD-EFAABBCCDDEE}\TreatAs",
                "message": "Registry value created",
                "timestamp_desc": "Creation Time",
            },
        ], index=ts)
        df["chronosift_row_id"] = [0]

        out = self.engine.apply_contextual(self.engine.apply_atomic(df.copy()))
        signals = out.iloc[0]["chronosift_signals"] if "chronosift_signals" in out.columns else {}
        signals = signals if isinstance(signals, dict) else {}

        self.assertGreater(float(signals.get("com_hijack_persistence", 0)), 0.0)

    def test_com_clsid_read_does_not_fire(self):
        ts = pd.to_datetime(["2024-06-16T20:12:00Z"], utc=True)
        df = pd.DataFrame([
            {
                "parser": "winreg",
                "filename": r"HKEY_CURRENT_USER\Software\Classes\CLSID\{00000001-0000-0000-0000-000000000000}\InprocServer32",
                "message": "Registry key opened",
                "timestamp_desc": "Access Time",
            },
        ], index=ts)
        df["chronosift_row_id"] = [0]

        out = self.engine.apply_contextual(self.engine.apply_atomic(df.copy()))
        signals = out.iloc[0]["chronosift_signals"] if "chronosift_signals" in out.columns else {}
        signals = signals if isinstance(signals, dict) else {}

        self.assertEqual(float(signals.get("com_hijack_persistence", 0)), 0.0)

    def test_com_clsid_without_inproc_or_treatas_does_not_fire(self):
        ts = pd.to_datetime(["2024-06-16T20:13:00Z"], utc=True)
        df = pd.DataFrame([
            {
                "parser": "winreg",
                "filename": r"HKEY_CURRENT_USER\Software\Classes\CLSID\{00000001-0000-0000-0000-000000000000}\ProgID",
                "message": "Registry value modified",
                "timestamp_desc": "Content Modification Time",
            },
        ], index=ts)
        df["chronosift_row_id"] = [0]

        out = self.engine.apply_contextual(self.engine.apply_atomic(df.copy()))
        signals = out.iloc[0]["chronosift_signals"] if "chronosift_signals" in out.columns else {}
        signals = signals if isinstance(signals, dict) else {}

        self.assertEqual(float(signals.get("com_hijack_persistence", 0)), 0.0)

    # ── T1489 Service Stop ─────────────────────────────────────────

    def test_service_stop_command_fires(self):
        ts = pd.to_datetime(["2024-06-16T20:20:00Z"], utc=True)
        df = pd.DataFrame([
            {
                "parser": "bash_history",
                "command_line": "sc stop spooler",
                "message": "sc stop spooler",
                "timestamp_desc": "Content Modification Time",
            },
        ], index=ts)
        df["chronosift_row_id"] = [0]

        out = self.engine.apply_contextual(self.engine.apply_atomic(df.copy()))
        signals = out.iloc[0]["chronosift_signals"] if "chronosift_signals" in out.columns else {}
        signals = signals if isinstance(signals, dict) else {}

        self.assertGreater(float(signals.get("service_stop", 0)), 0.0)

    def test_net_stop_command_fires(self):
        ts = pd.to_datetime(["2024-06-16T20:21:00Z"], utc=True)
        df = pd.DataFrame([
            {
                "parser": "bash_history",
                "command_line": "net stop WinDefend",
                "message": "net stop WinDefend",
                "timestamp_desc": "Content Modification Time",
            },
        ], index=ts)
        df["chronosift_row_id"] = [0]

        out = self.engine.apply_contextual(self.engine.apply_atomic(df.copy()))
        signals = out.iloc[0]["chronosift_signals"] if "chronosift_signals" in out.columns else {}
        signals = signals if isinstance(signals, dict) else {}

        self.assertGreater(float(signals.get("service_stop", 0)), 0.0)

    def test_systemctl_stop_fires(self):
        ts = pd.to_datetime(["2024-06-16T20:22:00Z"], utc=True)
        df = pd.DataFrame([
            {
                "parser": "bash_history",
                "command_line": "systemctl stop firewalld",
                "message": "systemctl stop firewalld",
                "timestamp_desc": "Content Modification Time",
            },
        ], index=ts)
        df["chronosift_row_id"] = [0]

        out = self.engine.apply_contextual(self.engine.apply_atomic(df.copy()))
        signals = out.iloc[0]["chronosift_signals"] if "chronosift_signals" in out.columns else {}
        signals = signals if isinstance(signals, dict) else {}

        self.assertGreater(float(signals.get("service_stop", 0)), 0.0)

    def test_stop_service_powershell_fires(self):
        ts = pd.to_datetime(["2024-06-16T20:23:00Z"], utc=True)
        df = pd.DataFrame([
            {
                "parser": "winevtx",
                "actor_cmd": "powershell Stop-Service -Name Spooler -Force",
                "command_line": "powershell Stop-Service -Name Spooler -Force",
                "message": "powershell Stop-Service -Name Spooler -Force",
                "timestamp_desc": "Event Recorded",
            },
        ], index=ts)
        df["chronosift_row_id"] = [0]

        out = self.engine.apply_contextual(self.engine.apply_atomic(df.copy()))
        signals = out.iloc[0]["chronosift_signals"] if "chronosift_signals" in out.columns else {}
        signals = signals if isinstance(signals, dict) else {}

        self.assertGreater(float(signals.get("service_stop", 0)), 0.0)

    def test_evtx_7036_stopped_state_fires(self):
        ts = pd.to_datetime(["2024-06-16T20:24:00Z"], utc=True)
        df = pd.DataFrame([
            {
                "parser": "winevtx",
                "event_identifier": "7036",
                "message": "The Print Spooler service entered the stopped state.",
                "timestamp_desc": "Event Recorded",
            },
        ], index=ts)
        df["chronosift_row_id"] = [0]

        out = self.engine.apply_contextual(self.engine.apply_atomic(df.copy()))
        signals = out.iloc[0]["chronosift_signals"] if "chronosift_signals" in out.columns else {}
        signals = signals if isinstance(signals, dict) else {}

        self.assertGreater(float(signals.get("service_stop", 0)), 0.0)

    def test_evtx_7036_service_stopped_not_command_detection(self):
        """EVTX 7036 'service stopped' should use event-based detection (low confidence),
        not command-token detection. The token 'service stop' must not match 'service stopped'."""
        ts = pd.to_datetime(["2024-06-16T20:24:30Z"], utc=True)
        df = pd.DataFrame([
            {
                "parser": "winevtx",
                "event_identifier": "7036",
                "message": "The Windows Defender service stopped",
                "timestamp_desc": "Event Recorded",
            },
        ], index=ts)
        df["chronosift_row_id"] = [0]

        out = self.engine.apply_contextual(self.engine.apply_atomic(df.copy()))
        signals = out.iloc[0]["chronosift_signals"] if "chronosift_signals" in out.columns else {}
        signals = signals if isinstance(signals, dict) else {}

        self.assertGreater(float(signals.get("service_stop", 0)), 0.0)
        explain = out.iloc[0]["chronosift_explain"] if "chronosift_explain" in out.columns else []
        explain = explain if isinstance(explain, list) else []
        # Find explain entries for service_stop — signals may be a list of
        # dicts (materialised) or strings (raw), so check both forms
        ss_entries = []
        for e in explain:
            if not isinstance(e, dict):
                continue
            sigs = e.get("signals") or []
            sig_names = set()
            for s in sigs:
                if isinstance(s, str):
                    sig_names.add(s)
                elif isinstance(s, dict):
                    sig_names.add(s.get("name", ""))
            if "service_stop" in sig_names:
                ss_entries.append(e)
        self.assertTrue(ss_entries, "Expected explain entry for service_stop")
        # Must be event-based (low confidence), not command-based (medium)
        self.assertEqual(ss_entries[0]["confidence"], "low")

    def test_evtx_7036_running_state_does_not_fire(self):
        ts = pd.to_datetime(["2024-06-16T20:25:00Z"], utc=True)
        df = pd.DataFrame([
            {
                "parser": "winevtx",
                "event_identifier": "7036",
                "message": "The Print Spooler service entered the running state.",
                "timestamp_desc": "Event Recorded",
            },
        ], index=ts)
        df["chronosift_row_id"] = [0]

        out = self.engine.apply_contextual(self.engine.apply_atomic(df.copy()))
        signals = out.iloc[0]["chronosift_signals"] if "chronosift_signals" in out.columns else {}
        signals = signals if isinstance(signals, dict) else {}

        self.assertEqual(float(signals.get("service_stop", 0)), 0.0)

    # ── T1070.006 Timestomping ─────────────────────────────────────

    def test_timestomping_si_before_fn_fires(self):
        """$SI creation earlier than $FN creation → timestomping detected."""
        ts = pd.to_datetime([
            "2024-06-16T21:00:00Z",
            "2024-06-16T21:00:10Z",
        ], utc=True)
        df = pd.DataFrame([
            {
                "parser": "mft",
                "filename": r"C:\Users\alice\evil.exe",
                "timestamp_desc": "$STANDARD_INFORMATION Creation Time",
            },
            {
                "parser": "mft",
                "filename": r"C:\Users\alice\evil.exe",
                "timestamp_desc": "$FILE_NAME Creation Time",
            },
        ], index=ts)
        df["chronosift_row_id"] = [0, 1]

        out = self.engine.apply_contextual(self.engine.apply_atomic(df.copy()))
        signals = out.iloc[0]["chronosift_signals"] if "chronosift_signals" in out.columns else {}
        signals = signals if isinstance(signals, dict) else {}

        self.assertGreater(float(signals.get("timestomping", 0)), 0.0)
        # Verify explain entry
        explain = out.iloc[0]["chronosift_explain"] if "chronosift_explain" in out.columns else []
        explain = explain if isinstance(explain, list) else []
        ts_entries = [e for e in explain if isinstance(e, dict) and e.get("rule_id") == "TIMESTOMPING"]
        self.assertTrue(ts_entries, "Expected TIMESTOMPING explain entry")
        self.assertEqual(ts_entries[0]["confidence"], "high")

    def test_timestomping_fn_not_after_si_does_not_fire(self):
        """$FN and $SI same timestamp → no timestomping."""
        ts = pd.to_datetime([
            "2024-06-16T21:10:00Z",
            "2024-06-16T21:10:00Z",
        ], utc=True)
        df = pd.DataFrame([
            {
                "parser": "mft",
                "filename": r"C:\Users\alice\normal.exe",
                "timestamp_desc": "$STANDARD_INFORMATION Creation Time",
            },
            {
                "parser": "mft",
                "filename": r"C:\Users\alice\normal.exe",
                "timestamp_desc": "$FILE_NAME Creation Time",
            },
        ], index=ts)
        df["chronosift_row_id"] = [0, 1]

        out = self.engine.apply_contextual(self.engine.apply_atomic(df.copy()))
        for row_i in range(len(out)):
            signals = out.iloc[row_i]["chronosift_signals"] if "chronosift_signals" in out.columns else {}
            signals = signals if isinstance(signals, dict) else {}
            self.assertEqual(float(signals.get("timestomping", 0)), 0.0)

    def test_timestomping_os_update_path_excluded(self):
        """Files in OS-update directories should not fire timestomping."""
        ts = pd.to_datetime([
            "2024-06-16T21:15:00Z",
            "2024-06-16T21:15:10Z",
        ], utc=True)
        df = pd.DataFrame([
            {
                "parser": "mft",
                "filename": r"C:\Windows\WinSxS\amd64_something\file.dll",
                "timestamp_desc": "$STANDARD_INFORMATION Creation Time",
            },
            {
                "parser": "mft",
                "filename": r"C:\Windows\WinSxS\amd64_something\file.dll",
                "timestamp_desc": "$FILE_NAME Creation Time",
            },
        ], index=ts)
        df["chronosift_row_id"] = [0, 1]

        out = self.engine.apply_contextual(self.engine.apply_atomic(df.copy()))
        for row_i in range(len(out)):
            signals = out.iloc[row_i]["chronosift_signals"] if "chronosift_signals" in out.columns else {}
            signals = signals if isinstance(signals, dict) else {}
            self.assertEqual(float(signals.get("timestomping", 0)), 0.0)

    def test_timestomping_bulk_extraction_dampened_to_low_confidence(self):
        """Many files in same directory with $FN > $SI → low confidence (archive extraction)."""
        base_ts = pd.Timestamp("2024-06-16T21:30:00Z")
        rows = []
        # Create 6 files (above BULK_THRESHOLD=5) in the same directory.
        # $SI creation is at T+0, $FN creation is at T+10s for each file
        # to ensure fn_ts - si_ts > 1s threshold.
        for i in range(6):
            fname = f"C:\\Users\\alice\\extracted\\file{i}.dll"
            rows.append({
                "parser": "mft",
                "filename": fname,
                "timestamp_desc": "$STANDARD_INFORMATION Creation Time",
                "_test_ts": base_ts + pd.Timedelta(seconds=i),
            })
            rows.append({
                "parser": "mft",
                "filename": fname,
                "timestamp_desc": "$FILE_NAME Creation Time",
                "_test_ts": base_ts + pd.Timedelta(seconds=i + 10),
            })

        ts = pd.to_datetime([r.pop("_test_ts") for r in rows], utc=True)
        df = pd.DataFrame(rows, index=ts)
        df["chronosift_row_id"] = list(range(len(df)))

        out = self.engine.apply_contextual(self.engine.apply_atomic(df.copy()))

        # Should still fire but with low confidence and bulk_extraction_dampened flag
        found_ts_explain = False
        for row_i in range(len(out)):
            explain = out.iloc[row_i]["chronosift_explain"] if "chronosift_explain" in out.columns else []
            explain = explain if isinstance(explain, list) else []
            for e in explain:
                if isinstance(e, dict) and e.get("rule_id") == "TIMESTOMPING":
                    found_ts_explain = True
                    self.assertEqual(e["confidence"], "low")
                    self.assertTrue(e["evidence"].get("bulk_extraction_dampened", False))
        self.assertTrue(found_ts_explain, "Expected TIMESTOMPING explains with low confidence for bulk extraction")

    def test_timestomping_single_file_stays_high_confidence(self):
        """A single isolated file with $FN > $SI stays high confidence."""
        ts = pd.to_datetime([
            "2024-06-16T21:40:00Z",
            "2024-06-16T21:40:10Z",
        ], utc=True)
        df = pd.DataFrame([
            {
                "parser": "mft",
                "filename": r"C:\Users\alice\Desktop\payload.exe",
                "timestamp_desc": "$STANDARD_INFORMATION Creation Time",
            },
            {
                "parser": "mft",
                "filename": r"C:\Users\alice\Desktop\payload.exe",
                "timestamp_desc": "$FILE_NAME Creation Time",
            },
        ], index=ts)
        df["chronosift_row_id"] = [0, 1]

        out = self.engine.apply_contextual(self.engine.apply_atomic(df.copy()))
        explain = out.iloc[0]["chronosift_explain"] if "chronosift_explain" in out.columns else []
        explain = explain if isinstance(explain, list) else []
        ts_entries = [e for e in explain if isinstance(e, dict) and e.get("rule_id") == "TIMESTOMPING"]
        self.assertTrue(ts_entries)
        self.assertEqual(ts_entries[0]["confidence"], "high")
        self.assertNotIn("bulk_extraction_dampened", ts_entries[0].get("evidence", {}))

    def test_timestomping_uses_normalised_parser_and_timestamp_desc_values(self):
        """Whitespace/casing variation should not suppress MFT timestomping detection."""
        ts = pd.to_datetime([
            "2024-06-16T21:45:00Z",
            "2024-06-16T21:45:10Z",
        ], utc=True)
        df = pd.DataFrame([
            {
                "parser": " MFT ",
                "filename": r"C:\Users\alice\Desktop\payload.exe",
                "timestamp_desc": " $STANDARD_INFORMATION Creation Time ",
            },
            {
                "parser": " mFt ",
                "filename": r"C:\Users\alice\Desktop\payload.exe",
                "timestamp_desc": " $FILE_NAME Creation Time ",
            },
        ], index=ts)
        df["chronosift_row_id"] = [0, 1]

        out = self.engine.apply_contextual(self.engine.apply_atomic(df.copy()))
        signals = out.iloc[0]["chronosift_signals"] if "chronosift_signals" in out.columns else {}
        signals = signals if isinstance(signals, dict) else {}

        self.assertGreater(float(signals.get("timestomping", 0)), 0.0)

    def test_timestomping_non_mft_parser_does_not_fire(self):
        """Non-MFT rows with creation timestamps should not trigger timestomping."""
        ts = pd.to_datetime([
            "2024-06-16T21:20:00Z",
            "2024-06-16T21:20:10Z",
        ], utc=True)
        df = pd.DataFrame([
            {
                "parser": "filestat",
                "filename": r"C:\Users\alice\file.exe",
                "timestamp_desc": "Creation Time",
            },
            {
                "parser": "filestat",
                "filename": r"C:\Users\alice\file.exe",
                "timestamp_desc": "Content Modification Time",
            },
        ], index=ts)
        df["chronosift_row_id"] = [0, 1]

        out = self.engine.apply_contextual(self.engine.apply_atomic(df.copy()))
        for row_i in range(len(out)):
            signals = out.iloc[row_i]["chronosift_signals"] if "chronosift_signals" in out.columns else {}
            signals = signals if isinstance(signals, dict) else {}
            self.assertEqual(float(signals.get("timestomping", 0)), 0.0)


# Import YARA-specific helpers from the engine module
extract_yara_rule_names = MODULE.extract_yara_rule_names
parse_yara_forge_metadata = MODULE.parse_yara_forge_metadata
_classify_yara_rule = MODULE._classify_yara_rule
YARA_CAT_CERTIFICATE = MODULE.YARA_CAT_CERTIFICATE
YARA_CAT_OFFENSIVE_TOOL = MODULE.YARA_CAT_OFFENSIVE_TOOL
YARA_CAT_RANSOMWARE = MODULE.YARA_CAT_RANSOMWARE
YARA_CAT_WEBSHELL = MODULE.YARA_CAT_WEBSHELL
YARA_CAT_APT = MODULE.YARA_CAT_APT
YARA_CAT_EXPLOIT = MODULE.YARA_CAT_EXPLOIT
YARA_CAT_MALWARE = MODULE.YARA_CAT_MALWARE


class ChronoSiftV231YaraCategoryTest(unittest.TestCase):
    """Tests for YARA Forge category-aware signal scoring."""

    # ── extract_yara_rule_names ──────────────────────────────────────────

    def test_extract_names_from_json_list(self):
        names = extract_yara_rule_names('["RULE_A", "RULE_B"]')
        self.assertEqual(names, ["RULE_A", "RULE_B"])

    def test_extract_names_from_python_list(self):
        names = extract_yara_rule_names("['RULE_A', 'RULE_B']")
        self.assertEqual(names, ["RULE_A", "RULE_B"])

    def test_extract_names_from_native_list(self):
        names = extract_yara_rule_names(["RULE_X", "RULE_Y"])
        self.assertEqual(names, ["RULE_X", "RULE_Y"])

    def test_extract_names_from_single_string(self):
        names = extract_yara_rule_names("RULE_SINGLE")
        self.assertEqual(names, ["RULE_SINGLE"])

    def test_extract_names_none(self):
        self.assertEqual(extract_yara_rule_names(None), [])

    def test_extract_names_empty_list(self):
        self.assertEqual(extract_yara_rule_names("[]"), [])

    # ── _classify_yara_rule ──────────────────────────────────────────────

    def test_classify_cert_blocklist_by_name(self):
        self.assertEqual(_classify_yara_rule("REVERSINGLABS_Cert_Blocklist_ABC123"), YARA_CAT_CERTIFICATE)

    def test_classify_mimikatz_by_name(self):
        self.assertEqual(_classify_yara_rule("BINARYALERT_Hacktool_Windows_Mimikatz_Errors"), YARA_CAT_OFFENSIVE_TOOL)

    def test_classify_cobaltstrike_by_name(self):
        self.assertEqual(_classify_yara_rule("GCTI_Cobaltstrike_Resources_Beacon"), YARA_CAT_OFFENSIVE_TOOL)

    def test_classify_ransomware_by_tc_detection_type(self):
        cat = _classify_yara_rule("REVERSINGLABS_Win32_Foo", meta_tc_detection_type="Ransomware")
        self.assertEqual(cat, YARA_CAT_RANSOMWARE)

    def test_classify_ransomware_by_name(self):
        self.assertEqual(_classify_yara_rule("DITEKSHEN_MALWARE_Win_Ransomware_Lockbit"), YARA_CAT_RANSOMWARE)

    def test_classify_webshell_by_name(self):
        self.assertEqual(_classify_yara_rule("SIGNATURE_BASE_Webshell_Php_Generic"), YARA_CAT_WEBSHELL)

    def test_classify_apt_by_name(self):
        self.assertEqual(_classify_yara_rule("SEKOIA_Apt_Kimsuky_Sharpext"), YARA_CAT_APT)

    def test_classify_exploit_by_name(self):
        self.assertEqual(_classify_yara_rule("SIGNATURE_BASE_Exploit_CVE_2021_44228"), YARA_CAT_EXPLOIT)

    def test_classify_hktl_by_name(self):
        self.assertEqual(_classify_yara_rule("SIGNATURE_BASE_HKTL_NET_GUID_Rubeus"), YARA_CAT_OFFENSIVE_TOOL)

    def test_classify_generic_malware_default(self):
        self.assertEqual(_classify_yara_rule("MALPEDIA_Win_Unknown_Auto"), YARA_CAT_MALWARE)

    def test_classify_info_tag_cert(self):
        cat = _classify_yara_rule("REVERSINGLABS_Cert_Blocklist_XYZ", inline_tags="INFO FILE")
        self.assertEqual(cat, YARA_CAT_CERTIFICATE)

    # ── parse_yara_forge_metadata ────────────────────────────────────────

    @unittest.skipUnless(
        pathlib.Path(YARA_METADATA_PATH).is_file(),
        "YARA Forge extended rules file not found",
    )
    def test_parse_metadata_loads_rules(self):
        idx = parse_yara_forge_metadata(YARA_METADATA_PATH)
        self.assertGreater(len(idx), 10000)

    @unittest.skipUnless(
        pathlib.Path(YARA_METADATA_PATH).is_file(),
        "YARA Forge extended rules file not found",
    )
    def test_parse_metadata_cert_classified(self):
        idx = parse_yara_forge_metadata(YARA_METADATA_PATH)
        cert_count = sum(1 for m in idx.values() if m.category == YARA_CAT_CERTIFICATE)
        self.assertGreater(cert_count, 1000, "Expected >1000 certificate blocklist rules")

    @unittest.skipUnless(
        pathlib.Path(YARA_METADATA_PATH).is_file(),
        "YARA Forge extended rules file not found",
    )
    def test_parse_metadata_offensive_tool_classified(self):
        idx = parse_yara_forge_metadata(YARA_METADATA_PATH)
        ot_count = sum(1 for m in idx.values() if m.category == YARA_CAT_OFFENSIVE_TOOL)
        self.assertGreater(ot_count, 500, "Expected >500 offensive tool rules")

    # ── Engine integration (category-aware signal injection) ─────────────

    def _build_yara_timeline(self, yara_match_value):
        """Build a minimal 1-row timeline with a YARA match."""
        base_ts = pd.Timestamp("2024-06-16T10:00:00Z")
        df = pd.DataFrame([{
            "parser": "filestat",
            "filename": "/tmp/test.exe",
            "display_name": "test.exe",
            "relative_path": "/tmp/test.exe",
            "timestamp_desc": "Creation Time",
            "hostname": "host1",
            "yara_match": yara_match_value,
        }], index=[base_ts])
        df["chronosift_row_id"] = [0]
        return df

    @unittest.skipUnless(
        pathlib.Path(YARA_METADATA_PATH).is_file(),
        "YARA Forge extended rules file not found",
    )
    def test_engine_offensive_tool_signal_emitted(self):
        engine = ChronoSiftEngine.from_yaml(RULES_PATH, WEIGHTS_PATH, yara_metadata_path=YARA_METADATA_PATH)
        df = self._build_yara_timeline('["BINARYALERT_Hacktool_Windows_Mimikatz_Errors"]')
        out = engine.apply_atomic(df, materialise_event_columns=True)
        signals = out.iloc[0]["chronosift_signals"] or {}
        self.assertGreater(float(signals.get("yara_offensive_tool", 0)), 0)
        self.assertGreater(float(signals.get("yara_hit_strength", 0)), 0)
        # Certificate signal should NOT be emitted
        self.assertEqual(float(signals.get("yara_certificate_blocklist", 0)), 0)

    @unittest.skipUnless(
        pathlib.Path(YARA_METADATA_PATH).is_file(),
        "YARA Forge extended rules file not found",
    )
    def test_engine_cert_blocklist_dampened(self):
        """Certificate blocklist matches should not contribute to yara_hit_strength."""
        engine = ChronoSiftEngine.from_yaml(RULES_PATH, WEIGHTS_PATH, yara_metadata_path=YARA_METADATA_PATH)
        df = self._build_yara_timeline('["REVERSINGLABS_Cert_Blocklist_05E2E6A4Cd09Ea54D665B075Fe22A256"]')
        out = engine.apply_atomic(df, materialise_event_columns=True)
        signals = out.iloc[0]["chronosift_signals"] or {}
        # Certificate signal should be emitted
        self.assertGreater(float(signals.get("yara_certificate_blocklist", 0)), 0)
        # But yara_hit_strength should be 0 (cert excluded from strength)
        self.assertEqual(float(signals.get("yara_hit_strength", 0)), 0)

    @unittest.skipUnless(
        pathlib.Path(YARA_METADATA_PATH).is_file(),
        "YARA Forge extended rules file not found",
    )
    def test_engine_ransomware_signal_emitted(self):
        engine = ChronoSiftEngine.from_yaml(RULES_PATH, WEIGHTS_PATH, yara_metadata_path=YARA_METADATA_PATH)
        df = self._build_yara_timeline('["REVERSINGLABS_Win32_Ransomware_Lockbit"]')
        out = engine.apply_atomic(df, materialise_event_columns=True)
        signals = out.iloc[0]["chronosift_signals"] or {}
        self.assertGreater(float(signals.get("yara_ransomware", 0)), 0)

    @unittest.skipUnless(
        pathlib.Path(YARA_METADATA_PATH).is_file(),
        "YARA Forge extended rules file not found",
    )
    def test_engine_mixed_hits_cert_excluded_from_strength(self):
        """When a file has both cert + real malware hits, only non-cert count affects strength."""
        engine = ChronoSiftEngine.from_yaml(RULES_PATH, WEIGHTS_PATH, yara_metadata_path=YARA_METADATA_PATH)
        df = self._build_yara_timeline(
            '["REVERSINGLABS_Cert_Blocklist_05E2E6A4Cd09Ea54D665B075Fe22A256", "REVERSINGLABS_Win32_Ransomware_Lockbit"]'
        )
        out = engine.apply_atomic(df, materialise_event_columns=True)
        signals = out.iloc[0]["chronosift_signals"] or {}
        # Both category signals emitted
        self.assertGreater(float(signals.get("yara_certificate_blocklist", 0)), 0)
        self.assertGreater(float(signals.get("yara_ransomware", 0)), 0)
        # Strength should reflect 1 non-cert hit (1/3 * score_mult ≈ 0.25)
        strength = float(signals.get("yara_hit_strength", 0))
        self.assertGreater(strength, 0)
        self.assertLess(strength, 0.5, "Expected ~0.33*0.75 for 1 non-cert hit")

    def test_engine_no_metadata_legacy_path(self):
        """Without YARA metadata file, engine falls back to legacy undifferentiated scoring."""
        engine = ChronoSiftEngine.from_yaml(RULES_PATH, WEIGHTS_PATH, yara_metadata_path=YARA_METADATA_PATH)
        df = self._build_yara_timeline('["SOME_RULE"]')
        out = engine.apply_atomic(df, materialise_event_columns=True)
        signals = out.iloc[0]["chronosift_signals"] or {}
        # Legacy path: yara_hit_strength > 0, no category signals
        self.assertGreater(float(signals.get("yara_hit_strength", 0)), 0)
        self.assertEqual(float(signals.get("yara_offensive_tool", 0)), 0)


# ── ClamAV category-aware scoring ────────────────────────────────────────────

parse_clamav_signature = MODULE.parse_clamav_signature
ClamAVSignatureMeta = MODULE.ClamAVSignatureMeta
AV_CAT_OFFENSIVE_TOOL = MODULE.AV_CAT_OFFENSIVE_TOOL
AV_CAT_RANSOMWARE = MODULE.AV_CAT_RANSOMWARE
AV_CAT_EXPLOIT = MODULE.AV_CAT_EXPLOIT
AV_CAT_MALWARE = MODULE.AV_CAT_MALWARE
AV_CAT_PUA = MODULE.AV_CAT_PUA
AV_CAT_WEBSHELL = MODULE.AV_CAT_WEBSHELL


class ChronoSiftV231ClamAVCategoryTest(unittest.TestCase):
    """Tests for ClamAV category-aware signal scoring.

    Covers the full ClamAV naming taxonomy — standard signatures
    (Platform.Category.Family-ID-Rev), PUA prefix forms,
    Heuristics/bytecode deviations, all 27 category tokens in
    _CLAMAV_CATEGORY_MAP, all family overrides in
    _CLAMAV_FAMILY_OVERRIDES, and multi-platform coverage.
    """

    # ── Structural parsing ───────────────────────────────────────────────

    def test_parse_standard_three_part_structure(self):
        """Standard Platform.Category.Family-ID-Rev parses all fields."""
        meta = parse_clamav_signature("Win.Trojan.Agent-12345-0")
        self.assertEqual(meta.platform, "Win")
        self.assertEqual(meta.category_token, "Trojan")
        self.assertEqual(meta.family, "Agent")
        self.assertEqual(meta.forensic_category, AV_CAT_MALWARE)

    def test_parse_two_part_signature(self):
        """Two-part signature (Platform.Family or Category.Family)."""
        meta = parse_clamav_signature("Win.Generic-999-0")
        self.assertEqual(meta.family, "Generic")

    def test_parse_single_part_signature(self):
        """Bare name with no dots, just Family-ID."""
        meta = parse_clamav_signature("Foobar-42-1")
        self.assertEqual(meta.family, "Foobar")
        self.assertEqual(meta.forensic_category, AV_CAT_MALWARE)

    def test_parse_family_with_dots(self):
        """Family segment containing extra dots: Win.Trojan.Sub.Family-1-0."""
        meta = parse_clamav_signature("Win.Trojan.Sub.Family-1-0")
        self.assertEqual(meta.category_token, "Trojan")
        # Family should be the remainder before the first '-'
        self.assertEqual(meta.family, "Sub.Family")

    def test_parse_no_id_suffix(self):
        """Signature with no -ID-Rev suffix: Win.Trojan.Agent."""
        meta = parse_clamav_signature("Win.Trojan.Agent")
        self.assertEqual(meta.family, "Agent")
        self.assertEqual(meta.forensic_category, AV_CAT_MALWARE)

    def test_parse_none_returns_default(self):
        meta = parse_clamav_signature(None)
        self.assertEqual(meta.forensic_category, AV_CAT_MALWARE)
        self.assertEqual(meta.platform, "")

    def test_parse_empty_string_returns_default(self):
        meta = parse_clamav_signature("")
        self.assertEqual(meta.forensic_category, AV_CAT_MALWARE)
        self.assertEqual(meta.family, "")

    def test_parse_nonstandard_garbage_returns_default(self):
        meta = parse_clamav_signature("SomethingWeird")
        self.assertEqual(meta.forensic_category, AV_CAT_MALWARE)

    # ── PUA prefix handling ──────────────────────────────────────────────

    def test_parse_pua_prefix_three_part(self):
        """PUA.Win.FamilyName-ID-Rev → category=PUA, platform from second part."""
        meta = parse_clamav_signature("PUA.Win.Toolbar-55555-0")
        self.assertEqual(meta.category_token, "PUA")
        self.assertEqual(meta.platform, "Win")
        self.assertEqual(meta.family, "Toolbar")
        self.assertEqual(meta.forensic_category, AV_CAT_PUA)

    def test_parse_pua_prefix_multi_part(self):
        """PUA.Unix.Coinminer.Generic-1-0 → PUA, platform Unix."""
        meta = parse_clamav_signature("PUA.Unix.Coinminer.Generic-1-0")
        self.assertEqual(meta.category_token, "PUA")
        self.assertEqual(meta.platform, "Unix")
        self.assertEqual(meta.forensic_category, AV_CAT_PUA)

    # ── Category token classification (all 27 tokens) ────────────────────

    def test_category_ransomware(self):
        meta = parse_clamav_signature("Win.Ransomware.Lockbit-9876543-0")
        self.assertEqual(meta.forensic_category, AV_CAT_RANSOMWARE)

    def test_category_trojan(self):
        meta = parse_clamav_signature("Win.Trojan.Generic-1-0")
        self.assertEqual(meta.forensic_category, AV_CAT_MALWARE)

    def test_category_backdoor(self):
        meta = parse_clamav_signature("Linux.Backdoor.Tsunami-42-0")
        self.assertEqual(meta.forensic_category, AV_CAT_MALWARE)

    def test_category_virus(self):
        meta = parse_clamav_signature("Win.Virus.Sality-100-0")
        self.assertEqual(meta.forensic_category, AV_CAT_MALWARE)

    def test_category_worm(self):
        meta = parse_clamav_signature("Win.Worm.Conficker-5-0")
        self.assertEqual(meta.forensic_category, AV_CAT_MALWARE)

    def test_category_malware(self):
        meta = parse_clamav_signature("Win.Malware.Generic-99-0")
        self.assertEqual(meta.forensic_category, AV_CAT_MALWARE)

    def test_category_dropper(self):
        meta = parse_clamav_signature("Win.Dropper.Emotet-7777-0")
        self.assertEqual(meta.forensic_category, AV_CAT_MALWARE)

    def test_category_downloader(self):
        meta = parse_clamav_signature("Win.Downloader.Banload-100-0")
        self.assertEqual(meta.forensic_category, AV_CAT_MALWARE)

    def test_category_loader(self):
        meta = parse_clamav_signature("Win.Loader.BazarLoader-3-0")
        self.assertEqual(meta.forensic_category, AV_CAT_MALWARE)

    def test_category_infostealer(self):
        meta = parse_clamav_signature("Win.Infostealer.Formbook-200-0")
        self.assertEqual(meta.forensic_category, AV_CAT_MALWARE)

    def test_category_spyware(self):
        meta = parse_clamav_signature("Win.Spyware.Predator-10-0")
        self.assertEqual(meta.forensic_category, AV_CAT_MALWARE)

    def test_category_keylogger(self):
        meta = parse_clamav_signature("Win.Keylogger.Hawkeye-30-0")
        self.assertEqual(meta.forensic_category, AV_CAT_MALWARE)

    def test_category_ircbot(self):
        meta = parse_clamav_signature("Linux.Ircbot.Kaiten-1-0")
        self.assertEqual(meta.forensic_category, AV_CAT_MALWARE)

    def test_category_proxy(self):
        meta = parse_clamav_signature("Win.Proxy.Agent-22-0")
        self.assertEqual(meta.forensic_category, AV_CAT_MALWARE)

    def test_category_phishing(self):
        meta = parse_clamav_signature("Html.Phishing.Bank-50-0")
        self.assertEqual(meta.forensic_category, AV_CAT_MALWARE)

    def test_category_packed(self):
        meta = parse_clamav_signature("Win.Packed.UPX-1-0")
        self.assertEqual(meta.forensic_category, AV_CAT_MALWARE)

    def test_category_packer(self):
        meta = parse_clamav_signature("Win.Packer.Themida-8-0")
        self.assertEqual(meta.forensic_category, AV_CAT_MALWARE)

    def test_category_file(self):
        meta = parse_clamav_signature("Win.File.Suspicious-333-0")
        self.assertEqual(meta.forensic_category, AV_CAT_MALWARE)

    def test_category_rootkit(self):
        meta = parse_clamav_signature("Win.Rootkit.TDL4-11-0")
        self.assertEqual(meta.forensic_category, AV_CAT_EXPLOIT)

    def test_category_exploit(self):
        meta = parse_clamav_signature("Win.Exploit.CVE_2021_44228-100-0")
        self.assertEqual(meta.forensic_category, AV_CAT_EXPLOIT)

    def test_category_tool(self):
        meta = parse_clamav_signature("Win.Tool.Netcat-2-0")
        self.assertEqual(meta.forensic_category, AV_CAT_OFFENSIVE_TOOL)

    def test_category_hacktool(self):
        meta = parse_clamav_signature("Win.Hacktool.Ncrack-1-0")
        self.assertEqual(meta.forensic_category, AV_CAT_OFFENSIVE_TOOL)

    def test_category_pua_token(self):
        meta = parse_clamav_signature("Win.Pua.Generic-1-0")
        self.assertEqual(meta.forensic_category, AV_CAT_PUA)

    def test_category_adware(self):
        meta = parse_clamav_signature("Win.Adware.Toolbar-55555-0")
        self.assertEqual(meta.forensic_category, AV_CAT_PUA)

    def test_category_coinminer(self):
        meta = parse_clamav_signature("Win.Coinminer.Generic-99999-0")
        self.assertEqual(meta.forensic_category, AV_CAT_PUA)

    def test_category_joke(self):
        meta = parse_clamav_signature("Win.Joke.FakeAlert-1-0")
        self.assertEqual(meta.forensic_category, AV_CAT_PUA)

    def test_category_countermeasure(self):
        meta = parse_clamav_signature("Win.Countermeasure.Agent-3-0")
        self.assertEqual(meta.forensic_category, AV_CAT_OFFENSIVE_TOOL)

    # ── Family override classification ───────────────────────────────────
    # Family overrides take priority even when the category token would
    # classify differently (e.g., Win.Trojan.Mimikatz → offensive_tool)

    def test_family_override_mimikatz_from_trojan(self):
        """Mimikatz as Trojan → offensive_tool via family override."""
        meta = parse_clamav_signature("Win.Trojan.Mimikatz-9999-0")
        self.assertEqual(meta.forensic_category, AV_CAT_OFFENSIVE_TOOL)

    def test_family_override_cobaltstrike(self):
        meta = parse_clamav_signature("Win.Trojan.CobaltStrike-1234-0")
        self.assertEqual(meta.forensic_category, AV_CAT_OFFENSIVE_TOOL)

    def test_family_override_metasploit(self):
        meta = parse_clamav_signature("Win.Backdoor.Metasploit-42-0")
        self.assertEqual(meta.forensic_category, AV_CAT_OFFENSIVE_TOOL)

    def test_family_override_meterpreter(self):
        meta = parse_clamav_signature("Win.Trojan.Meterpreter-77-0")
        self.assertEqual(meta.forensic_category, AV_CAT_OFFENSIVE_TOOL)

    def test_family_override_sharphound(self):
        meta = parse_clamav_signature("Win.Tool.SharpHound-1-0")
        self.assertEqual(meta.forensic_category, AV_CAT_OFFENSIVE_TOOL)

    def test_family_override_bloodhound(self):
        meta = parse_clamav_signature("Win.Tool.BloodHound-3-0")
        self.assertEqual(meta.forensic_category, AV_CAT_OFFENSIVE_TOOL)

    def test_family_override_rubeus(self):
        meta = parse_clamav_signature("Win.Hacktool.Rubeus-5-0")
        self.assertEqual(meta.forensic_category, AV_CAT_OFFENSIVE_TOOL)

    def test_family_override_impacket(self):
        meta = parse_clamav_signature("Win.Tool.Impacket-2-0")
        self.assertEqual(meta.forensic_category, AV_CAT_OFFENSIVE_TOOL)

    def test_family_override_lazagne(self):
        meta = parse_clamav_signature("Win.Trojan.LaZagne-1-0")
        self.assertEqual(meta.forensic_category, AV_CAT_OFFENSIVE_TOOL)

    def test_family_override_pwdump(self):
        meta = parse_clamav_signature("Win.Hacktool.Pwdump-10-0")
        self.assertEqual(meta.forensic_category, AV_CAT_OFFENSIVE_TOOL)

    def test_family_override_c99shell_webshell(self):
        """Php.Trojan.C99shell → webshell via family override."""
        meta = parse_clamav_signature("Php.Trojan.C99shell-1234-0")
        self.assertEqual(meta.forensic_category, AV_CAT_WEBSHELL)

    def test_family_override_r57shell_webshell(self):
        meta = parse_clamav_signature("Php.Backdoor.R57shell-1-0")
        self.assertEqual(meta.forensic_category, AV_CAT_WEBSHELL)

    def test_family_override_b374k_webshell(self):
        meta = parse_clamav_signature("Php.Trojan.B374k-7-0")
        self.assertEqual(meta.forensic_category, AV_CAT_WEBSHELL)

    def test_family_override_weevely_webshell(self):
        meta = parse_clamav_signature("Php.Backdoor.Weevely-3-0")
        self.assertEqual(meta.forensic_category, AV_CAT_WEBSHELL)

    def test_family_override_wso_webshell(self):
        meta = parse_clamav_signature("Php.Trojan.Wso-5-0")
        self.assertEqual(meta.forensic_category, AV_CAT_WEBSHELL)

    def test_family_override_petya_ransomware(self):
        meta = parse_clamav_signature("Win.Trojan.Petya-5555-0")
        self.assertEqual(meta.forensic_category, AV_CAT_RANSOMWARE)

    def test_family_override_wannacry_ransomware(self):
        meta = parse_clamav_signature("Win.Trojan.WannaCry-100-0")
        self.assertEqual(meta.forensic_category, AV_CAT_RANSOMWARE)

    def test_family_override_conti_ransomware(self):
        meta = parse_clamav_signature("Win.Malware.Conti-200-0")
        self.assertEqual(meta.forensic_category, AV_CAT_RANSOMWARE)

    def test_family_override_revil_ransomware(self):
        meta = parse_clamav_signature("Win.Trojan.REvil-50-0")
        self.assertEqual(meta.forensic_category, AV_CAT_RANSOMWARE)

    def test_family_override_ryuk_ransomware(self):
        meta = parse_clamav_signature("Win.Ransomware.Ryuk-8-0")
        self.assertEqual(meta.forensic_category, AV_CAT_RANSOMWARE)

    def test_family_override_maze_ransomware(self):
        meta = parse_clamav_signature("Win.Trojan.Maze-11-0")
        self.assertEqual(meta.forensic_category, AV_CAT_RANSOMWARE)

    def test_family_override_blackcat_ransomware(self):
        meta = parse_clamav_signature("Win.Ransomware.BlackCat-1-0")
        self.assertEqual(meta.forensic_category, AV_CAT_RANSOMWARE)

    def test_family_override_alphv_ransomware(self):
        meta = parse_clamav_signature("Win.Trojan.ALPHV-3-0")
        self.assertEqual(meta.forensic_category, AV_CAT_RANSOMWARE)

    def test_family_override_babuk_ransomware(self):
        meta = parse_clamav_signature("Win.Ransomware.Babuk-2-0")
        self.assertEqual(meta.forensic_category, AV_CAT_RANSOMWARE)

    def test_family_override_akira_ransomware(self):
        meta = parse_clamav_signature("Win.Ransomware.Akira-1-0")
        self.assertEqual(meta.forensic_category, AV_CAT_RANSOMWARE)

    def test_family_override_razy_ransomware(self):
        meta = parse_clamav_signature("Win.Trojan.Razy-6-0")
        self.assertEqual(meta.forensic_category, AV_CAT_RANSOMWARE)

    def test_family_override_lockbit_from_trojan(self):
        """Lockbit classified as Trojan → ransomware via family override."""
        meta = parse_clamav_signature("Win.Trojan.Lockbit-55-0")
        self.assertEqual(meta.forensic_category, AV_CAT_RANSOMWARE)

    # ── Multi-platform coverage ──────────────────────────────────────────

    def test_platform_linux(self):
        meta = parse_clamav_signature("Linux.Backdoor.Tsunami-42-0")
        self.assertEqual(meta.platform, "Linux")

    def test_platform_osx(self):
        meta = parse_clamav_signature("Osx.Trojan.Shlayer-1-0")
        self.assertEqual(meta.platform, "Osx")
        self.assertEqual(meta.forensic_category, AV_CAT_MALWARE)

    def test_platform_php(self):
        meta = parse_clamav_signature("Php.Trojan.Agent-123-0")
        self.assertEqual(meta.platform, "Php")

    def test_platform_html(self):
        meta = parse_clamav_signature("Html.Phishing.Generic-50-0")
        self.assertEqual(meta.platform, "Html")

    def test_platform_js(self):
        meta = parse_clamav_signature("Js.Trojan.Downloader-7-0")
        self.assertEqual(meta.platform, "Js")

    def test_platform_unix(self):
        meta = parse_clamav_signature("Unix.Trojan.Agent-1-0")
        self.assertEqual(meta.platform, "Unix")

    def test_platform_java(self):
        meta = parse_clamav_signature("Java.Exploit.CVE_2013_0431-1-0")
        self.assertEqual(meta.platform, "Java")
        self.assertEqual(meta.forensic_category, AV_CAT_EXPLOIT)

    def test_platform_doc(self):
        """OLE/macro-based Office detections."""
        meta = parse_clamav_signature("Doc.Dropper.Agent-444-0")
        self.assertEqual(meta.platform, "Doc")
        self.assertEqual(meta.forensic_category, AV_CAT_MALWARE)

    def test_platform_multios(self):
        meta = parse_clamav_signature("Multios.Trojan.Agent-1-0")
        self.assertEqual(meta.platform, "Multios")

    # ── Unknown / unrecognised category tokens default to malware ────────

    def test_unknown_category_token_defaults_malware(self):
        """Category tokens not in _CLAMAV_CATEGORY_MAP default to malware."""
        meta = parse_clamav_signature("Win.Fictitious.Agent-1-0")
        self.assertEqual(meta.forensic_category, AV_CAT_MALWARE)

    # ── Engine integration (ClamAV category-aware signal injection) ──────

    def _build_av_timeline(self, av_signature, av_hit=True):
        """Build a minimal 1-row timeline with an AV hit."""
        base_ts = pd.Timestamp("2024-06-16T10:00:00Z")
        df = pd.DataFrame([{
            "parser": "filestat",
            "filename": "/tmp/malware.exe",
            "display_name": "malware.exe",
            "relative_path": "/tmp/malware.exe",
            "timestamp_desc": "Creation Time",
            "hostname": "host1",
            "av_signature": av_signature,
            "av_hit": av_hit,
        }], index=[base_ts])
        df["chronosift_row_id"] = [0]
        return df

    def test_engine_av_malware_signal_emitted(self):
        engine = ChronoSiftEngine.from_yaml(RULES_PATH, WEIGHTS_PATH, yara_metadata_path=YARA_METADATA_PATH)
        df = self._build_av_timeline("Win.Trojan.Agent-12345-0")
        out = engine.apply_atomic(df, materialise_event_columns=True)
        signals = out.iloc[0]["chronosift_signals"] or {}
        self.assertGreater(float(signals.get("av_malware", 0)), 0)
        self.assertGreater(float(signals.get("av_hit", 0)), 0)

    def test_engine_av_ransomware_signal_emitted(self):
        engine = ChronoSiftEngine.from_yaml(RULES_PATH, WEIGHTS_PATH, yara_metadata_path=YARA_METADATA_PATH)
        df = self._build_av_timeline("Win.Ransomware.Lockbit-9876543-0")
        out = engine.apply_atomic(df, materialise_event_columns=True)
        signals = out.iloc[0]["chronosift_signals"] or {}
        self.assertGreater(float(signals.get("av_ransomware", 0)), 0)
        self.assertGreater(float(signals.get("av_hit", 0)), 0)

    def test_engine_av_exploit_signal_emitted(self):
        engine = ChronoSiftEngine.from_yaml(RULES_PATH, WEIGHTS_PATH, yara_metadata_path=YARA_METADATA_PATH)
        df = self._build_av_timeline("Win.Exploit.CVE_2021_44228-100-0")
        out = engine.apply_atomic(df, materialise_event_columns=True)
        signals = out.iloc[0]["chronosift_signals"] or {}
        self.assertGreater(float(signals.get("av_exploit", 0)), 0)
        self.assertGreater(float(signals.get("av_hit", 0)), 0)

    def test_engine_av_webshell_signal_emitted(self):
        engine = ChronoSiftEngine.from_yaml(RULES_PATH, WEIGHTS_PATH, yara_metadata_path=YARA_METADATA_PATH)
        df = self._build_av_timeline("Php.Trojan.C99shell-1234-0")
        out = engine.apply_atomic(df, materialise_event_columns=True)
        signals = out.iloc[0]["chronosift_signals"] or {}
        self.assertGreater(float(signals.get("av_webshell", 0)), 0)

    def test_engine_av_pua_dampened(self):
        """PUA detections should emit av_pua but suppress av_hit."""
        engine = ChronoSiftEngine.from_yaml(RULES_PATH, WEIGHTS_PATH, yara_metadata_path=YARA_METADATA_PATH)
        df = self._build_av_timeline("Win.Adware.Toolbar-55555-0")
        out = engine.apply_atomic(df, materialise_event_columns=True)
        signals = out.iloc[0]["chronosift_signals"] or {}
        self.assertGreater(float(signals.get("av_pua", 0)), 0)
        self.assertEqual(float(signals.get("av_hit", 0)), 0,
                         "PUA should suppress av_hit")

    def test_engine_av_pua_coinminer_dampened(self):
        """Coinminer PUA should also be dampened."""
        engine = ChronoSiftEngine.from_yaml(RULES_PATH, WEIGHTS_PATH, yara_metadata_path=YARA_METADATA_PATH)
        df = self._build_av_timeline("Win.Coinminer.Generic-1-0")
        out = engine.apply_atomic(df, materialise_event_columns=True)
        signals = out.iloc[0]["chronosift_signals"] or {}
        self.assertGreater(float(signals.get("av_pua", 0)), 0)
        self.assertEqual(float(signals.get("av_hit", 0)), 0)

    def test_engine_av_pua_prefix_dampened(self):
        """PUA.Win.* prefix form should also be dampened."""
        engine = ChronoSiftEngine.from_yaml(RULES_PATH, WEIGHTS_PATH, yara_metadata_path=YARA_METADATA_PATH)
        df = self._build_av_timeline("PUA.Win.Toolbar-1-0")
        out = engine.apply_atomic(df, materialise_event_columns=True)
        signals = out.iloc[0]["chronosift_signals"] or {}
        self.assertGreater(float(signals.get("av_pua", 0)), 0)
        self.assertEqual(float(signals.get("av_hit", 0)), 0)

    def test_engine_av_offensive_tool_signal_emitted(self):
        engine = ChronoSiftEngine.from_yaml(RULES_PATH, WEIGHTS_PATH, yara_metadata_path=YARA_METADATA_PATH)
        df = self._build_av_timeline("Win.Hacktool.Mimikatz-12345-0")
        out = engine.apply_atomic(df, materialise_event_columns=True)
        signals = out.iloc[0]["chronosift_signals"] or {}
        self.assertGreater(float(signals.get("av_offensive_tool", 0)), 0)

    def test_engine_av_offensive_tool_via_family_override(self):
        """Trojan.CobaltStrike should become av_offensive_tool via family override."""
        engine = ChronoSiftEngine.from_yaml(RULES_PATH, WEIGHTS_PATH, yara_metadata_path=YARA_METADATA_PATH)
        df = self._build_av_timeline("Win.Trojan.CobaltStrike-42-0")
        out = engine.apply_atomic(df, materialise_event_columns=True)
        signals = out.iloc[0]["chronosift_signals"] or {}
        self.assertGreater(float(signals.get("av_offensive_tool", 0)), 0)

    def test_engine_av_no_signature_no_category(self):
        """When av_hit is True but av_signature is empty, no category signal emitted."""
        engine = ChronoSiftEngine.from_yaml(RULES_PATH, WEIGHTS_PATH, yara_metadata_path=YARA_METADATA_PATH)
        df = self._build_av_timeline(None, av_hit=True)
        out = engine.apply_atomic(df, materialise_event_columns=True)
        signals = out.iloc[0]["chronosift_signals"] or {}
        # No category signals without a parseable signature
        self.assertEqual(float(signals.get("av_malware", 0)), 0)
        self.assertEqual(float(signals.get("av_ransomware", 0)), 0)
        self.assertEqual(float(signals.get("av_offensive_tool", 0)), 0)

    def test_engine_av_linux_backdoor(self):
        """Non-Windows platform detections should still emit correct signals."""
        engine = ChronoSiftEngine.from_yaml(RULES_PATH, WEIGHTS_PATH, yara_metadata_path=YARA_METADATA_PATH)
        df = self._build_av_timeline("Linux.Backdoor.Tsunami-42-0")
        out = engine.apply_atomic(df, materialise_event_columns=True)
        signals = out.iloc[0]["chronosift_signals"] or {}
        self.assertGreater(float(signals.get("av_malware", 0)), 0)
        self.assertGreater(float(signals.get("av_hit", 0)), 0)


# ── Geo continuity: new_city signal ──────────────────────────────────────────


class ChronoSiftV231NewCityTest(unittest.TestCase):
    """Tests for the new_city geo continuity signal."""

    @classmethod
    def setUpClass(cls):
        cls.engine = ChronoSiftEngine.from_yaml(RULES_PATH, WEIGHTS_PATH, yara_metadata_path=YARA_METADATA_PATH)

    def _build_geo_df(self, actors, ips, countries, asns, cities, timestamps):
        """Build a DataFrame with geo-enriched auth events."""
        df = pd.DataFrame(
            {
                "actor_principal": actors,
                "src_ip": ips,
                "geo_country_iso": countries,
                "geo_asn": asns,
                "geo_city_name": cities,
            },
            index=pd.to_datetime(timestamps),
        )
        return df

    def test_new_city_emitted_on_second_city(self):
        """Second city for same actor should emit new_city signal."""
        df = self._build_geo_df(
            actors=["alice", "alice"],
            ips=["203.0.113.10", "203.0.113.20"],
            countries=["GB", "GB"],
            asns=["64500", "64500"],
            cities=["London", "Manchester"],
            timestamps=["2024-06-16T10:00:00Z", "2024-06-16T12:00:00Z"],
        )
        signal_map = {
            0: {"auth_remote_success": 1.0},
            1: {"auth_remote_success": 1.0},
        }
        explain_map = {0: [], 1: []}
        self.engine._apply_geo_continuity_sparse(df, signal_map, explain_map, carried_state={})
        self.assertTrue(df.iloc[1]["geo_new_city"])
        self.assertEqual(signal_map[1].get("new_city"), 1.0)

    def test_first_city_no_signal(self):
        """First city seen for an actor should NOT emit new_city (no prior baseline)."""
        df = self._build_geo_df(
            actors=["alice"],
            ips=["203.0.113.10"],
            countries=["GB"],
            asns=["64500"],
            cities=["London"],
            timestamps=["2024-06-16T10:00:00Z"],
        )
        signal_map = {0: {"auth_remote_success": 1.0}}
        explain_map = {0: []}
        self.engine._apply_geo_continuity_sparse(df, signal_map, explain_map, carried_state={})
        self.assertNotIn("new_city", signal_map.get(0, {}))

    def test_same_city_no_signal(self):
        """Repeated city for same actor should NOT emit new_city."""
        df = self._build_geo_df(
            actors=["alice", "alice"],
            ips=["203.0.113.10", "203.0.113.20"],
            countries=["GB", "GB"],
            asns=["64500", "64500"],
            cities=["London", "London"],
            timestamps=["2024-06-16T10:00:00Z", "2024-06-16T12:00:00Z"],
        )
        signal_map = {
            0: {"auth_remote_success": 1.0},
            1: {"auth_remote_success": 1.0},
        }
        explain_map = {0: [], 1: []}
        self.engine._apply_geo_continuity_sparse(df, signal_map, explain_map, carried_state={})
        self.assertNotIn("new_city", signal_map.get(1, {}))

    def test_new_city_same_country(self):
        """City change within the same country should still emit new_city."""
        df = self._build_geo_df(
            actors=["alice", "alice", "alice"],
            ips=["1.1.1.1", "2.2.2.2", "3.3.3.3"],
            countries=["US", "US", "US"],
            asns=["64500", "64500", "64500"],
            cities=["New York", "Chicago", "Los Angeles"],
            timestamps=["2024-06-16T10:00:00Z", "2024-06-16T11:00:00Z", "2024-06-16T12:00:00Z"],
        )
        signal_map = {
            0: {"auth_remote_success": 1.0},
            1: {"auth_remote_success": 1.0},
            2: {"auth_remote_success": 1.0},
        }
        explain_map = {0: [], 1: [], 2: []}
        self.engine._apply_geo_continuity_sparse(df, signal_map, explain_map, carried_state={})
        self.assertEqual(signal_map[1].get("new_city"), 1.0)
        self.assertEqual(signal_map[2].get("new_city"), 1.0)
        # No new_country because all US
        self.assertNotIn("new_country", signal_map.get(1, {}))
        self.assertNotIn("new_country", signal_map.get(2, {}))

    def test_new_city_cross_country(self):
        """City change across countries should emit both new_city and new_country."""
        df = self._build_geo_df(
            actors=["alice", "alice"],
            ips=["203.0.113.10", "198.51.100.44"],
            countries=["GB", "DE"],
            asns=["64500", "64501"],
            cities=["London", "Berlin"],
            timestamps=["2024-06-16T10:00:00Z", "2024-06-16T12:00:00Z"],
        )
        signal_map = {
            0: {"auth_remote_success": 1.0},
            1: {"auth_remote_success": 1.0},
        }
        explain_map = {0: [], 1: []}
        self.engine._apply_geo_continuity_sparse(df, signal_map, explain_map, carried_state={})
        self.assertEqual(signal_map[1].get("new_city"), 1.0)
        self.assertEqual(signal_map[1].get("new_country"), 1.0)
        self.assertEqual(signal_map[1].get("boundary_crossing"), 1.0)

    def test_new_city_per_actor_isolation(self):
        """City tracking should be per-actor — alice's cities don't affect bob."""
        df = self._build_geo_df(
            actors=["alice", "bob", "alice", "bob"],
            ips=["1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4"],
            countries=["GB", "GB", "GB", "GB"],
            asns=["64500", "64500", "64500", "64500"],
            cities=["London", "London", "Manchester", "Manchester"],
            timestamps=[
                "2024-06-16T10:00:00Z", "2024-06-16T10:01:00Z",
                "2024-06-16T11:00:00Z", "2024-06-16T11:01:00Z",
            ],
        )
        signal_map = {
            0: {"auth_remote_success": 1.0},
            1: {"auth_remote_success": 1.0},
            2: {"auth_remote_success": 1.0},
            3: {"auth_remote_success": 1.0},
        }
        explain_map = {0: [], 1: [], 2: [], 3: []}
        self.engine._apply_geo_continuity_sparse(df, signal_map, explain_map, carried_state={})
        # Both actors see new_city on their second event
        self.assertEqual(signal_map[2].get("new_city"), 1.0)  # alice: London→Manchester
        self.assertEqual(signal_map[3].get("new_city"), 1.0)  # bob: London→Manchester

    def test_new_city_null_city_skipped(self):
        """Null/empty city values should not trigger new_city."""
        df = self._build_geo_df(
            actors=["alice", "alice"],
            ips=["203.0.113.10", "203.0.113.20"],
            countries=["GB", "GB"],
            asns=["64500", "64500"],
            cities=["London", None],
            timestamps=["2024-06-16T10:00:00Z", "2024-06-16T12:00:00Z"],
        )
        signal_map = {
            0: {"auth_remote_success": 1.0},
            1: {"auth_remote_success": 1.0},
        }
        explain_map = {0: [], 1: []}
        self.engine._apply_geo_continuity_sparse(df, signal_map, explain_map, carried_state={})
        self.assertNotIn("new_city", signal_map.get(1, {}))

    def test_new_city_no_auth_success_no_signal(self):
        """Events without auth_remote_success should not trigger city tracking."""
        df = self._build_geo_df(
            actors=["alice", "alice"],
            ips=["203.0.113.10", "203.0.113.20"],
            countries=["GB", "GB"],
            asns=["64500", "64500"],
            cities=["London", "Manchester"],
            timestamps=["2024-06-16T10:00:00Z", "2024-06-16T12:00:00Z"],
        )
        signal_map = {0: {}, 1: {}}  # No auth_remote_success
        explain_map = {0: [], 1: []}
        self.engine._apply_geo_continuity_sparse(df, signal_map, explain_map, carried_state={})
        self.assertNotIn("new_city", signal_map.get(1, {}))

    def test_new_city_explain_structure(self):
        """new_city explain entry should have correct structure and evidence."""
        df = self._build_geo_df(
            actors=["alice", "alice"],
            ips=["203.0.113.10", "203.0.113.20"],
            countries=["GB", "GB"],
            asns=["64500", "64500"],
            cities=["London", "Manchester"],
            timestamps=["2024-06-16T10:00:00Z", "2024-06-16T12:00:00Z"],
        )
        signal_map = {
            0: {"auth_remote_success": 1.0},
            1: {"auth_remote_success": 1.0},
        }
        explain_map = {0: [], 1: []}
        self.engine._apply_geo_continuity_sparse(df, signal_map, explain_map, carried_state={})
        city_explains = [e for e in explain_map[1] if e.get("rule_id") == "NEW_CITY"]
        self.assertEqual(len(city_explains), 1)
        expl = city_explains[0]
        self.assertEqual(expl["confidence"], "medium")
        self.assertEqual(expl["evidence_type"], "contextual")
        self.assertIn("new_city", expl["signals"])
        self.assertEqual(expl["evidence"]["geo_city_name"], "Manchester")
        self.assertEqual(expl["evidence"]["previous_cities"], "London")

    def test_new_city_carried_state(self):
        """City state should carry across partitions."""
        state = {}
        # Partition 1
        df1 = self._build_geo_df(
            actors=["alice"],
            ips=["203.0.113.10"],
            countries=["GB"],
            asns=["64500"],
            cities=["London"],
            timestamps=["2024-06-16T10:00:00Z"],
        )
        signal_map1 = {0: {"auth_remote_success": 1.0}}
        explain_map1 = {0: []}
        self.engine._apply_geo_continuity_sparse(df1, signal_map1, explain_map1, carried_state=state)

        # Partition 2 — Manchester should be new_city
        df2 = self._build_geo_df(
            actors=["alice"],
            ips=["203.0.113.20"],
            countries=["GB"],
            asns=["64500"],
            cities=["Manchester"],
            timestamps=["2024-06-16T14:00:00Z"],
        )
        signal_map2 = {0: {"auth_remote_success": 1.0}}
        explain_map2 = {0: []}
        self.engine._apply_geo_continuity_sparse(df2, signal_map2, explain_map2, carried_state=state)
        self.assertEqual(signal_map2[0].get("new_city"), 1.0)

    def test_no_geo_city_column_no_crash(self):
        """If geo_city_name column is absent, new_city should not crash."""
        df = pd.DataFrame(
            {
                "actor_principal": ["alice", "alice"],
                "src_ip": ["203.0.113.10", "198.51.100.44"],
                "geo_country_iso": ["GB", "CN"],
                "geo_asn": ["64500", "64501"],
            },
            index=pd.to_datetime(["2024-06-16T10:00:00Z", "2024-06-16T12:00:00Z"]),
        )
        signal_map = {
            0: {"auth_remote_success": 1.0},
            1: {"auth_remote_success": 1.0},
        }
        explain_map = {0: [], 1: []}
        # Should not raise
        self.engine._apply_geo_continuity_sparse(df, signal_map, explain_map, carried_state={})
        # Country/ASN should still work
        self.assertEqual(signal_map[1].get("new_country"), 1.0)
        # new_city should not be emitted
        self.assertNotIn("new_city", signal_map.get(1, {}))


if __name__ == "__main__":
    unittest.main()
