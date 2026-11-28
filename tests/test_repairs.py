import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from aegisforge.repairs import apply_repairs, propose_repairs

class RepairTests(unittest.TestCase):
    def test_preview_is_read_only_and_proposes_deterministic_repairs(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp); source=root/"settings.py"
            original="DEBUG = True\nimport requests\nrequests.get(url, verify=False)\n"
            source.write_text(original, encoding="utf-8")
            proposals=propose_repairs(root)
            self.assertEqual(source.read_text(encoding="utf-8"), original)
            self.assertEqual(len(proposals), 1)
            self.assertIn("DEBUG = False", proposals[0].replacement)
            self.assertIn("verify=True", proposals[0].replacement)
            self.assertIn("AF-CFG-001", proposals[0].rule_ids)
            self.assertIn("AF-PY-003", proposals[0].rule_ids)

    def test_apply_creates_backup_and_verifies_fix(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp); source=root/"config.env"
            original="DEBUG=true\nKEEP=this\n"
            source.write_text(original, encoding="utf-8")
            backups=apply_repairs(root, propose_repairs(root))
            self.assertEqual(source.read_text(encoding="utf-8"), "DEBUG=false\nKEEP=this\n")
            self.assertEqual(len(backups), 1)
            self.assertEqual(backups[0].read_text(encoding="utf-8"), original)

    def test_rolls_back_when_targeted_finding_remains(self):
        from aegisforge.models import Finding, ScanResult
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp); source=root/"app.py"
            original="import requests\nrequests.get(url, verify=False)\n"
            source.write_text(original, encoding="utf-8")
            proposals=propose_repairs(root)
            remaining=Finding("AF-PY-003","high","TLS verification disabled",
                "An HTTP client disables certificate verification.","app.py",2,1,
                "requests.get(url, verify=False)","Keep verification enabled.","high","CWE-295")
            incomplete=ScanResult(str(root),1,0,[remaining],[])
            with patch("aegisforge.repairs.scan_directory", return_value=incomplete):
                with self.assertRaisesRegex(RuntimeError,"verification failed"):
                    apply_repairs(root,proposals)
            self.assertEqual(source.read_text(encoding="utf-8"),original)
            backups=list((root/".aegisforge"/"backups").rglob("app.py"))
            self.assertTrue(backups)
            self.assertEqual(backups[0].read_text(encoding="utf-8"),original)

    def test_rejects_handcrafted_replacement_not_generated_by_a_supported_rule(self):
        from aegisforge.repairs import RepairProposal
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp); source=root/"config.env"
            original="DEBUG=true\n"; source.write_text(original,encoding="utf-8")
            preview=propose_repairs(root)[0]
            forged=RepairProposal(preview.path,preview.rule_ids,preview.original,
                "ATTACKER_CONTROLLED=true\n",preview.diff)
            with self.assertRaisesRegex(RuntimeError,"not a supported deterministic repair"):
                apply_repairs(root,[forged])
            self.assertEqual(source.read_text(encoding="utf-8"),original)

    def test_rejects_noncanonical_repair_path(self):
        from aegisforge.repairs import RepairProposal
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp); source=root/"config.env"
            original="DEBUG=true\n"; source.write_text(original,encoding="utf-8")
            preview=propose_repairs(root)[0]
            forged=RepairProposal("./"+preview.path,preview.rule_ids,preview.original,
                preview.replacement,preview.diff)
            with self.assertRaisesRegex(RuntimeError,"canonical relative path"):
                apply_repairs(root,[forged])
            self.assertEqual(source.read_text(encoding="utf-8"),original)

    def test_rolls_back_earlier_files_when_later_source_read_becomes_invalid(self):
        from aegisforge import repairs
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            first=root/"a.env"
            second=root/"b.env"
            original_first="DEBUG=true\n"
            original_second="DEBUG=true\n"
            first.write_text(original_first,encoding="utf-8")
            second.write_text(original_second,encoding="utf-8")
            proposals=propose_repairs(root)
            real_read=repairs.read_source_file
            calls=0
            def fail_on_second_write_check(path, max_bytes=1_000_000, *, root=None):
                nonlocal calls
                calls+=1
                # Two reads validate the original snapshots; the third checks a.env
                # immediately before writing; the fourth fails before b.env is written.
                if calls==4:
                    raise ValueError("simulated file grew beyond the read limit")
                return real_read(path,max_bytes,root=root)
            with patch("aegisforge.repairs.read_source_file",side_effect=fail_on_second_write_check):
                with self.assertRaisesRegex(ValueError,"grew beyond the read limit"):
                    apply_repairs(root,proposals)
            self.assertEqual(first.read_text(encoding="utf-8"),original_first)
            self.assertEqual(second.read_text(encoding="utf-8"),original_second)

    def test_rejects_stale_proposal(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp); source=root/"config.env"
            source.write_text("DEBUG=true\n",encoding="utf-8")
            proposals=propose_repairs(root)
            source.write_text("DEBUG=false\nKEEP=changed\n",encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError,"changed since preview"):
                apply_repairs(root,proposals)
            self.assertEqual(source.read_text(encoding="utf-8"),"DEBUG=false\nKEEP=changed\n")

    def test_refuses_backup_symlink_escape(self):
        with tempfile.TemporaryDirectory() as temp, tempfile.TemporaryDirectory() as outside:
            root=Path(temp); source=root/"config.env"
            source.write_text("DEBUG=true\n",encoding="utf-8")
            proposals=propose_repairs(root)
            (root/".aegisforge").symlink_to(Path(outside),target_is_directory=True)
            with self.assertRaisesRegex(RuntimeError,"backup directory.*symlink"):
                apply_repairs(root,proposals)
            self.assertEqual(source.read_text(encoding="utf-8"),"DEBUG=true\n")
            self.assertEqual(list(Path(outside).iterdir()),[])

    def test_rejects_absolute_proposal_path(self):
        from aegisforge.repairs import RepairProposal
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp); source=root/"config.env"
            original="DEBUG=true\n"; source.write_text(original,encoding="utf-8")
            proposal=RepairProposal(str(source.resolve()),("AF-CFG-001",),original,"DEBUG=false\n","")
            with self.assertRaisesRegex(RuntimeError,"must be relative"):
                apply_repairs(root,[proposal])
            self.assertEqual(source.read_text(encoding="utf-8"),original)

    def test_cli_preview_and_apply(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp); source=root/"config.env"
            source.write_text("DEBUG=true\n",encoding="utf-8")
            preview=subprocess.run([sys.executable,"-m","aegisforge","repair",str(root)],capture_output=True,text=True)
            self.assertEqual(preview.returncode,0,preview.stderr)
            self.assertIn("Preview only",preview.stdout)
            self.assertEqual(source.read_text(encoding="utf-8"),"DEBUG=true\n")
            applied=subprocess.run([sys.executable,"-m","aegisforge","repair",str(root),"--apply"],capture_output=True,text=True)
            self.assertEqual(applied.returncode,0,applied.stderr)
            self.assertEqual(source.read_text(encoding="utf-8"),"DEBUG=false\n")
            self.assertIn("Applied and verified",applied.stdout)

if __name__ == "__main__":
    unittest.main()
