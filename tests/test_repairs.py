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
        from aegisforge.repairs import RepairProposal
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp); source=root/"app.py"
            original="import requests\nrequests.get(url, verify=False)\n"
            source.write_text(original, encoding="utf-8")
            proposal=RepairProposal("app.py",("AF-PY-003",),original,original,"")
            with self.assertRaisesRegex(RuntimeError,"verification failed"):
                apply_repairs(root,[proposal])
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
