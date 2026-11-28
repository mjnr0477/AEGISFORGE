import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

from datetime import datetime, timedelta, timezone

from aegisforge.authority import AuthorityKernel, CapabilitySpec, Grant, DEFAULT_CAPABILITIES
from aegisforge.autonomy import (
    ActionTool,
    ToolPermissionError,
    ToolRegistry,
    create_local_registry,
    run_audit_mission,
)

class ToolRegistryTests(unittest.TestCase):
    def test_read_only_tool_runs_without_mutation_approval(self):
        registry=ToolRegistry()
        registry.register(ActionTool("read_project","Read-only example",lambda value:value.upper()))
        self.assertEqual(registry.call("read_project","hello"),"HELLO")

    def test_mutating_tool_requires_explicit_approval(self):
        registry=ToolRegistry()
        registry.register(ActionTool("change_project","Writes local files",lambda:"changed",mutates=True))
        with self.assertRaisesRegex(ToolPermissionError,"explicit approval"):
            registry.call("change_project")
        self.assertEqual(registry.call("change_project",approve_mutation=True),"changed")

    def test_authorized_read_only_tool_runs_only_with_exact_grant(self):
        now = datetime.now(timezone.utc)
        authority = AuthorityKernel(
            [CapabilitySpec("project.inspect", "Inspect project")],
            [Grant("operator", "project.inspect", "project:/repo", now + timedelta(minutes=5))],
        )
        registry = ToolRegistry()
        registry.register(ActionTool(
            "inspect_project", "Read-only example", lambda value: "READY",
            mutates=False, capability="project.inspect",
            scope_resolver=lambda value: f"project:{Path(value).resolve().as_posix()}",
        ))
        self.assertEqual(
            registry.call_authorized(
                "inspect_project", "/repo", authority=authority,
                subject="operator",
            ),
            "READY",
        )
        with self.assertRaises(ToolPermissionError):
            registry.call_authorized(
                "inspect_project", "/other", authority=authority,
                subject="operator",
            )

    def test_authorized_mutation_requires_single_use_approval(self):
        now = datetime.now(timezone.utc)
        authority = AuthorityKernel(
            [CapabilitySpec("project.repair", "Repair project", mutates=True)],
            [Grant("operator", "project.repair", "project:/repo", now + timedelta(minutes=5))],
        )
        registry = ToolRegistry()
        registry.register(ActionTool(
            "repair_project", "Writes project files", lambda target: f"repaired:{target}",
            mutates=True, capability="project.repair",
            scope_resolver=lambda target: f"project:{Path(target).resolve().as_posix()}",
        ))
        with self.assertRaisesRegex(ToolPermissionError, "approval_required"):
            registry.call_authorized(
                "repair_project", "/repo", authority=authority,
                subject="operator",
            )
        token = authority.issue_approval(
            subject="operator", capability="project.repair",
            resource="project:/repo", approver="owner",
        )
        self.assertEqual(
            registry.call_authorized(
                "repair_project", "/repo", authority=authority,
                subject="operator", approval_token=token,
            ),
            "repaired:/repo",
        )
        with self.assertRaisesRegex(ToolPermissionError, "invalid_or_consumed_approval"):
            registry.call_authorized(
                "repair_project", "/repo", authority=authority,
                subject="operator", approval_token=token,
            )

    def test_authorized_call_rejects_tool_capability_mutation_mismatch(self):
        authority = AuthorityKernel([CapabilitySpec("project.inspect", "Read-only")])
        registry = ToolRegistry()
        registry.register(ActionTool(
            "unsafe_tool", "Incorrectly classified", lambda target: None,
            mutates=True, capability="project.inspect",
            scope_resolver=lambda target: f"project:{Path(target).resolve().as_posix()}",
        ))
        with self.assertRaisesRegex(ToolPermissionError, "classification does not match"):
            registry.call_authorized(
                "unsafe_tool", "/repo", authority=authority,
                subject="operator",
            )

    def test_rejects_duplicate_tool_names(self):
        registry=ToolRegistry()
        registry.register(ActionTool("scan","first",lambda:None))
        with self.assertRaisesRegex(ValueError,"already registered"):
            registry.register(ActionTool("scan","second",lambda:None))

    def test_rejects_invalid_tool_names(self):
        registry=ToolRegistry()
        with self.assertRaisesRegex(ValueError,"tool name"):
            registry.register(ActionTool("../write","unsafe",lambda:None))

    def test_tool_catalog_does_not_expose_handlers(self):
        registry=ToolRegistry()
        registry.register(ActionTool("inspect","Read-only inspection",lambda:None))
        catalog=registry.describe()
        self.assertEqual(catalog,[{"name":"inspect","description":"Read-only inspection","mutates":False}])
        self.assertNotIn("handler",catalog[0])

class MissionRunnerTests(unittest.TestCase):
    def test_preview_mission_scans_and_plans_without_mutating(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            source=root/"settings.env"
            original="DEBUG=true\n"
            source.write_text(original,encoding="utf-8")
            result=run_audit_mission(root)
            self.assertEqual(result.status,"approval_required")
            self.assertIsNotNone(result.project_map)
            self.assertEqual(source.read_text(encoding="utf-8"),original)
            self.assertEqual(len(result.proposed_repairs),1)
            self.assertIn("map_project",[step.name for step in result.steps])
            self.assertEqual(result.steps[-1].status,"pending_approval")
            self.assertIn("scan_project",[step.name for step in result.steps])
            self.assertIn("propose_repairs",[step.name for step in result.steps])

    def test_mission_separates_supported_repairs_from_manual_review(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            (root/"settings.env").write_text("DEBUG=true\n",encoding="utf-8")
            (root/"app.py").write_text(
                "def endpoint():\n"
                "    user = request.args.get('code')\n"
                "    eval(user)\n",
                encoding="utf-8",
            )
            result=run_audit_mission(root)
            manual_ids={finding.rule_id for finding in result.manual_review_findings}
            initial_ids={finding.rule_id for finding in result.initial_findings}
            self.assertIn("AF-CFG-001",initial_ids)
            self.assertIn("AF-FLOW-001",initial_ids)
            self.assertNotIn("AF-CFG-001",manual_ids)
            self.assertIn("AF-FLOW-001",manual_ids)

    def test_apply_mission_requires_explicit_flag_and_verifies_changes(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            source=root/"settings.env"
            source.write_text("DEBUG=true\n",encoding="utf-8")
            result=run_audit_mission(root,apply_supported_repairs=True)
            self.assertEqual(result.status,"completed")
            self.assertEqual(source.read_text(encoding="utf-8"),"DEBUG=false\n")
            self.assertEqual(len(result.backups),1)
            self.assertEqual(result.final_findings,[])
            self.assertIn("verify_changes",[step.name for step in result.steps])

    def test_failed_repair_keeps_supported_finding_in_manual_review(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            source=root/"settings.env"
            source.write_text("DEBUG=true\n",encoding="utf-8")
            with patch("aegisforge.autonomy.apply_repairs",side_effect=RuntimeError("simulated repair failure")):
                result=run_audit_mission(root,apply_supported_repairs=True)
        self.assertEqual(result.status,"failed")
        self.assertIn("AF-CFG-001",{finding.rule_id for finding in result.manual_review_findings})

    def test_clean_project_completes_without_repair_approval(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            (root/"safe.py").write_text("print('hello')\n",encoding="utf-8")
            result=run_audit_mission(root)
            self.assertEqual(result.status,"completed")
            self.assertEqual(result.proposed_repairs,[])
            self.assertEqual(result.errors,[])

    def test_incomplete_scan_stops_before_repair_planning(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            (root/"too-large.py").write_bytes(b"x"*(1_000_001))
            result=run_audit_mission(root)
            self.assertEqual(result.status,"incomplete")
            self.assertIn("scan_project",[step.name for step in result.steps])
            skipped=[step for step in result.steps if step.name=="propose_repairs"]
            self.assertEqual(len(skipped),1)
            self.assertEqual(skipped[0].status,"skipped")

    def test_json_report_contains_plan_and_findings(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            (root/"settings.env").write_text("DEBUG=true\n",encoding="utf-8")
            (root/"app.py").write_text("def greet():\n    return 'hello'\n",encoding="utf-8")
            result=run_audit_mission(root)
            payload=result.to_dict()
            self.assertEqual(payload["mission"],"local_security_audit")
            self.assertEqual(payload["status"],"approval_required")
            self.assertEqual(payload["project_map"]["summary"]["modules"],1)
            self.assertEqual(payload["proposed_repairs"][0]["rule_ids"],["AF-CFG-001"])
            self.assertIn("manual_review_findings",payload)
            self.assertEqual(payload["initial_findings"][0]["rule_id"],"AF-CFG-001")

    def test_project_map_warning_stops_mission_before_repair_planning(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            source=root/"broken.py"
            source.write_text("def broken(:\n",encoding="utf-8")
            result=run_audit_mission(root)
            self.assertEqual(result.status,"incomplete")
            self.assertIsNotNone(result.project_map)
            self.assertTrue(any("syntax error" in warning for warning in result.project_map.warnings))
            proposal_steps=[step for step in result.steps if step.name=="propose_repairs"]
            self.assertEqual(len(proposal_steps),1)
            self.assertEqual(proposal_steps[0].status,"skipped")

    def test_authorized_mission_preview_uses_exact_project_grant(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "settings.env"
            source.write_text("DEBUG=true\n", encoding="utf-8")
            resource = f"project:{root.resolve().as_posix()}"
            now = datetime.now(timezone.utc)
            authority = AuthorityKernel(
                DEFAULT_CAPABILITIES,
                [Grant("operator", "project.inspect", resource, now + timedelta(minutes=5))],
            )
            result = run_audit_mission(root, authority=authority, subject="operator")
            self.assertEqual(result.status, "approval_required")
            self.assertEqual(source.read_text(encoding="utf-8"), "DEBUG=true\n")
            self.assertEqual(len(result.proposed_repairs), 1)
            self.assertTrue(all(
                entry["event"]["resource"] == resource
                for entry in authority.audit_entries()
                if entry["event"]["type"] == "authorization_decision"
            ))

    def test_authorized_mission_apply_requires_single_use_approval(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "settings.env"
            source.write_text("DEBUG=true\n", encoding="utf-8")
            resource = f"project:{root.resolve().as_posix()}"
            now = datetime.now(timezone.utc)
            authority = AuthorityKernel(
                DEFAULT_CAPABILITIES,
                [
                    Grant("operator", "project.inspect", resource, now + timedelta(minutes=5)),
                    Grant("operator", "project.repair", resource, now + timedelta(minutes=5)),
                ],
            )
            token = authority.issue_approval(
                subject="operator", capability="project.repair",
                resource=resource, approver="owner",
            )
            result = run_audit_mission(
                root, apply_supported_repairs=True, authority=authority,
                subject="operator", approval_token=token,
            )
            self.assertEqual(result.status, "completed")
            self.assertEqual(source.read_text(encoding="utf-8"), "DEBUG=false\n")
            self.assertEqual(len(result.backups), 1)
            self.assertEqual(result.final_findings, [])

    def test_authorized_mission_missing_approval_does_not_change_files(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "settings.env"
            source.write_text("DEBUG=true\n", encoding="utf-8")
            resource = f"project:{root.resolve().as_posix()}"
            now = datetime.now(timezone.utc)
            authority = AuthorityKernel(
                DEFAULT_CAPABILITIES,
                [
                    Grant("operator", "project.inspect", resource, now + timedelta(minutes=5)),
                    Grant("operator", "project.repair", resource, now + timedelta(minutes=5)),
                ],
            )
            result = run_audit_mission(
                root, apply_supported_repairs=True, authority=authority, subject="operator"
            )
            self.assertEqual(result.status, "approval_required")
            self.assertEqual(result.steps[-1].status, "pending_approval")
            self.assertEqual(source.read_text(encoding="utf-8"), "DEBUG=true\n")
            self.assertIsNotNone(result.final_scan)

    def test_authorized_mission_denies_repair_without_repair_grant(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "settings.env"
            source.write_text("DEBUG=true\n", encoding="utf-8")
            resource = f"project:{root.resolve().as_posix()}"
            now = datetime.now(timezone.utc)
            authority = AuthorityKernel(
                DEFAULT_CAPABILITIES,
                [Grant("operator", "project.inspect", resource, now + timedelta(minutes=5))],
            )
            result = run_audit_mission(
                root, apply_supported_repairs=True, authority=authority, subject="operator"
            )
            self.assertEqual(result.status, "failed")
            self.assertEqual(source.read_text(encoding="utf-8"), "DEBUG=true\n")
            self.assertIn("no_active_exact_scope_grant", " ".join(result.errors))
            self.assertIn("AF-CFG-001", {item.rule_id for item in result.manual_review_findings})

    def test_authorized_mission_denies_different_target_even_when_caller_claims_other_scope(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "settings.env"
            source.write_text("DEBUG=true\n", encoding="utf-8")
            now = datetime.now(timezone.utc)
            authority = AuthorityKernel(
                DEFAULT_CAPABILITIES,
                [Grant("operator", "project.inspect", "project:/different-project", now + timedelta(minutes=5))],
            )
            result = run_audit_mission(root, authority=authority, subject="operator")
            self.assertEqual(result.status, "failed")
            self.assertIsNone(result.initial_scan)
            self.assertIn("no_active_exact_scope_grant", " ".join(result.errors))
            self.assertEqual(source.read_text(encoding="utf-8"), "DEBUG=true\n")

    def test_authorized_tool_requires_resource_scope_resolver(self):
        now = datetime.now(timezone.utc)
        authority = AuthorityKernel(
            [CapabilitySpec("project.inspect", "Inspect project")],
            [Grant("operator", "project.inspect", "project:/repo", now + timedelta(minutes=5))],
        )
        registry = ToolRegistry()
        registry.register(ActionTool(
            "unbound_inspector", "Unbound", lambda: "ran",
            capability="project.inspect",
        ))
        with self.assertRaisesRegex(ToolPermissionError, "resource scope resolver"):
            registry.call_authorized(
                "unbound_inspector", authority=authority, subject="operator",
            )

    def test_custom_registry_mutation_gate_is_used(self):
        registry=create_local_registry()
        catalog=registry.describe()
        repair=next(item for item in catalog if item["name"]=="apply_supported_repairs")
        self.assertTrue(repair["mutates"])

if __name__ == "__main__":
    unittest.main()
