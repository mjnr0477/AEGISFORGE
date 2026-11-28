import unittest
from concurrent.futures import ThreadPoolExecutor
from threading import Lock
from datetime import datetime, timedelta, timezone
from types import MappingProxyType
from unittest.mock import patch

from aegisforge.adapters import (
    AdapterApprovalRequired,
    AdapterExecutionAuditError,
    AdapterError,
    AdapterNotFound,
    AdapterPermissionDenied,
    AdapterRegistry,
    AdapterSpec,
    OperationSpec,
    SimulationAdapter,
)
from aegisforge.authority import AuthorityKernel, CapabilitySpec, Grant


class AdapterRegistryTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime(2026, 11, 28, 10, 0, tzinfo=timezone.utc)
        capabilities = (
            CapabilitySpec("service.inspect", "Inspect service"),
            CapabilitySpec("service.restart", "Restart simulated service", mutates=True),
            CapabilitySpec("device.control", "Control simulated device", mutates=True),
        )
        grants = (
            Grant("operator", "service.inspect", "simulation:demo-service", self.now + timedelta(hours=1)),
            Grant("operator", "service.restart", "simulation:demo-service", self.now + timedelta(hours=1)),
            Grant("operator", "device.control", "simulation:demo-service", self.now + timedelta(hours=1)),
        )
        self.kernel = AuthorityKernel(capabilities, grants, clock=lambda: self.now)
        self.registry = AdapterRegistry(self.kernel)
        self.simulator = SimulationAdapter()
        self.registry.register(self.simulator.spec(), self.simulator.handlers())

    def test_read_operation_is_authorized_and_reports_simulation(self):
        status = self.registry.invoke(
            adapter_id="simulation", operation_name="inspect_status",
            subject="operator", arguments={},
        )
        self.assertEqual(status["mode"], "normal")
        self.assertTrue(status["simulated"])
        events = [entry["event"] for entry in self.kernel.audit_entries()]
        self.assertEqual(
            [event["type"] for event in events],
            ["authorization_decision", "execution_started", "execution_result"],
        )
        self.assertEqual(events[-1]["outcome"], "succeeded")
        self.assertEqual(events[-1]["operation"], "inspect_status")
        self.assertEqual(events[-1]["authorization_sequence"], 1)
        self.assertEqual(events[-1]["start_sequence"], 2)
        self.assertGreaterEqual(events[-1]["duration_ms"], 0)

    def test_mutation_requires_one_time_approval_and_changes_only_simulated_state(self):
        with self.assertRaises(AdapterApprovalRequired):
            self.registry.invoke(
                adapter_id="simulation", operation_name="set_mode",
                subject="operator", arguments={"mode": "maintenance"},
            )
        token = self.kernel.issue_approval(
            subject="operator", capability="device.control",
            resource="simulation:demo-service", approver="authenticated-owner",
        )
        status = self.registry.invoke(
            adapter_id="simulation", operation_name="set_mode",
            subject="operator", arguments={"mode": "maintenance"}, approval_token=token,
        )
        self.assertEqual(status["mode"], "maintenance")
        with self.assertRaises(AdapterApprovalRequired):
            self.registry.invoke(
                adapter_id="simulation", operation_name="set_mode",
                subject="operator", arguments={"mode": "normal"}, approval_token=token,
            )

    def test_handler_failure_is_recorded_without_leaking_error_message(self):
        registry = AdapterRegistry(self.kernel)
        spec = AdapterSpec(
            "failure-test", "handler failure audit",
            {"inspect": OperationSpec("inspect", "service.inspect", False,
                                      lambda arguments: None)},
            lambda operation, arguments: "simulation:demo-service",
        )

        def fail(arguments):
            del arguments
            raise RuntimeError("sensitive-token-value")

        registry.register(spec, {"inspect": fail})
        with self.assertRaisesRegex(RuntimeError, "sensitive-token-value"):
            registry.invoke(
                adapter_id="failure-test", operation_name="inspect",
                subject="operator", arguments={},
            )
        events = [entry["event"] for entry in self.kernel.audit_entries()]
        self.assertEqual(events[-1]["type"], "execution_result")
        self.assertEqual(events[-1]["outcome"], "failed")
        self.assertEqual(events[-1]["error_type"], "RuntimeError")
        self.assertNotIn("sensitive-token-value", str(events))

    def test_handler_timeout_is_recorded_as_distinct_outcome(self):
        registry = AdapterRegistry(self.kernel)
        spec = AdapterSpec(
            "timeout-test", "handler timeout audit",
            {"inspect": OperationSpec("inspect", "service.inspect", False,
                                      lambda arguments: None)},
            lambda operation, arguments: "simulation:demo-service",
        )

        def timeout(arguments):
            del arguments
            raise TimeoutError("remote operation may still be running")

        registry.register(spec, {"inspect": timeout})
        with self.assertRaises(TimeoutError):
            registry.invoke(
                adapter_id="timeout-test", operation_name="inspect",
                subject="operator", arguments={},
            )
        result_event = [
            entry["event"] for entry in self.kernel.audit_entries()
            if entry["event"]["type"] == "execution_result"
        ][-1]
        self.assertEqual(result_event["outcome"], "timed_out")
        self.assertEqual(result_event["error_type"], "TimeoutError")

    def test_execution_start_audit_failure_prevents_handler_invocation(self):
        calls = []
        registry = AdapterRegistry(self.kernel)
        spec = AdapterSpec(
            "start-audit-failure", "start audit failure",
            {"inspect": OperationSpec("inspect", "service.inspect", False,
                                      lambda arguments: None)},
            lambda operation, arguments: "simulation:demo-service",
        )
        registry.register(spec, {"inspect": lambda arguments: calls.append(arguments)})
        with patch.object(
            self.kernel, "record_execution_started",
            side_effect=RuntimeError("audit unavailable"),
        ):
            with self.assertRaisesRegex(RuntimeError, "audit unavailable"):
                registry.invoke(
                    adapter_id="start-audit-failure", operation_name="inspect",
                    subject="operator", arguments={},
                )
        self.assertEqual(calls, [])

    def test_result_audit_failure_warns_that_handler_may_have_completed(self):
        token = self.kernel.issue_approval(
            subject="operator", capability="device.control",
            resource="simulation:demo-service", approver="authenticated-owner",
        )
        with patch.object(
            self.kernel, "record_execution_result",
            side_effect=RuntimeError("ledger unavailable"),
        ):
            with self.assertRaisesRegex(AdapterExecutionAuditError, "reconcile before retrying"):
                self.registry.invoke(
                    adapter_id="simulation", operation_name="set_mode",
                    subject="operator", arguments={"mode": "maintenance"},
                    approval_token=token,
                )
        unresolved = self.kernel.pending_executions()
        self.assertEqual(len(unresolved), 1)
        self.assertEqual(unresolved[0]["operation"], "set_mode")
        self.assertEqual(unresolved[0]["status"], "outcome_unknown")
        status = self.registry.invoke(
            adapter_id="simulation", operation_name="inspect_status",
            subject="operator", arguments={},
        )
        self.assertEqual(status["mode"], "maintenance")

    def test_unknown_adapter_and_operation_are_rejected(self):
        with self.assertRaises(AdapterNotFound):
            self.registry.invoke(adapter_id="missing", operation_name="inspect_status",
                                 subject="operator", arguments={})
        with self.assertRaises(AdapterNotFound):
            self.registry.invoke(adapter_id="simulation", operation_name="shell",
                                 subject="operator", arguments={})

    def test_denied_scope_never_calls_handler(self):
        with self.assertRaises(AdapterPermissionDenied):
            self.registry.invoke(adapter_id="simulation", operation_name="inspect_status",
                                 subject="guest", arguments={})

    def test_resource_scope_is_derived_from_actual_operation_arguments(self):
        kernel = AuthorityKernel(
            [CapabilitySpec("service.inspect", "Inspect tenant service")],
            [Grant("operator", "service.inspect", "tenant:alpha",
                   self.now + timedelta(hours=1))],
            clock=lambda: self.now,
        )
        registry = AdapterRegistry(kernel)
        spec = AdapterSpec(
            "tenant-adapter", "scoped tenant test",
            {"inspect": OperationSpec("inspect", "service.inspect", False,
                                      lambda args: None)},
            lambda operation, args: f"tenant:{args['tenant_id']}",
        )
        registry.register(spec, {"inspect": lambda args: args["tenant_id"]})
        with self.assertRaises(AdapterPermissionDenied):
            registry.invoke(adapter_id="tenant-adapter", operation_name="inspect",
                            subject="operator", arguments={"tenant_id": "beta"})
        self.assertEqual(
            registry.invoke(adapter_id="tenant-adapter", operation_name="inspect",
                            subject="operator", arguments={"tenant_id": "alpha"}),
            "alpha",
        )

    def test_unknown_capabilities_are_rejected_at_registration(self):
        registry = AdapterRegistry(self.kernel)
        spec = AdapterSpec(
            "unknown-capability", "test",
            {"inspect": OperationSpec("inspect", "service.delete", False,
                                      lambda args: None)},
            lambda operation, args: "simulation:demo-service",
        )
        with self.assertRaisesRegex(ValueError, "unknown capability"):
            registry.register(spec, {"inspect": lambda args: None})

    def test_mutation_classification_must_match_kernel(self):
        spec = AdapterSpec(
            "wrong-classification", "test",
            {"inspect": OperationSpec("inspect", "service.inspect", True, lambda args: None)},
            lambda operation, args: "simulation:demo-service",
        )
        with self.assertRaisesRegex(ValueError, "mutation classification"):
            self.registry.register(spec, {"inspect": lambda args: None})

    def test_scope_resolver_must_return_valid_exact_resource(self):
        spec = AdapterSpec(
            "bad-scope", "test",
            {"inspect": OperationSpec("inspect", "service.inspect", False, lambda args: None)},
            lambda operation, args: "",
        )
        registry = AdapterRegistry(self.kernel)
        registry.register(spec, {"inspect": lambda args: "should-not-run"})
        with self.assertRaises(AdapterError):
            registry.invoke(adapter_id="bad-scope", operation_name="inspect",
                            subject="operator", arguments={})

    def test_operation_input_validation_runs_before_authorization(self):
        with self.assertRaises(ValueError):
            self.registry.invoke(adapter_id="simulation", operation_name="set_mode",
                                 subject="operator", arguments={"mode": "unsafe"})


    def test_one_time_approval_cannot_be_reused_by_concurrent_calls(self):
        executions = []
        execution_lock = Lock()
        spec = AdapterSpec(
            "concurrent-test", "concurrent one-time approval test",
            {"restart": OperationSpec("restart", "service.restart", True,
                                      lambda arguments: None)},
            lambda operation, arguments: "simulation:demo-service",
        )

        def handler(arguments):
            del arguments
            with execution_lock:
                executions.append("executed")
            return "executed"

        registry = AdapterRegistry(self.kernel)
        registry.register(spec, {"restart": handler})
        token = self.kernel.issue_approval(
            subject="operator", capability="service.restart",
            resource="simulation:demo-service", approver="authenticated-owner",
        )

        def invoke_once():
            try:
                return registry.invoke(
                    adapter_id="concurrent-test", operation_name="restart",
                    subject="operator", arguments={}, approval_token=token,
                )
            except AdapterApprovalRequired:
                return "denied"

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: invoke_once(), range(2)))
        self.assertEqual(results.count("executed"), 1)
        self.assertEqual(results.count("denied"), 1)
        self.assertEqual(executions, ["executed"])

    def test_restart_uses_separate_service_capability_and_single_use_approval(self):
        token = self.kernel.issue_approval(
            subject="operator", capability="service.restart",
            resource="simulation:demo-service", approver="authenticated-owner",
        )
        status = self.registry.invoke(
            adapter_id="simulation", operation_name="restart",
            subject="operator", arguments={}, approval_token=token,
        )
        self.assertEqual(status["restart_count"], 1)
        self.assertTrue(status["simulated"])

    def test_arguments_must_be_bounded_plain_json_data(self):
        class CustomValue:
            pass

        with self.assertRaises(TypeError):
            self.registry.invoke(adapter_id="simulation", operation_name="set_mode",
                                 subject="operator", arguments={"mode": CustomValue()})
        with self.assertRaises(TypeError):
            self.registry.invoke(adapter_id="simulation", operation_name="inspect_status",
                                 subject="operator", arguments=MappingProxyType({}))

    def test_argument_payload_limits_are_enforced(self):
        with self.assertRaises(ValueError):
            self.registry.invoke(adapter_id="simulation", operation_name="set_mode",
                                 subject="operator", arguments={"mode": "x" * 8193})
        nested = {}
        cursor = nested
        for _ in range(18):
            cursor["next"] = {}
            cursor = cursor["next"]
        with self.assertRaises(ValueError):
            self.registry.invoke(adapter_id="simulation", operation_name="set_mode",
                                 subject="operator", arguments={"mode": nested})

    def test_encoded_payload_size_includes_json_string_overhead(self):
        oversized = {"mode": ["x" * 8192 for _ in range(8)]}
        with self.assertRaises(ValueError):
            self.registry.invoke(adapter_id="simulation", operation_name="set_mode",
                                 subject="operator", arguments=oversized)

    def test_non_finite_json_numbers_are_rejected(self):
        with self.assertRaises(ValueError):
            self.registry.invoke(adapter_id="simulation", operation_name="set_mode",
                                 subject="operator", arguments={"mode": float("nan")})

    def test_integer_bounds_and_invalid_unicode_are_rejected(self):
        with self.assertRaises(ValueError):
            self.registry.invoke(adapter_id="simulation", operation_name="set_mode",
                                 subject="operator", arguments={"mode": 1 << 63})
        with self.assertRaises(ValueError):
            self.registry.invoke(adapter_id="simulation", operation_name="set_mode",
                                 subject="operator", arguments={"mode": "\ud800"})

    def test_validator_receives_deeply_immutable_arguments(self):
        def reject_mutation(arguments):
            arguments["nested"]["value"] = "changed"

        spec = AdapterSpec(
            "immutable-test", "test",
            {"inspect": OperationSpec("inspect", "service.inspect", False, reject_mutation)},
            lambda operation, arguments: "simulation:demo-service",
        )
        registry = AdapterRegistry(self.kernel)
        registry.register(spec, {"inspect": lambda arguments: "should-not-run"})
        original = {"nested": {"value": "original"}}
        with self.assertRaises(TypeError):
            registry.invoke(adapter_id="immutable-test", operation_name="inspect",
                            subject="operator", arguments=original)
        self.assertEqual(original["nested"]["value"], "original")

    def test_registered_handlers_are_snapshotted(self):
        registry = AdapterRegistry(self.kernel)
        spec = AdapterSpec(
            "snapshot-test", "test",
            {"inspect": OperationSpec("inspect", "service.inspect", False, lambda args: None)},
            lambda operation, arguments: "simulation:demo-service",
        )
        handlers = {"inspect": lambda arguments: "original"}
        registry.register(spec, handlers)
        handlers["inspect"] = lambda arguments: "replaced"
        result = registry.invoke(adapter_id="snapshot-test", operation_name="inspect",
                                 subject="operator", arguments={})
        self.assertEqual(result, "original")

    def test_simulation_resource_identity_is_immutable(self):
        with self.assertRaises(AttributeError):
            self.simulator.resource_id = "another-resource"
        with self.assertRaises(AttributeError):
            self.simulator._resource_id = "another-resource"
        with self.assertRaises(AttributeError):
            del self.simulator._resource_id
        self.assertEqual(self.simulator.resource_id, "demo-service")

    def test_registration_requires_exact_handler_set_and_catalog_has_no_handlers(self):
        registry = AdapterRegistry(self.kernel)
        with self.assertRaises(ValueError):
            registry.register(self.simulator.spec(), {})
        catalog = self.registry.catalog()
        self.assertEqual(catalog[0]["adapter_id"], "simulation")
        self.assertNotIn("handlers", catalog[0])
        self.assertEqual(
            {item["name"] for item in catalog[0]["operations"]},
            {"inspect_status", "restart", "set_mode"},
        )


if __name__ == "__main__":
    unittest.main()
