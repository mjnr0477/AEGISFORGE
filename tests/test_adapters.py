import unittest
from datetime import datetime, timedelta, timezone
from types import MappingProxyType

from aegisforge.adapters import (
    AdapterApprovalRequired,
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
        oversized = {"mode": ["x" * 8192 for _ in range(9)]}
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

    def test_simulation_resource_identity_has_no_public_setter(self):
        with self.assertRaises(AttributeError):
            self.simulator.resource_id = "another-resource"

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
