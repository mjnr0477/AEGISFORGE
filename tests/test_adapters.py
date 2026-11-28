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
            CapabilitySpec("device.control", "Control simulated device", mutates=True),
        )
        grants = (
            Grant("operator", "service.inspect", "simulation:demo-service", self.now + timedelta(hours=1)),
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

    def test_registration_requires_exact_handler_set_and_catalog_has_no_handlers(self):
        registry = AdapterRegistry(self.kernel)
        with self.assertRaises(ValueError):
            registry.register(self.simulator.spec(), {})
        catalog = self.registry.catalog()
        self.assertEqual(catalog[0]["adapter_id"], "simulation")
        self.assertNotIn("handlers", catalog[0])
        self.assertEqual(
            {item["name"] for item in catalog[0]["operations"]},
            {"inspect_status", "set_mode"},
        )


if __name__ == "__main__":
    unittest.main()
