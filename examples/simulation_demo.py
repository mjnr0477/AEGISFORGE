"""Interactive, local-only demonstration of AegisForge's simulation adapter.

This example demonstrates consent prompts, not authentication. The fixed subject
and approver labels below are demo placeholders. Real hosts must authenticate
both identities before requesting a one-time approval from AuthorityKernel.
"""
from datetime import datetime, timedelta, timezone

from aegisforge.adapters import AdapterApprovalRequired, AdapterRegistry, SimulationAdapter
from aegisforge.authority import AuthorityKernel, DEFAULT_CAPABILITIES, Grant


def main() -> int:
    simulator = SimulationAdapter()
    resource = f"simulation:{simulator.resource_id}"
    subject = "demo-operator"
    expires_at = datetime.now(timezone.utc) + timedelta(hours=1)
    grants = [
        Grant(subject, capability, resource, expires_at)
        for capability in ("service.inspect", "service.restart", "device.control")
    ]
    authority = AuthorityKernel(
        DEFAULT_CAPABILITIES,
        grants,
        audit_path=".aegisforge/simulation-audit.jsonl",
    )
    registry = AdapterRegistry(authority)
    registry.register(simulator.spec(), simulator.handlers())

    status = registry.invoke(
        adapter_id="simulation",
        operation_name="inspect_status",
        subject=subject,
        arguments={},
    )
    print("Initial simulated state:", status)

    demonstrations = (
        ("restart", "service.restart", {}),
        ("set_mode", "device.control", {"mode": "maintenance"}),
    )
    for operation, capability, arguments in demonstrations:
        prompt = f"Approve simulated {operation} on {resource}? [y/N] "
        if input(prompt).strip().lower() != "y":
            print(f"Skipped {operation}.")
            continue
        token = authority.issue_approval(
            subject=subject,
            capability=capability,
            resource=resource,
            approver="demo-console-approver",
        )
        try:
            status = registry.invoke(
                adapter_id="simulation",
                operation_name=operation,
                subject=subject,
                arguments=arguments,
                approval_token=token,
            )
        except AdapterApprovalRequired as exc:
            print(f"Denied {operation}: {exc}")
            continue
        print(f"Simulated {operation} result:", status)

    print("Audit decisions recorded in .aegisforge/simulation-audit.jsonl")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
