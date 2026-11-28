# AegisForge adapter contract

AegisForge adapters are trusted, explicitly registered integrations behind the Authority Kernel. Registration is an allowlist, not a plugin loader. The registry does not discover Python modules, import third-party plugins, execute shell commands, or make network requests.

## Required operation contract

Every adapter has:
- A stable **adapter_id** and a short description.
- An explicit mapping of operation names to OperationSpec values.
- A validator for each operation's argument object.
- One capability and a truthful mutates classification per operation.
- A resource resolver that derives the exact resource identifier from the same validated argument object passed to the operation handler.
- Exactly one handler for every declared operation, with no undeclared handlers.

The registry checks that each capability exists in the Authority Kernel and that OperationSpec.mutates matches the capability catalogue. Unknown capabilities and mismatched mutation classifications are rejected at registration.

## Input and scope rules

AdapterRegistry.invoke accepts a plain Python dict containing JSON data only. It copies the data into deeply immutable mappings and tuples before validation, scope resolution, authorization, or handler execution. Custom Python objects, non-finite floats, integers outside signed 64-bit range, invalid UTF-8 strings, and excessive nesting, item counts, string lengths, or encoded payload size are rejected.

The resource resolver runs on this immutable copy. The handler receives that same copy, not the caller's original object. This prevents callers or validators from changing a nested resource selector between scope calculation and execution.

A resolver must bind every target selector that can affect the handler's side effects. Do not derive a grant from one target ID while allowing the handler to act on a different hidden/default target. Prefer stable resource IDs, not display names or mutable labels. Keep each tenant, workspace, service, or device scope exact; do not add wildcard grants or infer parent access.

Example contract only (not a live connector):

~~~python
from aegisforge.adapters import AdapterSpec, OperationSpec

spec = AdapterSpec(
    adapter_id="inventory-demo",
    description="Read one explicitly scoped inventory record.",
    operations={
        "inspect": OperationSpec(
            name="inspect",
            capability="service.inspect",
            mutates=False,
            validate=validate_inspect_arguments,
        ),
    },
    resource_resolver=lambda operation, args: (
        f"inventory:{args['tenant_id']}:{args['record_id']}"
    ),
)
~~~

The matching handler must use the same tenant_id and record_id values. This example intentionally omits authentication and a real backend.

## Mutating operations

Use separate, narrowly defined operations and capabilities. A read operation must not be classified as mutating; a state-changing operation must not be classified as read-only. Mutating operations require both:
1. An active exact-scope grant for the authenticated subject and capability.
2. A short-lived, exact-scope, single-use approval token issued only after the host authenticates the approver and records explicit consent.

The approval token is a separate argument to invoke, not part of the adapter payload. The host's approval UI should show the specific operation, target resource, and meaningful parameters (with secrets redacted) before asking for consent. Never expose AuthorityKernel.issue_approval directly to an unauthenticated client. The demo's fixed subject/approver labels are illustrative only.

Do not build a generic run_command, arbitrary URL fetch, unrestricted filesystem, or generic device-control operation as an adapter. A real integration needs a reviewed set of narrow operations, explicit resource IDs, bounded input/output, authentication, timeout behavior, and documented failure semantics.

## Handler behavior

Adapters are trusted application code; the registry does not sandbox Python handlers. Keep handlers small and bounded. A handler must not silently switch resource scope, execute user-supplied code, or perform unreviewed side effects. For network-backed adapters added later, use verified TLS, explicit destination allowlists, bounded connect/read timeouts, and operation-specific retry rules. Never blindly retry a non-idempotent mutation.

The registry performs authorization immediately before the handler. Authorization is fail-closed if the audit log cannot be verified or appended. The Authority Kernel's ledger records approval issuance and authorization decisions; in this version it does not record whether the adapter handler later completed, failed, or timed out. Do not interpret an allowed decision as proof of successful execution.

## Current implementation boundary

The bundled SimulationAdapter runs entirely in memory. It supports status inspection, an increment-only simulated restart counter, and a simulated operating mode. Its resource identity is immutable after construction. Mutations use separate service.restart and device.control capabilities and require one-time approval. It has no access to live services, hardware, the host operating system, or a network.

A future production adapter must have its own positive and negative tests for exact resource isolation, missing/expired grants, approval reuse, malformed inputs, handler errors, timeouts, and side effects. Do not register a live integration merely because it satisfies the Python interface.
