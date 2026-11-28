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

The validator and resource resolver run before authorization, so both must be deterministic, local, and side-effect-free: no file writes, network requests, subprocesses, external mutations, or approval prompts. The resource resolver runs on the immutable copy. The handler receives that same copy, not the caller's original object. This prevents callers or validators from changing a nested resource selector between scope calculation and execution. The handler is the only stage allowed to perform the operation, and it is called only after an allow decision.

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

Adapters are trusted application code; the registry does not sandbox Python validators, resource resolvers, or handlers. Keep validators and resolvers pure, and keep handlers small and bounded. A handler must not silently switch resource scope, execute user-supplied code, or perform unreviewed side effects. For network-backed adapters added later, use verified TLS, explicit destination allowlists, bounded connect/read timeouts, and operation-specific retry rules. Never blindly retry a non-idempotent mutation.

The adapter registry and the AuthorityKernel-integrated local ToolRegistry both record an execution_started event after an allow decision and before calling the handler, then append an execution_result event with succeeded, failed, or timed_out, duration, and exception type (never exception text or handler output). Each start is linked to one allowed authorization sequence and may have only one result. If the start event cannot be appended, the handler is not called. If the result event cannot be appended, the caller receives AdapterExecutionAuditError or ToolExecutionAuditError and must reconcile the external state before retrying. A handler exception may occur after partial side effects; failed does not imply rolled back. A Python TimeoutError is recorded as timed_out. The registry does not forcibly interrupt handlers or impose a deadline; each real integration must configure bounded timeouts in its own client and transport. A process crash, forced termination, or result-log failure can leave a start without a result, which means outcome unknown and requires reconciliation. The audit record is operational evidence, not proof that an external system actually applied the operation.

## Current implementation boundary

The bundled SimulationAdapter runs entirely in memory. It supports status inspection, an increment-only simulated restart counter, and a simulated operating mode. Its resource identity is immutable after construction. Mutations use separate service.restart and device.control capabilities and require one-time approval. It has no access to live services, hardware, the host operating system, or a network.

A future production adapter must have its own positive and negative tests for exact resource isolation, missing/expired grants, approval reuse, malformed inputs, handler errors, timeouts, and side effects. Do not register a live integration merely because it satisfies the Python interface.
