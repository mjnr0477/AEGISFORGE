"""Explicit, authority-gated adapter contracts and a deterministic simulator.

Adapters are registered by trusted application code. This module performs no
plugin discovery, dynamic imports, shell execution, or network I/O.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from threading import RLock
from typing import Any, Callable, Mapping

from .authority import AuthorityKernel

IDENTIFIER_RE = re.compile(r"^[a-z][a-z0-9_-]{1,63}$")


class AdapterError(RuntimeError):
    """Base error for invalid adapter definitions or invocation."""


class AdapterNotFound(AdapterError):
    """Raised when an adapter or operation is not explicitly registered."""


class AdapterPermissionDenied(PermissionError):
    """Raised when the authority kernel denies an adapter operation."""


class AdapterApprovalRequired(AdapterPermissionDenied):
    """Raised when a mutation has a grant but no valid one-time approval."""


@dataclass(frozen=True, slots=True)
class OperationSpec:
    name: str
    capability: str
    mutates: bool
    validate: Callable[[Mapping[str, Any]], None]

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not IDENTIFIER_RE.fullmatch(self.name):
            raise ValueError("operation name must be a lowercase identifier")
        if not isinstance(self.capability, str) or not self.capability:
            raise ValueError("operation capability must not be empty")
        if not isinstance(self.mutates, bool):
            raise ValueError("operation mutates must be boolean")
        if not callable(self.validate):
            raise TypeError("operation validator must be callable")


@dataclass(frozen=True, slots=True)
class AdapterSpec:
    adapter_id: str
    description: str
    operations: Mapping[str, OperationSpec]
    resource_resolver: Callable[[str, Mapping[str, Any]], str]

    def __post_init__(self) -> None:
        if not isinstance(self.adapter_id, str) or not IDENTIFIER_RE.fullmatch(self.adapter_id):
            raise ValueError("adapter_id must be a lowercase identifier")
        if not isinstance(self.description, str) or not self.description.strip():
            raise ValueError("adapter description must not be empty")
        if not callable(self.resource_resolver):
            raise TypeError("adapter resource_resolver must be callable")
        if not isinstance(self.operations, Mapping) or not self.operations:
            raise ValueError("adapter must declare at least one operation")
        copied = dict(self.operations)
        for key, operation in copied.items():
            if key != operation.name or not isinstance(operation, OperationSpec):
                raise ValueError("operation keys must match OperationSpec names")
        object.__setattr__(self, "operations", copied)


@dataclass(frozen=True, slots=True)
class _RegisteredAdapter:
    spec: AdapterSpec
    handlers: Mapping[str, Callable[[Mapping[str, Any]], Any]]


class AdapterRegistry:
    """Explicit adapter allowlist; every invocation is authorized at this boundary."""

    def __init__(self, authority: AuthorityKernel) -> None:
        if not isinstance(authority, AuthorityKernel):
            raise TypeError("authority must be an AuthorityKernel")
        self._authority = authority
        self._adapters: dict[str, _RegisteredAdapter] = {}
        self._lock = RLock()

    def register(
        self,
        spec: AdapterSpec,
        handlers: Mapping[str, Callable[[Mapping[str, Any]], Any]],
    ) -> None:
        if not isinstance(spec, AdapterSpec):
            raise TypeError("spec must be an AdapterSpec")
        if not isinstance(handlers, Mapping) or set(handlers) != set(spec.operations):
            raise ValueError("handlers must exactly match the declared operations")
        for name, handler in handlers.items():
            if not callable(handler):
                raise TypeError(f"handler for {name} must be callable")
            operation = spec.operations[name]
            mutates = self._authority.capability_is_mutating(operation.capability)
            if mutates is None:
                raise ValueError(f"unknown capability: {operation.capability}")
            if mutates != operation.mutates:
                raise ValueError(f"operation mutation classification conflicts with {operation.capability}")
        with self._lock:
            if spec.adapter_id in self._adapters:
                raise ValueError(f"adapter already registered: {spec.adapter_id}")
            self._adapters[spec.adapter_id] = _RegisteredAdapter(spec, dict(handlers))

    def catalog(self) -> list[dict[str, Any]]:
        """Return metadata only; never expose handlers or executable objects."""
        with self._lock:
            return [
                {
                    "adapter_id": item.spec.adapter_id,
                    "description": item.spec.description,
                    "operations": [
                        {
                            "name": op.name,
                            "capability": op.capability,
                            "mutates": op.mutates,
                        }
                        for op in item.spec.operations.values()
                    ],
                }
                for item in self._adapters.values()
            ]

    def invoke(
        self,
        *,
        adapter_id: str,
        operation_name: str,
        subject: str,
        arguments: Mapping[str, Any],
        approval_token: str | None = None,
    ) -> Any:
        if not isinstance(arguments, Mapping):
            raise TypeError("arguments must be a mapping")
        with self._lock:
            registered = self._adapters.get(adapter_id)
        if registered is None:
            raise AdapterNotFound(f"unknown adapter: {adapter_id}")
        operation = registered.spec.operations.get(operation_name)
        if operation is None:
            raise AdapterNotFound(f"unknown operation: {adapter_id}.{operation_name}")
        safe_arguments = dict(arguments)
        operation.validate(safe_arguments)
        resource = registered.spec.resource_resolver(operation_name, safe_arguments)
        if not isinstance(resource, str) or not resource.strip() or len(resource) > 1024:
            raise AdapterError("resource resolver returned an invalid scope")
        decision = self._authority.authorize(
            subject=subject,
            capability=operation.capability,
            resource=resource,
            approval_token=approval_token,
        )
        if not decision.allowed:
            error = AdapterApprovalRequired if decision.reason in {
                "approval_required", "approval_expired", "approval_scope_mismatch",
                "invalid_or_consumed_approval",
            } else AdapterPermissionDenied
            raise error(f"{decision.reason}: {operation.capability} on {resource}")
        return registered.handlers[operation_name](safe_arguments)


def _validate_empty(arguments: Mapping[str, Any]) -> None:
    if arguments:
        raise ValueError("this operation accepts no arguments")


def _validate_mode(arguments: Mapping[str, Any]) -> None:
    if set(arguments) != {"mode"} or arguments["mode"] not in {"normal", "maintenance"}:
        raise ValueError("mode must be exactly 'normal' or 'maintenance'")


class SimulationAdapter:
    """In-memory service/device simulator. It never touches a real system."""

    def __init__(self, resource_id: str = "demo-service") -> None:
        if not isinstance(resource_id, str) or not IDENTIFIER_RE.fullmatch(resource_id):
            raise ValueError("resource_id must be a lowercase identifier")
        self.resource_id = resource_id
        self._mode = "normal"
        self._restart_count = 0
        self._lock = RLock()

    def spec(self) -> AdapterSpec:
        return AdapterSpec(
            adapter_id="simulation",
            description="In-memory demonstration adapter; no external system access.",
            operations={
                "inspect_status": OperationSpec(
                    "inspect_status", "service.inspect", False, _validate_empty
                ),
                "set_mode": OperationSpec(
                    "set_mode", "device.control", True, _validate_mode
                ),
            },
            resource_resolver=self._resource,
        )

    def handlers(self) -> Mapping[str, Callable[[Mapping[str, Any]], Any]]:
        return {
            "inspect_status": self._inspect_status,
            "set_mode": self._set_mode,
        }

    def _resource(self, operation_name: str, arguments: Mapping[str, Any]) -> str:
        del operation_name, arguments
        return f"simulation:{self.resource_id}"

    def _inspect_status(self, arguments: Mapping[str, Any]) -> dict[str, Any]:
        del arguments
        with self._lock:
            return {
                "adapter": "simulation",
                "resource": self.resource_id,
                "mode": self._mode,
                "restart_count": self._restart_count,
                "simulated": True,
            }

    def _set_mode(self, arguments: Mapping[str, Any]) -> dict[str, Any]:
        with self._lock:
            self._mode = str(arguments["mode"])
            return self._inspect_status({})
