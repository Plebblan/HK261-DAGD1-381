"""OpenAPI 3 document loading and transport-neutral operation normalization."""

from __future__ import annotations

import logging
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Mapping

import yaml

from src.common.logging import configure_component_logging, log_context

logger = logging.getLogger(__name__)
_METHODS = {"get", "put", "post", "delete", "options", "head", "patch", "trace"}


class _UniqueKeySafeLoader(yaml.SafeLoader):
    """Safe YAML loader that rejects duplicate keys in source mappings."""

    def construct_mapping(self, node: yaml.MappingNode, deep: bool = False) -> dict[Any, Any]:
        seen: set[Any] = set()
        for key_node, _ in node.value:
            if key_node.tag == "tag:yaml.org,2002:merge":
                continue
            key = self.construct_object(key_node, deep=deep)
            try:
                if key in seen:
                    raise yaml.constructor.ConstructorError(
                        "while constructing a mapping",
                        node.start_mark,
                        f"duplicate key {key!r}",
                        key_node.start_mark,
                    )
                seen.add(key)
            except TypeError:
                pass
        return super().construct_mapping(node, deep=deep)


class SpecLoadError(ValueError):
    """The document is unreadable, invalid, or cannot be normalized safely."""


@dataclass(frozen=True)
class NormalizedOperation:
    """One OpenAPI operation with references resolved where finite."""

    operation_id: str
    method: str
    route_template: str
    parameters: tuple[dict[str, Any], ...] = ()
    request_body: dict[str, Any] | None = None
    response_schemas: dict[str, dict[str, Any]] = field(default_factory=dict)
    responses: dict[str, Any] = field(default_factory=dict)
    servers: tuple[dict[str, Any], ...] = ()
    security: tuple[dict[str, list[str]], ...] | None = None
    tags: tuple[str, ...] = ()
    summary: str | None = None
    description: str | None = None
    deprecated: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable mapping for downstream modules."""
        return asdict(self)


@dataclass(frozen=True)
class NormalizedSpec:
    """Normalized OpenAPI document summary and its ordered operations."""

    source: str
    openapi: str
    info: dict[str, Any]
    servers: tuple[dict[str, Any], ...]
    security: tuple[dict[str, list[str]], ...] | None
    schemas: dict[str, Any]
    security_schemes: dict[str, Any]
    operations: tuple[NormalizedOperation, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "openapi": self.openapi,
            "info": self.info,
            "servers": [dict(item) for item in self.servers],
            "security": None if self.security is None else [dict(item) for item in self.security],
            "schemas": self.schemas,
            "security_schemes": self.security_schemes,
            "operations": [operation.to_dict() for operation in self.operations],
        }


def _pointer(document: Mapping[str, Any], ref: str) -> Any:
    if not ref.startswith("#/"):
        raise SpecLoadError(f"only local JSON Pointer references are supported: {ref!r}")
    current: Any = document
    for raw_token in ref[2:].split("/"):
        token = raw_token.replace("~1", "/").replace("~0", "~")
        try:
            current = current[token]
        except (KeyError, TypeError) as exc:
            raise SpecLoadError(f"unresolved reference: {ref!r}") from exc
    return current


def _ensure_acyclic(value: Any) -> None:
    """Reject recursive YAML aliases while allowing ordinary shared aliases."""
    active: set[int] = set()
    visited: set[int] = set()
    pending: list[tuple[Any, bool]] = [(value, False)]
    while pending:
        current, exiting = pending.pop()
        if not isinstance(current, (list, dict)):
            continue
        identity = id(current)
        if exiting:
            active.remove(identity)
            visited.add(identity)
        elif identity in active:
            raise SpecLoadError("cyclic YAML aliases are not supported")
        elif identity not in visited:
            active.add(identity)
            pending.append((current, True))
            children = (
                [item for pair in current.items() for item in pair]
                if isinstance(current, dict)
                else current
            )
            pending.extend((child, False) for child in reversed(children))


def _resolve(
    value: Any,
    document: Mapping[str, Any],
    stack: tuple[str, ...] = (),
) -> Any:
    """Resolve local refs recursively; keep recursive schema edges as refs."""
    if isinstance(value, list):
        return [_resolve(item, document, stack) for item in value]
    if not isinstance(value, dict):
        return value
    if "$ref" in value:
        ref = value["$ref"]
        if not isinstance(ref, str):
            raise SpecLoadError("$ref values must be strings")
        if not ref.startswith("#/"):
            raise SpecLoadError(f"only local JSON Pointer references are supported: {ref!r}")
        if ref in stack:
            return {
                "$ref": ref,
                **{
                    key: _resolve(item, document, stack)
                    for key, item in value.items()
                    if key != "$ref"
                },
            }
        resolved = _resolve(_pointer(document, ref), document, (*stack, ref))
        siblings = {key: item for key, item in value.items() if key != "$ref"}
        if siblings and isinstance(resolved, dict):
            resolved = {**resolved, **_resolve(siblings, document, stack)}
        return resolved
    return {key: _resolve(item, document, stack) for key, item in value.items()}


def _servers(value: Any) -> tuple[dict[str, Any], ...]:
    if value is None:
        return ()
    if not isinstance(value, list):
        raise SpecLoadError("servers must be an array")
    normalized = []
    for server in value:
        if not isinstance(server, dict) or not isinstance(server.get("url"), str):
            raise SpecLoadError("each server must be an object with a url")
        normalized.append(server)
    return tuple(normalized)


def _security(value: Any, *, where: str) -> tuple[dict[str, list[str]], ...] | None:
    if value is None:
        return None
    if not isinstance(value, list):
        raise SpecLoadError(f"{where} security must be an array")
    normalized: list[dict[str, list[str]]] = []
    for requirement in value:
        if not isinstance(requirement, dict) or not all(
            isinstance(name, str) and isinstance(scopes, list) and all(isinstance(scope, str) for scope in scopes)
            for name, scopes in requirement.items()
        ):
            raise SpecLoadError(f"{where} contains an invalid security requirement")
        normalized.append(requirement)
    return tuple(normalized)


def _normalize_parameters(path_parameters: Any, operation_parameters: Any) -> tuple[dict[str, Any], ...]:
    if not isinstance(path_parameters, (list, tuple)) or not isinstance(
        operation_parameters, (list, tuple)
    ):
        raise SpecLoadError("parameters must be arrays")
    merged: dict[tuple[str, str], dict[str, Any]] = {}
    for parameter in (*path_parameters, *operation_parameters):
        if not isinstance(parameter, dict):
            raise SpecLoadError("parameters must be parameter objects")
        name, location = parameter.get("name"), parameter.get("in")
        if not isinstance(name, str) or not isinstance(location, str):
            raise SpecLoadError("each parameter must define string name and in fields")
        if location not in {"path", "query", "header", "cookie"}:
            raise SpecLoadError(f"unsupported parameter location {location!r} for {name!r}")
        key = (name, location)
        normalized = dict(parameter)
        if location == "path":
            normalized["required"] = True
        merged[key] = normalized
    return tuple(merged.values())


def _response_schemas(responses: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    schemas: dict[str, dict[str, Any]] = {}
    for status_code, response in responses.items():
        content = response.get("content", {}) if isinstance(response, dict) else {}
        if not isinstance(content, dict):
            continue
        for media_type, media in content.items():
            if isinstance(media, dict) and "schema" in media:
                schemas.setdefault(str(status_code), {})[media_type] = media["schema"]
    return schemas


def _operation_id(method: str, route: str, operation: Mapping[str, Any]) -> str:
    supplied = operation.get("operationId")
    if supplied is not None:
        if not isinstance(supplied, str) or not supplied.strip():
            raise SpecLoadError(f"invalid operationId for {method.upper()} {route}")
        return supplied
    return f"{method.upper()} {route}"


def _parse_document(path: Path) -> dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8-sig") as handle:
            document = yaml.load(handle, Loader=_UniqueKeySafeLoader)
    except (OSError, UnicodeError) as exc:
        raise SpecLoadError(f"cannot read OpenAPI document {path}: {exc}") from exc
    except yaml.YAMLError as exc:
        raise SpecLoadError(f"invalid JSON/YAML in OpenAPI document {path}: {exc}") from exc
    if not isinstance(document, dict):
        raise SpecLoadError("OpenAPI document root must be an object")
    version = document.get("openapi")
    if not isinstance(version, str) or not version.startswith("3."):
        raise SpecLoadError("only OpenAPI 3.x documents are supported")
    if not isinstance(document.get("paths", {}), dict):
        raise SpecLoadError("OpenAPI paths must be an object")
    if not isinstance(document.get("info"), dict):
        raise SpecLoadError("OpenAPI info must be an object")
    _ensure_acyclic(document)
    return document


def load_spec(
    path: str | Path,
    *,
    logging_config: Mapping[str, Any] | None = None,
    log_dir: str | Path | None = None,
    run_id: str | None = None,
) -> NormalizedSpec:
    """Parse an OpenAPI 3 JSON/YAML file and normalize its operations.

    Only local ``#/...`` references are resolved. External references fail
    closed and are never fetched. Recursive schema references are retained as
    JSON Pointers so recursive models remain finite.
    """
    spec_path = Path(path)
    if log_dir is not None:
        configure_component_logging(
            log_dir,
            component="spec_loader",
            run_id=run_id,
            config=logging_config,
            logger_name=logger.name,
        )
    try:
        document = _parse_document(spec_path)
        resolved = _resolve(document, document)
        root_servers = _servers(resolved.get("servers", []))
        root_security = _security(resolved.get("security"), where="root")
        components = resolved.get("components", {}) or {}
        if not isinstance(components, dict):
            raise SpecLoadError("components must be an object")
        schemas = components.get("schemas", {}) or {}
        security_schemes = components.get("securitySchemes", {}) or {}
        if not isinstance(schemas, dict) or not isinstance(security_schemes, dict):
            raise SpecLoadError("components.schemas and components.securitySchemes must be objects")

        operations: list[NormalizedOperation] = []
        seen_ids: set[str] = set()
        for route, path_item in resolved.get("paths", {}).items():
            if not isinstance(route, str) or not route.startswith("/") or not isinstance(path_item, dict):
                raise SpecLoadError(f"invalid path item: {route!r}")
            path_parameters = path_item.get("parameters", []) or []
            path_servers = _servers(path_item.get("servers")) or root_servers
            for raw_method, operation in path_item.items():
                method = str(raw_method).lower()
                if method not in _METHODS:
                    continue
                if not isinstance(operation, dict):
                    raise SpecLoadError(f"{method.upper()} {route} must be an object")
                op_id = _operation_id(method, route, operation)
                if op_id in seen_ids:
                    raise SpecLoadError(f"duplicate operationId {op_id!r}")
                seen_ids.add(op_id)
                parameters = _normalize_parameters(path_parameters, operation.get("parameters", []) or [])
                request_body = operation.get("requestBody")
                if request_body is not None and not isinstance(request_body, dict):
                    raise SpecLoadError(f"requestBody for {op_id!r} must be an object")
                responses = operation.get("responses", {}) or {}
                if not isinstance(responses, dict):
                    raise SpecLoadError(f"responses for {op_id!r} must be an object")
                op_servers = _servers(operation.get("servers")) or path_servers
                op_security = _security(operation["security"], where=op_id) if "security" in operation else root_security
                tags = operation.get("tags", ()) or ()
                if not isinstance(tags, (list, tuple)) or not all(isinstance(tag, str) for tag in tags):
                    raise SpecLoadError(f"tags for {op_id!r} must be an array of strings")
                operations.append(
                    NormalizedOperation(
                        operation_id=op_id,
                        method=method.upper(),
                        route_template=route,
                        parameters=parameters,
                        request_body=request_body,
                        response_schemas=_response_schemas(responses),
                        responses=responses,
                        servers=op_servers,
                        security=op_security,
                        tags=tuple(tags),
                        summary=operation.get("summary"),
                        description=operation.get("description"),
                        deprecated=bool(operation.get("deprecated", False)),
                    )
                )
        result = NormalizedSpec(
            source=str(spec_path.resolve()),
            openapi=resolved["openapi"],
            info=resolved["info"],
            servers=root_servers,
            security=root_security,
            schemas=schemas,
            security_schemes=security_schemes,
            operations=tuple(operations),
        )
        logger.info("loaded OpenAPI %s with %d operations", result.openapi, len(operations), extra={"run_id": run_id})
        return result
    except Exception:
        with log_context(run_id=run_id):
            logger.exception("spec_loader action_failure: could not load or normalize OpenAPI document")
        raise
