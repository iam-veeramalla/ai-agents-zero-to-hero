# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Kubernetes Model Context Protocol (MCP) Server over Streamable HTTP.

Runs inside a GKE cluster, verifies incoming agent SPIFFE identities
(JWT-SVID Bearer tokens issued by Google Cloud Workload/Agent Identity),
and uses Kubernetes user impersonation (`Impersonate-User: <spiffe_id>`)
to forward the caller's SPIFFE identity to the Kubernetes API server
instead of acting as the generic MCP server service account.
"""

from contextvars import ContextVar
import json
import logging
import os
from typing import Any
import urllib.request

import jwt
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

try:
    from mcp.server.mcpserver import Context, MCPServer
except ImportError:  # pragma: no cover - fallback for mcp 1.x
    from mcp.server.fastmcp import Context, FastMCP as MCPServer  # type: ignore[no-redef]

from app.tools import (
    get_deployment_history as _get_deployment_history,
    get_nodes_info as _get_nodes_info,
    get_pod_events as _get_pod_events,
    get_pod_logs as _get_pod_logs,
    get_secret as _get_secret,
    investigate_kubernetes_logs as _investigate_kubernetes_logs,
    list_pods as _list_pods,
    restart_deployment as _restart_deployment,
)

logger = logging.getLogger(__name__)
logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"))

# ContextVar holding the lowercase HTTP headers of the active incoming MCP request.
_current_request_headers: ContextVar[dict[str, str]] = ContextVar(
    "_current_request_headers", default={}
)

# Cache of PyJWKClient instances keyed by JWKS URI and OpenID discovery metadata keyed by issuer.
_jwk_clients: dict[str, jwt.PyJWKClient] = {}
_oidc_jwks_uri_cache: dict[str, str] = {}

GOOGLE_ACCOUNTS_ISSUERS = {"https://accounts.google.com", "accounts.google.com"}
GOOGLE_DEFAULT_CERTS_URL = "https://www.googleapis.com/oauth2/v3/certs"


def _resolve_jwks_uri(issuer: str) -> str:
    """Resolve the JWKS endpoint URI for a given token issuer."""
    explicit_jwks = os.environ.get("MCP_JWKS_URI", "").strip()
    if explicit_jwks:
        return explicit_jwks

    if issuer in GOOGLE_ACCOUNTS_ISSUERS:
        return GOOGLE_DEFAULT_CERTS_URL

    if issuer in _oidc_jwks_uri_cache:
        return _oidc_jwks_uri_cache[issuer]

    issuer_base = issuer.rstrip("/")
    if not issuer_base.startswith("https://"):
        raise ValueError(f"Unsupported or insecure token issuer: {issuer}")

    discovery_url = f"{issuer_base}/.well-known/openid-configuration"
    try:
        req = urllib.request.Request(discovery_url, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            metadata = json.loads(resp.read().decode("utf-8"))
            jwks_uri = metadata.get("jwks_uri")
            if isinstance(jwks_uri, str) and jwks_uri.startswith("https://"):
                _oidc_jwks_uri_cache[issuer] = jwks_uri
                return jwks_uri
    except Exception as exc:
        logger.debug("OIDC discovery lookup failed for %s (%s); using fallback JWKS path.", issuer, exc)

    fallback_jwks_uri = f"{issuer_base}/openid/jwks"
    _oidc_jwks_uri_cache[issuer] = fallback_jwks_uri
    return fallback_jwks_uri


def _get_jwk_client(jwks_uri: str) -> jwt.PyJWKClient:
    """Get or create a cached PyJWKClient for the given JWKS URI."""
    if jwks_uri not in _jwk_clients:
        _jwk_clients[jwks_uri] = jwt.PyJWKClient(jwks_uri, cache_keys=True)
    return _jwk_clients[jwks_uri]


def verify_spiffe_token(
    token: str,
    expected_audience: str | None = None,
) -> str:
    """Verify an incoming Bearer JWT-SVID and return its SPIFFE ID (`sub` claim).

    Validates the JWT cryptographic signature against the issuer's JWKS endpoint,
    verifies token expiration (`exp`) and issuer (`iss`), and ensures the subject
    (`sub`) is a valid SPIFFE ID (`spiffe://<trust-domain>/...`).

    Args:
        token: Raw Bearer JWT string.
        expected_audience: Optional expected `aud` claim. Defaults to the
            `MCP_EXPECTED_AUDIENCE` environment variable if configured.

    Returns:
        The verified SPIFFE ID string (e.g., `spiffe://agents.global.org-...`).

    Raises:
        ValueError: If the token is missing, malformed, expired, fails signature
            verification, or does not carry a `spiffe://` subject identity.
    """
    if not token or not token.strip():
        raise ValueError("Missing Bearer token in Authorization header.")

    raw_token = token.strip()
    try:
        unverified_claims = jwt.decode(raw_token, options={"verify_signature": False})
    except Exception as exc:
        raise ValueError(f"Malformed JWT bearer token: {exc}") from exc

    issuer = unverified_claims.get("iss")
    subject = unverified_claims.get("sub")
    if not isinstance(issuer, str) or not issuer.strip():
        raise ValueError("Token is missing required 'iss' (issuer) claim.")
    if not isinstance(subject, str) or not subject.strip():
        raise ValueError("Token is missing required 'sub' (subject) claim.")

    if not subject.startswith("spiffe://"):
        raise ValueError(
            f"Token subject '{subject}' is not a valid SPIFFE ID (expected 'spiffe://<trust-domain>/...')."
        )

    audience = (
        expected_audience
        if expected_audience is not None
        else (os.environ.get("MCP_EXPECTED_AUDIENCE", "").strip() or None)
    )

    jwks_uri = _resolve_jwks_uri(issuer)
    try:
        jwk_client = _get_jwk_client(jwks_uri)
        signing_key = jwk_client.get_signing_key_from_jwt(raw_token)
        decode_kwargs: dict[str, Any] = {
            "key": signing_key.key,
            "algorithms": ["RS256", "ES256"],
            "issuer": issuer,
        }
        if audience:
            decode_kwargs["audience"] = audience
        else:
            decode_kwargs["options"] = {"verify_aud": False}

        verified_claims = jwt.decode(raw_token, **decode_kwargs)
    except Exception as exc:
        raise ValueError(f"JWT signature or claim verification failed: {exc}") from exc

    verified_sub = verified_claims.get("sub", "")
    if not isinstance(verified_sub, str) or not verified_sub.startswith("spiffe://"):
        raise ValueError(
            f"Verified token subject '{verified_sub}' is not a valid SPIFFE ID."
        )

    return verified_sub


def extract_and_verify_spiffe_identity(ctx: Context | None = None) -> str:
    """Extract the Bearer token from the incoming MCP HTTP request and return the verified SPIFFE ID.

    Args:
        ctx: Optional MCP request Context containing HTTP headers.

    Returns:
        The verified SPIFFE ID string (`spiffe://...`).

    Raises:
        ValueError: If no Authorization Bearer header is present or verification fails.
    """
    auth_header: str | None = None

    if ctx is not None:
        try:
            headers = getattr(ctx, "headers", None)
            if headers:
                auth_header = headers.get("authorization") or headers.get("Authorization")
        except Exception:
            auth_header = None

    if not auth_header:
        ctx_headers = _current_request_headers.get()
        auth_header = ctx_headers.get("authorization")

    if not auth_header or not auth_header.strip():
        raise ValueError(
            "Missing Authorization header. The MCP server requires a valid agent SPIFFE Bearer token."
        )

    parts = auth_header.strip().split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "bearer" or not parts[1].strip():
        raise ValueError(
            "Invalid Authorization header format. Expected 'Authorization: Bearer <spiffe-jwt>'."
        )

    spiffe_id = verify_spiffe_token(parts[1].strip())
    logger.info(
        "Verified incoming agent SPIFFE identity: %s (forwarding via Kubernetes user impersonation)",
        spiffe_id,
    )
    return spiffe_id


mcp = MCPServer(
    "k8s-mcp-server",
    instructions=(
        "Kubernetes cluster inspection and forensic investigation MCP server. "
        "Verifies the caller's SPIFFE identity and impersonates that identity "
        "against the Kubernetes API server to list pods, fetch container logs, "
        "inspect pod events, check deployment rollout history, inspect node "
        "health, and run forensic log analysis."
    ),
)


@mcp.tool()
def list_pods(
    namespace: str = "default",
    all_namespaces: bool = False,
    ctx: Context | None = None,
) -> dict[str, Any]:
    """List pods in a Kubernetes namespace or across all namespaces with status and restart counts.

    Use this tool to discover pods, identify unhealthy pods (e.g., CrashLoopBackOff,
    ImagePullBackOff, Pending, OOMKilled, Error), or inspect overall workload health
    in the cluster when a specific pod name is not yet known.

    Args:
        namespace: The Kubernetes namespace to list pods from (defaults to 'default').
            Ignored when all_namespaces is True.
        all_namespaces: Whether to list pods across all namespaces in the cluster
            (defaults to False).

    Returns:
        A dictionary containing the list of pods with their phase, ready status,
        restart counts, waiting/terminated reasons, node assignment, and summary counts.
    """
    try:
        spiffe_id = extract_and_verify_spiffe_identity(ctx)
    except ValueError as exc:
        return {
            "status": "ERROR",
            "message": f"SPIFFE authentication failed: {exc}",
            "namespace": "all" if all_namespaces else namespace,
        }

    result = _list_pods(
        namespace=namespace,
        all_namespaces=all_namespaces,
        impersonate_user=spiffe_id,
    )
    result["impersonated_user"] = spiffe_id
    return result


@mcp.tool()
def get_pod_logs(
    pod_name: str,
    namespace: str = "default",
    container: str = "",
    tail_lines: int = 200,
    previous: bool = False,
    ctx: Context | None = None,
) -> dict[str, Any]:
    """Fetch container logs directly from a Kubernetes pod in the cluster.

    Use this tool to retrieve real-time or previous (crashed) container logs
    from a running or failing pod in a Kubernetes namespace.

    Args:
        pod_name: The name of the pod (or pod prefix/deployment name if exact pod name is unknown).
        namespace: The Kubernetes namespace where the pod is located (defaults to 'default').
        container: Optional specific container name inside the pod. Leave empty to auto-select.
        tail_lines: Number of recent log lines to fetch (defaults to 200).
        previous: Whether to fetch logs from the previous terminated container instance (useful for CrashLoopBackOff).

    Returns:
        A dictionary containing the fetched pod logs, pod phase, container statuses,
        and metadata, or an error report if the pod cannot be accessed.
    """
    try:
        spiffe_id = extract_and_verify_spiffe_identity(ctx)
    except ValueError as exc:
        return {
            "status": "ERROR",
            "message": f"SPIFFE authentication failed: {exc}",
            "pod_name": pod_name,
            "namespace": namespace,
        }

    result = _get_pod_logs(
        pod_name=pod_name,
        namespace=namespace,
        container=container,
        tail_lines=tail_lines,
        previous=previous,
        impersonate_user=spiffe_id,
    )
    result["impersonated_user"] = spiffe_id
    return result


@mcp.tool()
def get_pod_events(
    pod_name: str,
    namespace: str = "default",
    ctx: Context | None = None,
) -> dict[str, Any]:
    """Fetch Kubernetes events related to a specific pod in the cluster.

    Use this tool to inspect scheduling failures, image pull errors, probe
    failures, volume mount errors, OOMKills, and kubelet warnings for a pod.

    Args:
        pod_name: The name of the pod (or prefix) to fetch events for.
        namespace: The Kubernetes namespace (defaults to 'default').

    Returns:
        A dictionary containing chronological events (type, reason, message, count, source).
    """
    try:
        spiffe_id = extract_and_verify_spiffe_identity(ctx)
    except ValueError as exc:
        return {
            "status": "ERROR",
            "message": f"SPIFFE authentication failed: {exc}",
            "pod_name": pod_name,
            "namespace": namespace,
        }

    result = _get_pod_events(
        pod_name=pod_name,
        namespace=namespace,
        impersonate_user=spiffe_id,
    )
    result["impersonated_user"] = spiffe_id
    return result


@mcp.tool()
def get_deployment_history(
    deployment_name: str = "",
    pod_name: str = "",
    namespace: str = "default",
    ctx: Context | None = None,
) -> dict[str, Any]:
    """Fetch rollout history and ReplicaSet revisions for a Kubernetes Deployment.

    Use this tool to check if a recent version change, image update, or
    configuration rollout triggered a pod failure or regression. You can
    provide either `deployment_name` directly or `pod_name` (the tool will
    resolve the owning Deployment automatically).

    Args:
        deployment_name: Name of the Kubernetes Deployment (optional if pod_name is provided).
        pod_name: Name of a pod owned by the Deployment (optional if deployment_name is provided).
        namespace: The Kubernetes namespace (defaults to 'default').

    Returns:
        A dictionary containing Deployment status, strategy, conditions, and
        ordered ReplicaSet revision history with container images and timestamps.
    """
    try:
        spiffe_id = extract_and_verify_spiffe_identity(ctx)
    except ValueError as exc:
        return {
            "status": "ERROR",
            "message": f"SPIFFE authentication failed: {exc}",
            "deployment_name": deployment_name,
            "namespace": namespace,
        }

    result = _get_deployment_history(
        deployment_name=deployment_name,
        pod_name=pod_name,
        namespace=namespace,
        impersonate_user=spiffe_id,
    )
    result["impersonated_user"] = spiffe_id
    return result


@mcp.tool()
def get_nodes_info(
    node_name: str = "",
    ctx: Context | None = None,
) -> dict[str, Any]:
    """Fetch health, conditions, resource capacity/allocatable, and taints for Kubernetes nodes.

    Use this tool to diagnose cluster-level or node-level issues such as
    Node NotReady, MemoryPressure, DiskPressure, PIDPressure, NetworkUnavailable,
    unschedulable cordoned nodes, taints blocking pod scheduling, or CPU/memory
    resource exhaustion.

    Args:
        node_name: Optional specific node name (or substring) to inspect. Leave empty
            to inspect all nodes in the cluster.

    Returns:
        A dictionary containing node count, healthy/unhealthy summary, and detailed
        per-node status, conditions, capacity, allocatable resources, taints, and system info.
    """
    try:
        spiffe_id = extract_and_verify_spiffe_identity(ctx)
    except ValueError as exc:
        return {
            "status": "ERROR",
            "message": f"SPIFFE authentication failed: {exc}",
            "node_name": node_name,
        }

    result = _get_nodes_info(
        node_name=node_name,
        impersonate_user=spiffe_id,
    )
    result["impersonated_user"] = spiffe_id
    return result


@mcp.tool()
def restart_deployment(
    deployment_name: str = "",
    pod_name: str = "",
    namespace: str = "default",
    ctx: Context | None = None,
) -> dict[str, Any]:
    """Trigger a rolling restart of a Kubernetes Deployment.

    Use this tool to remediate workloads experiencing transient failures,
    deadlocks, exhausted database connection pools, memory leaks, or to
    apply updated secrets or configurations. You can provide either
    `deployment_name` directly or `pod_name` (the tool will resolve the
    owning Deployment automatically).

    Args:
        deployment_name: Name of the Deployment to restart (optional if pod_name is provided).
        pod_name: Name of a pod owned by the Deployment (optional if deployment_name is provided).
        namespace: The Kubernetes namespace (defaults to 'default').

    Returns:
        A dictionary containing the restart status, deployment_name, namespace,
        restarted_at timestamp, and execution message.
    """
    try:
        spiffe_id = extract_and_verify_spiffe_identity(ctx)
    except ValueError as exc:
        return {
            "status": "ERROR",
            "message": f"SPIFFE authentication failed: {exc}",
            "deployment_name": deployment_name,
            "namespace": namespace,
        }

    result = _restart_deployment(
        deployment_name=deployment_name,
        pod_name=pod_name,
        namespace=namespace,
        impersonate_user=spiffe_id,
    )
    result["impersonated_user"] = spiffe_id
    return result


@mcp.tool()
def get_secret(
    secret_name: str,
    namespace: str = "default",
    key: str = "",
    decode: bool = True,
    ctx: Context | None = None,
) -> dict[str, Any]:
    """Inspect metadata, data keys, and decoded values for a Kubernetes Secret.

    Use this tool during incident investigations to verify whether expected
    secret keys exist, check database credentials or API keys, or diagnose
    issues where containers crash due to missing or invalid secrets.

    Args:
        secret_name: Name of the Kubernetes Secret to inspect.
        namespace: The Kubernetes namespace (defaults to 'default').
        key: Optional specific key inside the secret to retrieve.
        decode: Whether to base64-decode the secret values into strings (defaults to True).

    Returns:
        A dictionary containing status, secret_name, namespace, secret type,
        list of keys, and decoded data mapping or specific key value.
    """
    try:
        spiffe_id = extract_and_verify_spiffe_identity(ctx)
    except ValueError as exc:
        return {
            "status": "ERROR",
            "message": f"SPIFFE authentication failed: {exc}",
            "secret_name": secret_name,
            "namespace": namespace,
        }

    result = _get_secret(
        secret_name=secret_name,
        namespace=namespace,
        key=key,
        decode=decode,
        impersonate_user=spiffe_id,
    )
    result["impersonated_user"] = spiffe_id
    return result


@mcp.tool()
def investigate_kubernetes_logs(logs: str) -> dict[str, Any]:
    """Perform a comprehensive forensic investigation on raw Kubernetes or container log text.

    Extracts error signals, stack traces, OOM/crash events, probe failures, and
    correlates them against known Kubernetes failure signatures to determine root
    cause and remediation steps.

    Args:
        logs: Raw multi-line log string from kubectl logs, pod events, or container output.

    Returns:
        A dictionary containing structured investigation results including status,
        executive_summary, severity, root_cause_hypotheses, key_evidence,
        remediation_plan, and log_metadata.
    """
    return _investigate_kubernetes_logs(logs=logs)


@mcp.custom_route("/health", methods=["GET"])
async def health_check(request: Request) -> JSONResponse:
    """Kubernetes readiness and liveness probe endpoint."""
    return JSONResponse(
        {
            "status": "ok",
            "service": "k8s-mcp-server",
            "mcp_endpoint": "/mcp",
        }
    )


class _RequestHeadersMiddleware:
    """ASGI middleware that captures incoming HTTP request headers in a ContextVar."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("type") == "http":
            raw_headers = scope.get("headers") or []
            headers_dict = {
                k.decode("latin-1").lower(): v.decode("latin-1")
                for k, v in raw_headers
            }
            token = _current_request_headers.set(headers_dict)
            try:
                await self.app(scope, receive, send)
            finally:
                _current_request_headers.reset(token)
        else:
            await self.app(scope, receive, send)


app = mcp.streamable_http_app(
    streamable_http_path="/mcp",
    json_response=True,
    stateless_http=True,
    host="0.0.0.0",
)
app.add_middleware(_RequestHeadersMiddleware)


if __name__ == "__main__":
    import uvicorn

    port = int(os.environ.get("PORT", "8080"))
    uvicorn.run(app, host="0.0.0.0", port=port)
