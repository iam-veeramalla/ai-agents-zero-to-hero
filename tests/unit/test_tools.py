import base64
import json
from unittest.mock import MagicMock, patch

from app.tools import (
    get_pod_logs,
    get_secret,
    investigate_kubernetes_logs,
    investigate_log_file,
    list_pods,
    restart_deployment,
)


def test_investigate_kubernetes_logs_tool():
    logs = "2026-09-22T10:15:24.120Z stderr F Container terminated with exit code 137 (OOMKilled)"
    result = investigate_kubernetes_logs(logs)

    assert result["severity"] == "CRITICAL"
    assert len(result["evidence"]) >= 1
    assert result["evidence"][0]["line_number"] == 1
    assert "OOMKilled" in result["evidence"][0]["log_excerpt"]


def test_investigate_empty_logs_tool():
    result = investigate_kubernetes_logs("")
    assert result["status"] == "ERROR"
    assert "empty" in result["message"]


def test_investigate_log_file_tool(tmp_path):
    log_file = tmp_path / "sample.log"
    log_file.write_text("2026-09-22T08:00:25Z [ERROR] psycopg2.OperationalError: could not connect to server: Connection refused")

    result = investigate_log_file(str(log_file))
    assert result["severity"] == "HIGH"
    assert len(result["evidence"]) >= 1
    assert "Database Connection" in result["evidence"][0]["signal_name"]


def test_investigate_nonexistent_file():
    result = investigate_log_file("/non/existent/path/pod.log")
    assert result["status"] == "ERROR"
    assert "not found" in result["message"]


def test_get_pod_logs_empty_name():
    result = get_pod_logs("")
    assert result["status"] == "ERROR"
    assert "pod_name must be provided" in result["message"]

    result_whitespace = get_pod_logs("   ")
    assert result_whitespace["status"] == "ERROR"
    assert "pod_name must be provided" in result_whitespace["message"]


def test_get_pod_logs_k8s_client_success():
    mock_client = MagicMock()
    mock_client.read_namespaced_pod_log.return_value = (
        "2026-09-29T12:00:00Z line 1\n2026-09-29T12:00:01Z line 2\n"
    )

    with patch("app.tools._get_k8s_client", return_value=mock_client):
        result = get_pod_logs(
            pod_name="payment-svc-789",
            namespace="payments",
            container="app",
            tail_lines=100,
            previous=True,
            timestamps=True,
        )

    assert result["status"] == "SUCCESS"
    assert result["pod_name"] == "payment-svc-789"
    assert result["namespace"] == "payments"
    assert result["container"] == "app"
    assert result["line_count"] == 2
    assert "line 1" in result["logs"]

    mock_client.read_namespaced_pod_log.assert_called_once_with(
        name="payment-svc-789",
        namespace="payments",
        container="app",
        tail_lines=100,
        previous=True,
        timestamps=True,
    )


def test_get_pod_logs_k8s_client_api_exception():
    from kubernetes.client.exceptions import ApiException

    mock_client = MagicMock()
    mock_client.read_namespaced_pod_log.side_effect = ApiException(
        status=404, reason="Pod Not Found"
    )

    with patch("app.tools._get_k8s_client", return_value=mock_client):
        result = get_pod_logs(pod_name="missing-pod", namespace="default")

    assert result["status"] == "ERROR"
    assert "404" in result["message"]
    assert "Pod Not Found" in result["message"]
    assert result["pod_name"] == "missing-pod"


def test_get_pod_logs_kubectl_fallback_success():
    mock_proc = MagicMock()
    mock_proc.returncode = 0
    mock_proc.stdout = "2026-09-29T12:05:00Z startup completed successfully\n"

    with patch("app.tools._get_k8s_client", return_value=None), patch(
        "subprocess.run", return_value=mock_proc
    ) as mock_run:
        result = get_pod_logs(
            pod_name="web-frontend",
            namespace="prod",
            tail_lines=50,
        )

    assert result["status"] == "SUCCESS"
    assert result["pod_name"] == "web-frontend"
    assert result["namespace"] == "prod"
    assert "startup completed" in result["logs"]
    assert result["line_count"] == 1

    mock_run.assert_called_once_with(
        ["kubectl", "logs", "web-frontend", "-n", "prod", "--tail", "50", "--timestamps"],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )


def test_get_pod_logs_kubectl_fallback_error():
    mock_proc = MagicMock()
    mock_proc.returncode = 1
    mock_proc.stderr = "Error from server (NotFound): pods 'bad-pod' not found\n"
    mock_proc.stdout = ""

    with patch("app.tools._get_k8s_client", return_value=None), patch(
        "subprocess.run", return_value=mock_proc
    ):
        result = get_pod_logs(pod_name="bad-pod")

    assert result["status"] == "ERROR"
    assert "NotFound" in result["message"]
    assert result["pod_name"] == "bad-pod"


def test_list_pods_k8s_client_success():
    mock_client = MagicMock()
    mock_pod = MagicMock()
    mock_pod.metadata.name = "crashloop-pod-123"
    mock_pod.metadata.namespace = "default"
    mock_pod.spec.node_name = "node-1"
    mock_pod.status.phase = "Running"

    mock_cs = MagicMock()
    mock_cs.name = "app"
    mock_cs.ready = False
    mock_cs.restart_count = 5
    mock_cs.state.waiting.reason = "CrashLoopBackOff"
    mock_cs.state.terminated = None
    mock_cs.last_state = None
    mock_pod.status.container_statuses = [mock_cs]

    mock_resp = MagicMock()
    mock_resp.items = [mock_pod]
    mock_client.list_namespaced_pod.return_value = mock_resp

    with patch("app.tools._get_k8s_client", return_value=mock_client):
        result = list_pods(namespace="default", all_namespaces=False)

    assert result["status"] == "SUCCESS"
    assert result["total_pods"] == 1
    assert result["unhealthy_pods"] == 1
    assert result["pods"][0]["name"] == "crashloop-pod-123"
    assert result["pods"][0]["phase"] == "Running"
    assert result["pods"][0]["reason"] == "CrashLoopBackOff"
    assert result["pods"][0]["restarts"] == 5


def test_mcp_server_tools_and_health():
    from starlette.testclient import TestClient
    from app.mcp_server import app as mcp_app, mcp

    with TestClient(mcp_app) as client:
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"

    tool_names = {t.name for t in mcp._tool_manager.list_tools()}
    assert {
        "list_pods",
        "get_pod_logs",
        "get_pod_events",
        "get_deployment_history",
        "get_nodes_info",
        "investigate_kubernetes_logs",
        "restart_deployment",
        "get_secret",
    }.issubset(tool_names)


def test_mcp_toolset_spiffe_header_provider():
    from app.agent import (
        K8S_MCP_SERVER_URL,
        get_mcp_auth_headers,
        k8s_mcp_toolset,
    )

    assert k8s_mcp_toolset is not None
    assert k8s_mcp_toolset._header_provider is get_mcp_auth_headers

    with patch(
        "app.agent.id_token.fetch_id_token", return_value="spiffe-jwt-token-123"
    ) as mock_fetch:
        headers = get_mcp_auth_headers()
        assert headers == {"Authorization": "Bearer spiffe-jwt-token-123"}
        mock_fetch.assert_called_once()
        assert mock_fetch.call_args[0][1] == K8S_MCP_SERVER_URL


def test_mcp_server_verifies_spiffe_and_impersonates_k8s_user():
    import time
    import jwt
    from cryptography.hazmat.primitives.asymmetric import rsa
    from app.mcp_server import (
        _current_request_headers,
        list_pods as mcp_list_pods,
        verify_spiffe_token,
    )

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    spiffe_id = (
        "spiffe://agents.global.org-310633432312.system.id.goog/"
        "resources/aiplatform/projects/1098749337818/locations/us-east1/"
        "reasoningEngines/2253300647057162240"
    )
    issuer = (
        "https://sts.googleapis.com/v1/organizations/310633432312/"
        "locations/global/workloadIdentityPools/agents.global.org-310633432312.system.id.goog"
    )
    now = int(time.time())
    token = jwt.encode(
        {
            "iss": issuer,
            "sub": spiffe_id,
            "aud": "http://34.23.62.189/mcp",
            "iat": now,
            "exp": now + 3600,
        },
        private_key,
        algorithm="RS256",
        headers={"kid": "test-key-1"},
    )

    mock_signing_key = MagicMock()
    mock_signing_key.key = public_key
    mock_jwk_client = MagicMock()
    mock_jwk_client.get_signing_key_from_jwt.return_value = mock_signing_key

    with patch("app.mcp_server._resolve_jwks_uri", return_value=f"{issuer}/openid/jwks"), patch(
        "app.mcp_server._get_jwk_client", return_value=mock_jwk_client
    ):
        verified_id = verify_spiffe_token(token)
        assert verified_id == spiffe_id

        # Verify MCP tool forwards the verified SPIFFE ID via impersonate_user
        ctx_token = _current_request_headers.set({"authorization": f"Bearer {token}"})
        try:
            with patch("app.mcp_server._list_pods") as mock_list_pods:
                mock_list_pods.return_value = {
                    "status": "SUCCESS",
                    "namespace": "default",
                    "total_pods": 0,
                    "pods": [],
                }
                res = mcp_list_pods(namespace="default", all_namespaces=False)
                assert res["status"] == "SUCCESS"
                assert res["impersonated_user"] == spiffe_id
                mock_list_pods.assert_called_once_with(
                    namespace="default",
                    all_namespaces=False,
                    impersonate_user=spiffe_id,
                )
        finally:
            _current_request_headers.reset(ctx_token)


def test_mcp_server_rejects_missing_or_non_spiffe_token():
    from app.mcp_server import _current_request_headers, list_pods as mcp_list_pods

    ctx_token = _current_request_headers.set({})
    try:
        res = mcp_list_pods(namespace="default")
        assert res["status"] == "ERROR"
        assert "SPIFFE authentication failed" in res["message"]
    finally:
        _current_request_headers.reset(ctx_token)


def test_k8s_client_sets_impersonate_user_header():
    from app.tools import _get_k8s_client

    spiffe_id = "spiffe://agents.global.org-310633432312.system.id.goog/resources/aiplatform/projects/1098749337818/locations/us-east1/reasoningEngines/2253300647057162240"

    with patch("kubernetes.config.load_incluster_config"), patch(
        "kubernetes.client.ApiClient"
    ) as mock_api_client_cls, patch("kubernetes.client.CoreV1Api") as mock_core_v1_cls:
        mock_api_client_instance = MagicMock()
        mock_api_client_cls.return_value = mock_api_client_instance

        _get_k8s_client(impersonate_user=spiffe_id)
        mock_api_client_instance.set_default_header.assert_called_once_with(
            "Impersonate-User", spiffe_id
        )
        mock_core_v1_cls.assert_called_once_with(api_client=mock_api_client_instance)


def test_restart_deployment_empty_input():
    result = restart_deployment("", "")
    assert result["status"] == "ERROR"
    assert "Either deployment_name or pod_name" in result["message"]


def test_restart_deployment_k8s_client_success():
    mock_apps = MagicMock()

    with patch("app.tools._get_k8s_apps_client", return_value=mock_apps):
        result = restart_deployment(deployment_name="payment-api", namespace="default")

    assert result["status"] == "SUCCESS"
    assert result["deployment_name"] == "payment-api"
    assert result["namespace"] == "default"
    assert "restarted_at" in result
    assert "triggered successfully" in result["message"]
    mock_apps.patch_namespaced_deployment.assert_called_once()
    call_kwargs = mock_apps.patch_namespaced_deployment.call_args[1]
    assert call_kwargs["name"] == "payment-api"
    assert call_kwargs["namespace"] == "default"
    assert "kubectl.kubernetes.io/restartedAt" in call_kwargs["body"]["spec"]["template"]["metadata"]["annotations"]


def test_restart_deployment_resolve_pod_name():
    mock_apps = MagicMock()

    with patch("app.tools._resolve_deployment_name", return_value="payment-api") as mock_resolve, patch(
        "app.tools._get_k8s_apps_client", return_value=mock_apps
    ):
        result = restart_deployment(pod_name="payment-api-79b8f6c4d-xk9qp", namespace="default")

    assert result["status"] == "SUCCESS"
    assert result["deployment_name"] == "payment-api"
    mock_resolve.assert_called_once_with(
        pod_name="payment-api-79b8f6c4d-xk9qp",
        namespace="default",
        impersonate_user=None,
    )


def test_restart_deployment_k8s_client_api_exception():
    from kubernetes.client.exceptions import ApiException

    mock_apps = MagicMock()
    mock_apps.patch_namespaced_deployment.side_effect = ApiException(
        status=404, reason="Deployment Not Found"
    )

    with patch("app.tools._get_k8s_apps_client", return_value=mock_apps):
        result = restart_deployment(deployment_name="missing-deploy", namespace="default")

    assert result["status"] == "ERROR"
    assert "404" in result["message"]
    assert "Deployment Not Found" in result["message"]


def test_restart_deployment_kubectl_fallback_success():
    mock_proc = MagicMock()
    mock_proc.returncode = 0
    mock_proc.stdout = "deployment.apps/payment-api restarted\n"

    with patch("app.tools._get_k8s_apps_client", return_value=None), patch(
        "subprocess.run", return_value=mock_proc
    ) as mock_run:
        result = restart_deployment(deployment_name="payment-api", namespace="prod")

    assert result["status"] == "SUCCESS"
    assert result["deployment_name"] == "payment-api"
    assert "restarted" in result["message"]
    mock_run.assert_called_once_with(
        ["kubectl", "rollout", "restart", "deployment/payment-api", "-n", "prod"],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )


def test_restart_deployment_kubectl_fallback_error():
    mock_proc = MagicMock()
    mock_proc.returncode = 1
    mock_proc.stderr = "Error from server (NotFound): deployments.apps 'bad-deploy' not found\n"
    mock_proc.stdout = ""

    with patch("app.tools._get_k8s_apps_client", return_value=None), patch(
        "subprocess.run", return_value=mock_proc
    ):
        result = restart_deployment(deployment_name="bad-deploy")

    assert result["status"] == "ERROR"
    assert "NotFound" in result["message"]


def test_get_secret_empty_name():
    result = get_secret("")
    assert result["status"] == "ERROR"
    assert "secret_name must be provided" in result["message"]


def test_get_secret_k8s_client_success_decode():
    mock_core = MagicMock()
    mock_secret = MagicMock()
    mock_secret.type = "Opaque"
    mock_secret.data = {
        "DB_PASSWORD": base64.b64encode(b"super_secret_pw").decode("utf-8"),
        "DB_USER": base64.b64encode(b"app_user").decode("utf-8"),
    }
    mock_core.read_namespaced_secret.return_value = mock_secret

    with patch("app.tools._get_k8s_client", return_value=mock_core):
        result = get_secret(secret_name="db-credentials", namespace="default")

    assert result["status"] == "SUCCESS"
    assert result["secret_name"] == "db-credentials"
    assert result["namespace"] == "default"
    assert result["type"] == "Opaque"
    assert "DB_PASSWORD" in result["keys"]
    assert "DB_USER" in result["keys"]
    assert result["data"]["DB_PASSWORD"] == "super_secret_pw"
    assert result["data"]["DB_USER"] == "app_user"


def test_get_secret_key_filter_and_missing_key():
    mock_core = MagicMock()
    mock_secret = MagicMock()
    mock_secret.type = "Opaque"
    mock_secret.data = {
        "API_KEY": base64.b64encode(b"token-xyz").decode("utf-8"),
    }
    mock_core.read_namespaced_secret.return_value = mock_secret

    with patch("app.tools._get_k8s_client", return_value=mock_core):
        res_key = get_secret(secret_name="api-secrets", key="API_KEY")
        assert res_key["status"] == "SUCCESS"
        assert res_key["key"] == "API_KEY"
        assert res_key["value"] == "token-xyz"

        res_missing = get_secret(secret_name="api-secrets", key="NON_EXISTENT")
        assert res_missing["status"] == "ERROR"
        assert "not found in secret" in res_missing["message"]


def test_get_secret_k8s_client_api_exception():
    from kubernetes.client.exceptions import ApiException

    mock_core = MagicMock()
    mock_core.read_namespaced_secret.side_effect = ApiException(
        status=404, reason="Secret Not Found"
    )

    with patch("app.tools._get_k8s_client", return_value=mock_core):
        result = get_secret(secret_name="missing-sec")

    assert result["status"] == "ERROR"
    assert "404" in result["message"]
    assert "Secret Not Found" in result["message"]


def test_get_secret_kubectl_fallback_success():
    mock_proc = MagicMock()
    mock_proc.returncode = 0
    mock_proc.stdout = json.dumps({
        "type": "Opaque",
        "data": {
            "STRIPE_KEY": base64.b64encode(b"sk_test_1234").decode("utf-8"),
        },
    })

    with patch("app.tools._get_k8s_client", return_value=None), patch(
        "subprocess.run", return_value=mock_proc
    ) as mock_run:
        result = get_secret(secret_name="payment-secret", namespace="payments")

    assert result["status"] == "SUCCESS"
    assert result["secret_name"] == "payment-secret"
    assert result["data"]["STRIPE_KEY"] == "sk_test_1234"
    mock_run.assert_called_once_with(
        ["kubectl", "get", "secret", "payment-secret", "-n", "payments", "-o", "json"],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )


def test_get_secret_kubectl_fallback_error():
    mock_proc = MagicMock()
    mock_proc.returncode = 1
    mock_proc.stderr = "Error from server (NotFound): secrets 'missing' not found\n"
    mock_proc.stdout = ""

    with patch("app.tools._get_k8s_client", return_value=None), patch(
        "subprocess.run", return_value=mock_proc
    ):
        result = get_secret(secret_name="missing")

    assert result["status"] == "ERROR"
    assert "NotFound" in result["message"]


def test_mcp_server_restart_deployment_and_get_secret():
    from app.mcp_server import (
        _current_request_headers,
    )
    from app.mcp_server import (
        get_secret as mcp_get_secret,
    )
    from app.mcp_server import (
        restart_deployment as mcp_restart_deployment,
    )

    spiffe_id = "spiffe://agents.global.org-310633432312.system.id.goog/sa/k8s-agent"

    with patch("app.mcp_server.extract_and_verify_spiffe_identity", return_value=spiffe_id), patch(
        "app.mcp_server._restart_deployment", return_value={"status": "SUCCESS"}
    ) as mock_restart, patch(
        "app.mcp_server._get_secret", return_value={"status": "SUCCESS"}
    ) as mock_sec:
        ctx_token = _current_request_headers.set({"authorization": "Bearer valid-token"})
        try:
            res_restart = mcp_restart_deployment(deployment_name="app-deploy", namespace="prod")
            assert res_restart["status"] == "SUCCESS"
            assert res_restart["impersonated_user"] == spiffe_id
            mock_restart.assert_called_once_with(
                deployment_name="app-deploy",
                pod_name="",
                namespace="prod",
                impersonate_user=spiffe_id,
            )

            res_sec = mcp_get_secret(secret_name="app-secret", namespace="prod", key="DB_PASS")
            assert res_sec["status"] == "SUCCESS"
            assert res_sec["impersonated_user"] == spiffe_id
            mock_sec.assert_called_once_with(
                secret_name="app-secret",
                namespace="prod",
                key="DB_PASS",
                decode=True,
                impersonate_user=spiffe_id,
            )
        finally:
            _current_request_headers.reset(ctx_token)



