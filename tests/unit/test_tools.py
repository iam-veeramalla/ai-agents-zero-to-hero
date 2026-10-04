from unittest.mock import MagicMock, patch

from app.tools import get_pod_logs, investigate_kubernetes_logs, investigate_log_file


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
