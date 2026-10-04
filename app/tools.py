"""ADK Tools for Kubernetes Log Investigation and Pod Log Retrieval."""

import json
import os
import subprocess
from typing import Any

from app.k8s_forensics import LogAnalyzer

analyzer = LogAnalyzer()


def _get_k8s_client():
    """Initializes and returns the Kubernetes CoreV1Api client, or None if unavailable."""
    try:
        from kubernetes import client, config

        try:
            config.load_incluster_config()
        except Exception:
            config.load_kube_config()
        return client.CoreV1Api()
    except Exception:
        return None


def _get_k8s_apps_client():
    """Initializes and returns the Kubernetes AppsV1Api client, or None if unavailable."""
    try:
        from kubernetes import client, config

        try:
            config.load_incluster_config()
        except Exception:
            config.load_kube_config()
        return client.AppsV1Api()
    except Exception:
        return None


def get_pod_logs(
    pod_name: str,
    namespace: str = "default",
    container: str = "",
    tail_lines: int = 500,
    previous: bool = False,
    timestamps: bool = True,
) -> dict[str, Any]:
    """Fetches log output from a specific Kubernetes pod container.

    Args:
        pod_name: Name of the target Kubernetes pod.
        namespace: Kubernetes namespace where the pod is located.
        container: Name of the container inside the pod (optional, required if pod has multiple containers).
        tail_lines: Number of most recent log lines to retrieve.
        previous: If True, retrieve logs for the previous terminated container instance (useful for crash investigation).
        timestamps: If True, include RFC3339 timestamps at the beginning of each log line.

    Returns:
        A dictionary containing the status ('SUCCESS' or 'ERROR'), pod_name,
        namespace, container, line_count, and raw log string content or error details.
    """
    if not pod_name or not pod_name.strip():
        return {
            "status": "ERROR",
            "message": "pod_name must be provided and non-empty.",
            "pod_name": pod_name,
            "namespace": namespace,
        }

    pod_name = pod_name.strip()
    namespace = namespace.strip() if namespace else "default"
    container = container.strip() if container else ""

    # Strategy 1: Attempt retrieval via Kubernetes Python API client
    api_client = _get_k8s_client()
    if api_client is not None:
        try:
            from kubernetes.client.exceptions import ApiException

            kwargs: dict[str, Any] = {
                "name": pod_name,
                "namespace": namespace,
                "previous": previous,
                "timestamps": timestamps,
            }
            if container:
                kwargs["container"] = container
            if tail_lines and tail_lines > 0:
                kwargs["tail_lines"] = tail_lines

            raw_logs = api_client.read_namespaced_pod_log(**kwargs)
            logs_str = raw_logs if isinstance(raw_logs, str) else str(raw_logs or "")
            return {
                "status": "SUCCESS",
                "pod_name": pod_name,
                "namespace": namespace,
                "container": container,
                "line_count": len(logs_str.splitlines()),
                "logs": logs_str,
            }
        except ApiException as e:
            # If the API returned an explicit k8s error (e.g. 404 Pod not found, 400 bad container)
            return {
                "status": "ERROR",
                "message": f"Kubernetes API error (HTTP {e.status}): {e.reason or e.body or str(e)}",
                "pod_name": pod_name,
                "namespace": namespace,
            }
        except Exception:
            # Fall back to kubectl if python client hit network/config failure
            pass

    # Strategy 2: Fallback to kubectl CLI
    cmd = ["kubectl", "logs", pod_name, "-n", namespace]
    if container:
        cmd.extend(["-c", container])
    if tail_lines and tail_lines > 0:
        cmd.extend(["--tail", str(tail_lines)])
    if previous:
        cmd.append("--previous")
    if timestamps:
        cmd.append("--timestamps")

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        if proc.returncode == 0:
            return {
                "status": "SUCCESS",
                "pod_name": pod_name,
                "namespace": namespace,
                "container": container,
                "line_count": len(proc.stdout.splitlines()),
                "logs": proc.stdout,
            }
        return {
            "status": "ERROR",
            "message": f"kubectl error: {proc.stderr.strip() or proc.stdout.strip()}",
            "pod_name": pod_name,
            "namespace": namespace,
        }
    except FileNotFoundError:
        return {
            "status": "ERROR",
            "message": "Neither Kubernetes Python client nor 'kubectl' command is available.",
            "pod_name": pod_name,
            "namespace": namespace,
        }
    except Exception as exc:
        return {
            "status": "ERROR",
            "message": f"Failed to retrieve pod logs: {exc!s}",
            "pod_name": pod_name,
            "namespace": namespace,
        }


def get_pod_events(
    pod_name: str,
    namespace: str = "default",
) -> dict[str, Any]:
    """Fetches Kubernetes cluster events associated with a specific pod.

    Args:
        pod_name: Name of the target Kubernetes pod.
        namespace: Kubernetes namespace where the pod is located.

    Returns:
        A dictionary containing the status ('SUCCESS' or 'ERROR'), pod_name,
        namespace, events_count, and a structured list of event objects (type, reason,
        message, count, timestamp, source).
    """
    if not pod_name or not pod_name.strip():
        return {
            "status": "ERROR",
            "message": "pod_name must be provided and non-empty.",
            "pod_name": pod_name,
            "namespace": namespace,
        }

    pod_name = pod_name.strip()
    namespace = namespace.strip() if namespace else "default"

    # Strategy 1: Attempt retrieval via Kubernetes Python API client
    api_client = _get_k8s_client()
    if api_client is not None:
        try:
            from kubernetes.client.exceptions import ApiException

            field_selector = f"involvedObject.name={pod_name}"
            event_list = api_client.list_namespaced_event(
                namespace=namespace,
                field_selector=field_selector,
            )
            parsed_events = []
            for item in event_list.items:
                ts = (
                    item.last_timestamp.isoformat()
                    if item.last_timestamp
                    else (item.event_time.isoformat() if item.event_time else None)
                )
                source_component = item.source.component if item.source else None
                parsed_events.append(
                    {
                        "type": item.type,
                        "reason": item.reason,
                        "message": item.message,
                        "count": item.count or 1,
                        "last_timestamp": ts,
                        "source_component": source_component,
                    }
                )
            return {
                "status": "SUCCESS",
                "pod_name": pod_name,
                "namespace": namespace,
                "events_count": len(parsed_events),
                "events": parsed_events,
            }
        except ApiException as e:
            return {
                "status": "ERROR",
                "message": f"Kubernetes API error (HTTP {e.status}): {e.reason or e.body or str(e)}",
                "pod_name": pod_name,
                "namespace": namespace,
            }
        except Exception:
            # Fall back to kubectl
            pass

    # Strategy 2: Fallback to kubectl CLI
    cmd = [
        "kubectl",
        "get",
        "events",
        "-n",
        namespace,
        "--field-selector",
        f"involvedObject.name={pod_name}",
        "-o",
        "json",
    ]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        if proc.returncode == 0:
            data = json.loads(proc.stdout)
            items = data.get("items", [])
            parsed_events = []
            for item in items:
                parsed_events.append(
                    {
                        "type": item.get("type"),
                        "reason": item.get("reason"),
                        "message": item.get("message"),
                        "count": item.get("count", 1),
                        "last_timestamp": item.get("lastTimestamp") or item.get("eventTime"),
                        "source_component": item.get("source", {}).get("component")
                        if isinstance(item.get("source"), dict)
                        else None,
                    }
                )
            return {
                "status": "SUCCESS",
                "pod_name": pod_name,
                "namespace": namespace,
                "events_count": len(parsed_events),
                "events": parsed_events,
            }
        return {
            "status": "ERROR",
            "message": f"kubectl error: {proc.stderr.strip() or proc.stdout.strip()}",
            "pod_name": pod_name,
            "namespace": namespace,
        }
    except FileNotFoundError:
        return {
            "status": "ERROR",
            "message": "Neither Kubernetes Python client nor 'kubectl' command is available.",
            "pod_name": pod_name,
            "namespace": namespace,
        }
    except Exception as exc:
        return {
            "status": "ERROR",
            "message": f"Failed to retrieve pod events: {exc!s}",
            "pod_name": pod_name,
            "namespace": namespace,
        }


def get_deployment_history(
    deployment_name: str = "",
    namespace: str = "default",
    pod_name: str = "",
) -> dict[str, Any]:
    """Retrieves deployment rollout history and analyzes container image/version changes across revisions.

    Args:
        deployment_name: Name of the Kubernetes Deployment to inspect (optional if pod_name is provided).
        namespace: Kubernetes namespace where the deployment or pod is located.
        pod_name: Name of a specific pod to automatically resolve its parent deployment and inspect history (optional if deployment_name is provided).

    Returns:
        A dictionary containing the status ('SUCCESS' or 'ERROR'), deployment_name,
        namespace, current_version, previous_version, version_changed flag,
        a list of revisions with container images, and an analysis summary.
    """
    deployment_name = deployment_name.strip() if deployment_name else ""
    namespace = namespace.strip() if namespace else "default"
    pod_name = pod_name.strip() if pod_name else ""

    if not deployment_name and not pod_name:
        return {
            "status": "ERROR",
            "message": "Either deployment_name or pod_name must be provided to fetch rollout history.",
            "namespace": namespace,
        }

    # Step 1: If pod_name is provided but deployment_name is not, resolve the parent Deployment
    if pod_name and not deployment_name:
        core_client = _get_k8s_client()
        if core_client is not None:
            try:
                pod = core_client.read_namespaced_pod(name=pod_name, namespace=namespace)
                for ref in pod.metadata.owner_references or []:
                    if ref.kind == "ReplicaSet":
                        rs_name = ref.name
                        apps_client = _get_k8s_apps_client()
                        if apps_client is not None:
                            try:
                                rs = apps_client.read_namespaced_replica_set(
                                    name=rs_name, namespace=namespace
                                )
                                for rs_ref in rs.metadata.owner_references or []:
                                    if rs_ref.kind == "Deployment":
                                        deployment_name = rs_ref.name
                                        break
                            except Exception:
                                pass
                        if not deployment_name and "-" in rs_name:
                            deployment_name = rs_name.rsplit("-", 1)[0]
                        break
            except Exception:
                pass

        # Fallback resolution via kubectl if deployment_name still unresolved
        if not deployment_name:
            try:
                res_pod = subprocess.run(
                    [
                        "kubectl",
                        "get",
                        "pod",
                        pod_name,
                        "-n",
                        namespace,
                        "-o",
                        "jsonpath={.metadata.ownerReferences[0].name}",
                    ],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )
                if res_pod.returncode == 0 and res_pod.stdout.strip():
                    owner = res_pod.stdout.strip()
                    res_rs = subprocess.run(
                        [
                            "kubectl",
                            "get",
                            "rs",
                            owner,
                            "-n",
                            namespace,
                            "-o",
                            "jsonpath={.metadata.ownerReferences[0].name}",
                        ],
                        capture_output=True,
                        text=True,
                        timeout=10,
                        check=False,
                    )
                    if res_rs.returncode == 0 and res_rs.stdout.strip():
                        deployment_name = res_rs.stdout.strip()
                    elif "-" in owner:
                        deployment_name = owner.rsplit("-", 1)[0]
            except Exception:
                pass

        if not deployment_name:
            if pod_name.count("-") >= 2:
                deployment_name = pod_name.rsplit("-", 2)[0]
            else:
                deployment_name = pod_name

    # Step 2: Fetch revisions for the deployment
    revisions_data: list[dict[str, Any]] = []

    # Attempt via Kubernetes Python API client
    apps_client = _get_k8s_apps_client()
    if apps_client is not None:
        try:
            from kubernetes.client.exceptions import ApiException

            rs_list = apps_client.list_namespaced_replica_set(namespace=namespace)
            for rs in rs_list.items:
                is_owned = False
                for owner in rs.metadata.owner_references or []:
                    if owner.kind == "Deployment" and owner.name == deployment_name:
                        is_owned = True
                        break
                if not is_owned and rs.metadata.name.startswith(f"{deployment_name}-"):
                    is_owned = True

                if is_owned:
                    rev_str = (rs.metadata.annotations or {}).get(
                        "deployment.kubernetes.io/revision", "0"
                    )
                    try:
                        rev_num = int(rev_str)
                    except ValueError:
                        rev_num = 0

                    containers = [
                        {"name": c.name, "image": c.image}
                        for c in (rs.spec.template.spec.containers or [])
                    ]
                    revisions_data.append(
                        {
                            "revision": rev_num,
                            "replica_set": rs.metadata.name,
                            "created_at": rs.metadata.creation_timestamp.isoformat()
                            if rs.metadata.creation_timestamp
                            else None,
                            "change_cause": (rs.metadata.annotations or {}).get(
                                "kubernetes.io/change-cause"
                            ),
                            "containers": containers,
                        }
                    )
        except ApiException as e:
            return {
                "status": "ERROR",
                "message": f"Kubernetes API error (HTTP {e.status}): {e.reason or e.body or str(e)}",
                "deployment_name": deployment_name,
                "namespace": namespace,
            }
        except Exception:
            pass

    # Fallback via kubectl if no revisions retrieved via Python client
    if not revisions_data:
        try:
            cmd = ["kubectl", "get", "rs", "-n", namespace, "-o", "json"]
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            if proc.returncode == 0:
                data = json.loads(proc.stdout)
                for item in data.get("items", []):
                    meta = item.get("metadata", {})
                    owners = meta.get("ownerReferences", [])
                    is_owned = any(
                        o.get("kind") == "Deployment" and o.get("name") == deployment_name
                        for o in owners
                    )
                    if not is_owned and meta.get("name", "").startswith(f"{deployment_name}-"):
                        is_owned = True

                    if is_owned:
                        annotations = meta.get("annotations", {})
                        rev_str = annotations.get("deployment.kubernetes.io/revision", "0")
                        try:
                            rev_num = int(rev_str)
                        except ValueError:
                            rev_num = 0
                        spec_containers = (
                            item.get("spec", {})
                            .get("template", {})
                            .get("spec", {})
                            .get("containers", [])
                        )
                        containers = [
                            {"name": c.get("name"), "image": c.get("image")}
                            for c in spec_containers
                        ]
                        revisions_data.append(
                            {
                                "revision": rev_num,
                                "replica_set": meta.get("name"),
                                "created_at": meta.get("creationTimestamp"),
                                "change_cause": annotations.get("kubernetes.io/change-cause"),
                                "containers": containers,
                            }
                        )
        except Exception:
            pass

    if not revisions_data:
        return {
            "status": "ERROR",
            "message": f"No deployment history or ReplicaSets found for deployment '{deployment_name}' in namespace '{namespace}'.",
            "deployment_name": deployment_name,
            "namespace": namespace,
        }

    # Step 3: Sort revisions chronologically by revision number
    revisions_data.sort(key=lambda x: x["revision"])

    latest = revisions_data[-1]
    current_containers = latest["containers"]
    prev = revisions_data[-2] if len(revisions_data) >= 2 else None
    prev_containers = prev["containers"] if prev else []

    changes = []
    version_changed = False
    if prev:
        prev_map = {c["name"]: c["image"] for c in prev_containers}
        for c in current_containers:
            c_name = c["name"]
            curr_img = c["image"]
            old_img = prev_map.get(c_name)
            if old_img and old_img != curr_img:
                version_changed = True
                changes.append(
                    f"Container '{c_name}' image changed from '{old_img}' to '{curr_img}'."
                )
            elif not old_img:
                version_changed = True
                changes.append(f"New container '{c_name}' added with image '{curr_img}'.")
    else:
        changes.append(
            f"Initial release (revision {latest['revision']}) with image(s): "
            + ", ".join(f"{c['name']}={c['image']}" for c in current_containers)
        )

    if version_changed:
        analysis = (
            f"Detected version change in revision {latest['revision']} (created at {latest['created_at']}): "
            + " ".join(changes)
        )
    else:
        analysis = (
            f"Active revision is {latest['revision']}. No recent image version changes detected between the last two revisions."
        )

    return {
        "status": "SUCCESS",
        "deployment_name": deployment_name,
        "namespace": namespace,
        "total_revisions": len(revisions_data),
        "current_revision": latest["revision"],
        "current_version": current_containers,
        "previous_revision": prev["revision"] if prev else None,
        "previous_version": prev_containers if prev else None,
        "version_changed": version_changed,
        "analysis": analysis,
        "revisions": revisions_data,
    }


def investigate_kubernetes_logs(logs: str, max_evidence_items: int = 10) -> dict[str, Any]:
    """Performs deep forensic investigation on Kubernetes container logs.

    Extracts root causes, supporting evidence with exact line numbers and timestamps,
    reconstructs an incident timeline, and prescribes remediation actions.

    Args:
        logs: Raw multi-line string containing Kubernetes container or application logs.
        max_evidence_items: Maximum number of supporting evidence snippets to extract.

    Returns:
        A structured dictionary containing severity, root causes, supporting evidence,
        timeline, impact assessment, and remediation steps.
    """
    if not logs or not logs.strip():
        return {
            "status": "ERROR",
            "message": "Logs input is empty. Please provide log text to investigate.",
        }

    report = analyzer.analyze(logs, max_evidence_items=max_evidence_items)
    return report.model_dump()


def investigate_log_file(file_path: str, max_evidence_items: int = 10) -> dict[str, Any]:
    """Reads logs from a local file path and performs complete Kubernetes forensic investigation.

    Args:
        file_path: Absolute or relative path to the log file on disk.
        max_evidence_items: Maximum number of supporting evidence snippets to extract.

    Returns:
        A structured dictionary containing the detailed investigation report.
    """
    if not os.path.exists(file_path):
        return {
            "status": "ERROR",
            "message": f"Log file not found at path: {file_path}",
        }

    try:
        with open(file_path, encoding="utf-8", errors="replace") as f:
            content = f.read()
        return investigate_kubernetes_logs(content, max_evidence_items=max_evidence_items)
    except Exception as e:
        return {
            "status": "ERROR",
            "message": f"Failed to read file {file_path}: {e!s}",
        }
