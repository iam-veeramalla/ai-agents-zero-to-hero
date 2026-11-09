"""ADK Tools for Kubernetes Log Investigation and Pod Log Retrieval."""

import base64
import json
import os
import subprocess
from datetime import UTC, datetime
from typing import Any

from app.k8s_forensics import LogAnalyzer

analyzer = LogAnalyzer()


def _format_k8s_api_error(e: Any) -> str:
    """Formats a Kubernetes ApiException into a descriptive error string including body message."""
    reason = getattr(e, "reason", None) or ""
    body = getattr(e, "body", None)
    detail = ""
    if body:
        try:
            body_text = body.decode("utf-8") if isinstance(body, bytes) else str(body)
            body_json = json.loads(body_text)
            detail = body_json.get("message") or ""
        except Exception:
            detail = str(body).strip()
    if reason and detail and detail != reason:
        msg = f"{reason} - {detail}"
    else:
        msg = detail or reason or str(e)
    return f"Kubernetes API error (HTTP {getattr(e, 'status', 'Unknown')}): {msg}"


def _get_k8s_client(impersonate_user: str | None = None):
    """Initializes and returns the Kubernetes CoreV1Api client, or None if unavailable."""
    try:
        from kubernetes import client, config

        try:
            config.load_incluster_config()
        except Exception:
            config.load_kube_config()
        api_client = client.ApiClient()
        if impersonate_user:
            api_client.set_default_header("Impersonate-User", impersonate_user)
        return client.CoreV1Api(api_client=api_client)
    except Exception:
        return None


def _get_k8s_apps_client(impersonate_user: str | None = None):
    """Initializes and returns the Kubernetes AppsV1Api client, or None if unavailable."""
    try:
        from kubernetes import client, config

        try:
            config.load_incluster_config()
        except Exception:
            config.load_kube_config()
        api_client = client.ApiClient()
        if impersonate_user:
            api_client.set_default_header("Impersonate-User", impersonate_user)
        return client.AppsV1Api(api_client=api_client)
    except Exception:
        return None


def list_pods(
    namespace: str = "default",
    all_namespaces: bool = False,
    impersonate_user: str | None = None,
) -> dict[str, Any]:
    """Lists Kubernetes pods in a namespace or across all namespaces with their status, readiness, restarts, and container states.

    Args:
        namespace: Kubernetes namespace to list pods from (defaults to 'default'). Pass 'all' or set all_namespaces=True to inspect all namespaces.
        all_namespaces: If True, lists pods across all namespaces in the cluster.
        impersonate_user: Optional Kubernetes user/SPIFFE identity to impersonate via Impersonate-User.

    Returns:
        A dictionary containing the status ('SUCCESS' or 'ERROR'), namespace scope,
        total_pods, unhealthy_pods count, and a list of pod summaries.
    """
    namespace = namespace.strip() if namespace else "default"
    if namespace.lower() in ("all", "*"):
        all_namespaces = True

    api_client = (
        _get_k8s_client(impersonate_user=impersonate_user)
        if impersonate_user
        else _get_k8s_client()
    )
    if api_client is not None:
        try:
            from kubernetes.client.exceptions import ApiException

            if all_namespaces:
                pod_list = api_client.list_pod_for_all_namespaces()
            else:
                pod_list = api_client.list_namespaced_pod(namespace=namespace)

            pods_summary = []
            unhealthy_count = 0
            for pod in pod_list.items:
                p_name = pod.metadata.name if pod.metadata else ""
                p_ns = pod.metadata.namespace if pod.metadata else namespace
                phase = pod.status.phase if pod.status else "Unknown"
                node_name = pod.spec.node_name if pod.spec else None

                c_statuses = (pod.status.container_statuses if pod.status else None) or []
                total_c = len(c_statuses) or len((pod.spec.containers if pod.spec else None) or [])
                ready_c = sum(1 for cs in c_statuses if cs.ready)
                restarts = sum((cs.restart_count or 0) for cs in c_statuses)

                reasons = []
                for cs in c_statuses:
                    if cs.state:
                        if cs.state.waiting and cs.state.waiting.reason:
                            reasons.append(cs.state.waiting.reason)
                        elif cs.state.terminated and cs.state.terminated.reason:
                            reasons.append(cs.state.terminated.reason)
                    if cs.last_state and cs.last_state.terminated and cs.last_state.terminated.reason:
                        term_reason = cs.last_state.terminated.reason
                        if term_reason not in reasons:
                            reasons.append(f"LastTerminated:{term_reason}")

                reason_str = ", ".join(reasons) if reasons else phase
                is_healthy = (
                    (phase == "Running" and ready_c == total_c and total_c > 0 and not reasons)
                    or phase == "Succeeded"
                )
                if not is_healthy:
                    unhealthy_count += 1

                pods_summary.append(
                    {
                        "name": p_name,
                        "namespace": p_ns,
                        "phase": phase,
                        "ready": f"{ready_c}/{total_c}",
                        "restarts": restarts,
                        "reason": reason_str,
                        "healthy": is_healthy,
                        "node_name": node_name,
                    }
                )

            return {
                "status": "SUCCESS",
                "namespace": "all" if all_namespaces else namespace,
                "total_pods": len(pods_summary),
                "unhealthy_pods": unhealthy_count,
                "pods": pods_summary,
            }
        except ApiException as e:
            return {
                "status": "ERROR",
                "message": _format_k8s_api_error(e),
                "namespace": "all" if all_namespaces else namespace,
            }
        except Exception:
            pass

    cmd = ["kubectl", "get", "pods"]
    if impersonate_user:
        cmd.append(f"--as={impersonate_user}")
    if all_namespaces:
        cmd.append("-A")
    else:
        cmd.extend(["-n", namespace])
    cmd.extend(["-o", "json"])

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
            pods_summary = []
            unhealthy_count = 0
            for item in items:
                meta = item.get("metadata", {})
                spec = item.get("spec", {})
                status = item.get("status", {})
                phase = status.get("phase", "Unknown")
                c_statuses = status.get("containerStatuses", []) or []
                total_c = len(c_statuses) or len(spec.get("containers", []) or [])
                ready_c = sum(1 for cs in c_statuses if cs.get("ready"))
                restarts = sum(cs.get("restartCount", 0) for cs in c_statuses)

                reasons = []
                for cs in c_statuses:
                    state = cs.get("state", {})
                    if "waiting" in state and state["waiting"].get("reason"):
                        reasons.append(state["waiting"]["reason"])
                    elif "terminated" in state and state["terminated"].get("reason"):
                        reasons.append(state["terminated"]["reason"])
                    last_state = cs.get("lastState", {})
                    if "terminated" in last_state and last_state["terminated"].get("reason"):
                        tr = last_state["terminated"]["reason"]
                        if tr not in reasons:
                            reasons.append(f"LastTerminated:{tr}")

                reason_str = ", ".join(reasons) if reasons else phase
                is_healthy = (
                    (phase == "Running" and ready_c == total_c and total_c > 0 and not reasons)
                    or phase == "Succeeded"
                )
                if not is_healthy:
                    unhealthy_count += 1

                pods_summary.append(
                    {
                        "name": meta.get("name", ""),
                        "namespace": meta.get("namespace", namespace),
                        "phase": phase,
                        "ready": f"{ready_c}/{total_c}",
                        "restarts": restarts,
                        "reason": reason_str,
                        "healthy": is_healthy,
                        "node_name": spec.get("nodeName"),
                    }
                )

            return {
                "status": "SUCCESS",
                "namespace": "all" if all_namespaces else namespace,
                "total_pods": len(pods_summary),
                "unhealthy_pods": unhealthy_count,
                "pods": pods_summary,
            }
        return {
            "status": "ERROR",
            "message": f"kubectl error: {proc.stderr.strip() or proc.stdout.strip()}",
            "namespace": "all" if all_namespaces else namespace,
        }
    except FileNotFoundError:
        return {
            "status": "ERROR",
            "message": "Neither Kubernetes Python client nor 'kubectl' command is available.",
            "namespace": "all" if all_namespaces else namespace,
        }
    except Exception as exc:
        return {
            "status": "ERROR",
            "message": f"Failed to list pods: {exc!s}",
            "namespace": "all" if all_namespaces else namespace,
        }


def get_pod_logs(
    pod_name: str,
    namespace: str = "default",
    container: str = "",
    tail_lines: int = 500,
    previous: bool = False,
    timestamps: bool = True,
    impersonate_user: str | None = None,
) -> dict[str, Any]:
    """Fetches log output from a specific Kubernetes pod container.

    Args:
        pod_name: Name of the target Kubernetes pod.
        namespace: Kubernetes namespace where the pod is located.
        container: Name of the container inside the pod (optional, required if pod has multiple containers).
        tail_lines: Number of most recent log lines to retrieve.
        previous: If True, retrieve logs for the previous terminated container instance (useful for crash investigation).
        timestamps: If True, include RFC3339 timestamps at the beginning of each log line.
        impersonate_user: Optional Kubernetes user identity (e.g. SPIFFE ID) to impersonate.

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
    api_client = _get_k8s_client(impersonate_user=impersonate_user)
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
                "message": _format_k8s_api_error(e),
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
    if impersonate_user:
        cmd.append(f"--as={impersonate_user}")

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
    impersonate_user: str | None = None,
) -> dict[str, Any]:
    """Fetches Kubernetes cluster events associated with a specific pod.

    Args:
        pod_name: Name of the target Kubernetes pod.
        namespace: Kubernetes namespace where the pod is located.
        impersonate_user: Optional Kubernetes user identity (e.g. SPIFFE ID) to impersonate.

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
    api_client = _get_k8s_client(impersonate_user=impersonate_user)
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
                "message": _format_k8s_api_error(e),
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
    if impersonate_user:
        cmd.append(f"--as={impersonate_user}")
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


def _resolve_deployment_name(
    pod_name: str,
    namespace: str = "default",
    impersonate_user: str | None = None,
) -> str:
    """Helper to resolve parent deployment name from a pod name."""
    if not pod_name:
        return ""

    core_client = _get_k8s_client(impersonate_user=impersonate_user)
    if core_client is not None:
        try:
            pod = core_client.read_namespaced_pod(name=pod_name, namespace=namespace)
            for ref in pod.metadata.owner_references or []:
                if ref.kind == "ReplicaSet":
                    rs_name = ref.name
                    apps_client = _get_k8s_apps_client(impersonate_user=impersonate_user)
                    if apps_client is not None:
                        try:
                            rs = apps_client.read_namespaced_replica_set(
                                name=rs_name, namespace=namespace
                            )
                            for rs_ref in rs.metadata.owner_references or []:
                                if rs_ref.kind == "Deployment":
                                    return rs_ref.name
                        except Exception:
                            pass
                    if "-" in rs_name:
                        return rs_name.rsplit("-", 1)[0]
                    return rs_name
        except Exception:
            pass

    try:
        pod_cmd = [
            "kubectl",
            "get",
            "pod",
            pod_name,
            "-n",
            namespace,
            "-o",
            "jsonpath={.metadata.ownerReferences[0].name}",
        ]
        if impersonate_user:
            pod_cmd.append(f"--as={impersonate_user}")
        res_pod = subprocess.run(
            pod_cmd,
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        if res_pod.returncode == 0 and res_pod.stdout.strip():
            owner = res_pod.stdout.strip()
            rs_cmd = [
                "kubectl",
                "get",
                "rs",
                owner,
                "-n",
                namespace,
                "-o",
                "jsonpath={.metadata.ownerReferences[0].name}",
            ]
            if impersonate_user:
                rs_cmd.append(f"--as={impersonate_user}")
            res_rs = subprocess.run(
                rs_cmd,
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            if res_rs.returncode == 0 and res_rs.stdout.strip():
                return res_rs.stdout.strip()
            elif "-" in owner:
                return owner.rsplit("-", 1)[0]
            return owner
    except Exception:
        pass

    if pod_name.count("-") >= 2:
        return pod_name.rsplit("-", 2)[0]
    return pod_name


def get_deployment_history(
    deployment_name: str = "",
    namespace: str = "default",
    pod_name: str = "",
    impersonate_user: str | None = None,
) -> dict[str, Any]:
    """Retrieves deployment rollout history and analyzes container image/version changes across revisions.

    Args:
        deployment_name: Name of the Kubernetes Deployment to inspect (optional if pod_name is provided).
        namespace: Kubernetes namespace where the deployment or pod is located.
        pod_name: Name of a specific pod to automatically resolve its parent deployment and inspect history (optional if deployment_name is provided).
        impersonate_user: Optional Kubernetes user identity (e.g. SPIFFE ID) to impersonate.

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
        deployment_name = _resolve_deployment_name(
            pod_name=pod_name,
            namespace=namespace,
            impersonate_user=impersonate_user,
        )

        if not deployment_name:
            if pod_name.count("-") >= 2:
                deployment_name = pod_name.rsplit("-", 2)[0]
            else:
                deployment_name = pod_name

    # Step 2: Fetch revisions for the deployment
    revisions_data: list[dict[str, Any]] = []

    # Attempt via Kubernetes Python API client
    apps_client = _get_k8s_apps_client(impersonate_user=impersonate_user)
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
                "message": _format_k8s_api_error(e),
                "deployment_name": deployment_name,
                "namespace": namespace,
            }
        except Exception:
            pass

    # Fallback via kubectl if no revisions retrieved via Python client
    if not revisions_data:
        try:
            cmd = ["kubectl", "get", "rs", "-n", namespace, "-o", "json"]
            if impersonate_user:
                cmd.append(f"--as={impersonate_user}")
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


def restart_deployment(
    deployment_name: str = "",
    namespace: str = "default",
    pod_name: str = "",
    impersonate_user: str | None = None,
) -> dict[str, Any]:
    """Triggers a rolling restart of a Kubernetes Deployment (equivalent to `kubectl rollout restart`).

    Args:
        deployment_name: Name of the Deployment to restart (optional if pod_name is provided).
        namespace: Kubernetes namespace where the deployment is located (defaults to 'default').
        pod_name: Name of a specific pod to automatically resolve its parent deployment and restart it (optional if deployment_name is provided).
        impersonate_user: Optional Kubernetes user identity (e.g. SPIFFE ID) to impersonate.

    Returns:
        A dictionary containing the status ('SUCCESS' or 'ERROR'), deployment_name,
        namespace, restarted_at timestamp, and execution message.
    """
    deployment_name = deployment_name.strip() if deployment_name else ""
    namespace = namespace.strip() if namespace else "default"
    pod_name = pod_name.strip() if pod_name else ""

    if not deployment_name and not pod_name:
        return {
            "status": "ERROR",
            "message": "Either deployment_name or pod_name must be provided to restart a deployment.",
            "namespace": namespace,
        }

    if pod_name and not deployment_name:
        deployment_name = _resolve_deployment_name(
            pod_name=pod_name,
            namespace=namespace,
            impersonate_user=impersonate_user,
        )

    if not deployment_name:
        return {
            "status": "ERROR",
            "message": f"Could not determine parent deployment for pod '{pod_name}'.",
            "namespace": namespace,
        }

    now_iso = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")

    # Strategy 1: Attempt via Kubernetes Python API client (patch template annotations)
    apps_client = _get_k8s_apps_client(impersonate_user=impersonate_user)
    if apps_client is not None:
        try:
            from kubernetes.client.exceptions import ApiException

            patch_body = {
                "spec": {
                    "template": {
                        "metadata": {
                            "annotations": {
                                "kubectl.kubernetes.io/restartedAt": now_iso
                            }
                        }
                    }
                }
            }
            apps_client.patch_namespaced_deployment(
                name=deployment_name,
                namespace=namespace,
                body=patch_body,
            )
            return {
                "status": "SUCCESS",
                "deployment_name": deployment_name,
                "namespace": namespace,
                "restarted_at": now_iso,
                "message": f"Deployment '{deployment_name}' rolling restart triggered successfully at {now_iso}.",
            }
        except ApiException as e:
            return {
                "status": "ERROR",
                "message": _format_k8s_api_error(e),
                "deployment_name": deployment_name,
                "namespace": namespace,
            }
        except Exception:
            pass

    # Strategy 2: Fallback to kubectl rollout restart
    cmd = ["kubectl", "rollout", "restart", f"deployment/{deployment_name}", "-n", namespace]
    if impersonate_user:
        cmd.append(f"--as={impersonate_user}")

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
                "deployment_name": deployment_name,
                "namespace": namespace,
                "restarted_at": now_iso,
                "message": proc.stdout.strip() or f"Deployment '{deployment_name}' restarted successfully.",
            }
        return {
            "status": "ERROR",
            "message": f"kubectl error: {proc.stderr.strip() or proc.stdout.strip()}",
            "deployment_name": deployment_name,
            "namespace": namespace,
        }
    except FileNotFoundError:
        return {
            "status": "ERROR",
            "message": "Neither Kubernetes Python client nor 'kubectl' command is available.",
            "deployment_name": deployment_name,
            "namespace": namespace,
        }
    except Exception as exc:
        return {
            "status": "ERROR",
            "message": f"Failed to restart deployment: {exc!s}",
            "deployment_name": deployment_name,
            "namespace": namespace,
        }


def get_secret(
    secret_name: str,
    namespace: str = "default",
    key: str = "",
    decode: bool = True,
    impersonate_user: str | None = None,
) -> dict[str, Any]:
    """Retrieves metadata, keys, and values for a Kubernetes Secret in a namespace.

    Args:
        secret_name: Name of the Kubernetes Secret to retrieve.
        namespace: Kubernetes namespace where the secret is located (defaults to 'default').
        key: Specific key inside the secret data to retrieve. If empty, all keys and values are returned.
        decode: If True, base64-decodes values into UTF-8 strings. If False, returns raw base64 data.
        impersonate_user: Optional Kubernetes user identity (e.g. SPIFFE ID) to impersonate.

    Returns:
        A dictionary containing the status ('SUCCESS' or 'ERROR'), secret_name,
        namespace, type, keys list, and secret data mapping or specific key value.
    """
    secret_name = secret_name.strip() if secret_name else ""
    namespace = namespace.strip() if namespace else "default"
    key = key.strip() if key else ""

    if not secret_name:
        return {
            "status": "ERROR",
            "message": "secret_name must be provided and non-empty.",
            "namespace": namespace,
        }

    # Strategy 1: Attempt retrieval via Kubernetes Python API client
    core_client = _get_k8s_client(impersonate_user=impersonate_user)
    if core_client is not None:
        try:
            from kubernetes.client.exceptions import ApiException

            secret_obj = core_client.read_namespaced_secret(name=secret_name, namespace=namespace)
            sec_type = secret_obj.type or "Opaque"
            raw_data = secret_obj.data or {}
            keys = list(raw_data.keys())

            if key and key not in raw_data:
                return {
                    "status": "ERROR",
                    "message": f"Key '{key}' not found in secret '{secret_name}'. Available keys: {keys}",
                    "secret_name": secret_name,
                    "namespace": namespace,
                    "keys": keys,
                }

            processed_data: dict[str, Any] = {}
            for k, val in raw_data.items():
                if key and k != key:
                    continue
                if decode and val is not None:
                    try:
                        decoded_bytes = base64.b64decode(val)
                        try:
                            processed_data[k] = decoded_bytes.decode("utf-8")
                        except UnicodeDecodeError:
                            processed_data[k] = f"<binary: {len(decoded_bytes)} bytes>"
                    except Exception:
                        processed_data[k] = str(val)
                else:
                    processed_data[k] = str(val) if val is not None else ""

            result: dict[str, Any] = {
                "status": "SUCCESS",
                "secret_name": secret_name,
                "namespace": namespace,
                "type": sec_type,
                "keys": keys,
                "data": processed_data,
            }
            if key:
                result["key"] = key
                result["value"] = processed_data.get(key, "")
            return result
        except ApiException as e:
            return {
                "status": "ERROR",
                "message": _format_k8s_api_error(e),
                "secret_name": secret_name,
                "namespace": namespace,
            }
        except Exception:
            pass

    # Strategy 2: Fallback to kubectl get secret -o json
    cmd = ["kubectl", "get", "secret", secret_name, "-n", namespace, "-o", "json"]
    if impersonate_user:
        cmd.append(f"--as={impersonate_user}")

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        if proc.returncode == 0:
            secret_json = json.loads(proc.stdout)
            sec_type = secret_json.get("type", "Opaque")
            raw_data = secret_json.get("data", {}) or {}
            keys = list(raw_data.keys())

            if key and key not in raw_data:
                return {
                    "status": "ERROR",
                    "message": f"Key '{key}' not found in secret '{secret_name}'. Available keys: {keys}",
                    "secret_name": secret_name,
                    "namespace": namespace,
                    "keys": keys,
                }

            processed_data = {}
            for k, val in raw_data.items():
                if key and k != key:
                    continue
                if decode and val is not None:
                    try:
                        decoded_bytes = base64.b64decode(val)
                        try:
                            processed_data[k] = decoded_bytes.decode("utf-8")
                        except UnicodeDecodeError:
                            processed_data[k] = f"<binary: {len(decoded_bytes)} bytes>"
                    except Exception:
                        processed_data[k] = str(val)
                else:
                    processed_data[k] = str(val) if val is not None else ""

            result = {
                "status": "SUCCESS",
                "secret_name": secret_name,
                "namespace": namespace,
                "type": sec_type,
                "keys": keys,
                "data": processed_data,
            }
            if key:
                result["key"] = key
                result["value"] = processed_data.get(key, "")
            return result
        return {
            "status": "ERROR",
            "message": f"kubectl error: {proc.stderr.strip() or proc.stdout.strip()}",
            "secret_name": secret_name,
            "namespace": namespace,
        }
    except FileNotFoundError:
        return {
            "status": "ERROR",
            "message": "Neither Kubernetes Python client nor 'kubectl' command is available.",
            "secret_name": secret_name,
            "namespace": namespace,
        }
    except Exception as exc:
        return {
            "status": "ERROR",
            "message": f"Failed to get secret: {exc!s}",
            "secret_name": secret_name,
            "namespace": namespace,
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


def _parse_k8s_node(node: Any) -> dict[str, Any]:
    """Parses a Kubernetes V1Node object or JSON dictionary into a normalized dictionary representation."""
    is_dict = isinstance(node, dict)

    # Extract metadata
    metadata = node.get("metadata", {}) if is_dict else getattr(node, "metadata", None)
    name = (metadata.get("name") if is_dict else getattr(metadata, "name", "")) or ""
    labels = (metadata.get("labels") or {}) if is_dict else (getattr(metadata, "labels", None) or {})
    created = metadata.get("creationTimestamp") if is_dict else getattr(metadata, "creation_timestamp", None)
    created_str = created.isoformat() if hasattr(created, "isoformat") else (str(created) if created else None)

    # Extract node roles
    roles = []
    for k in labels.keys():
        if k.startswith("node-role.kubernetes.io/"):
            roles.append(k.split("/", 1)[1])
        elif k == "kubernetes.io/role":
            roles.append(labels[k])
    if not roles:
        roles = ["worker"]

    # Extract spec & taints
    spec = node.get("spec", {}) if is_dict else getattr(node, "spec", None)
    taints_raw = (spec.get("taints", []) if is_dict else getattr(spec, "taints", None)) or []
    taints = []
    for t in taints_raw:
        t_key = t.get("key") if isinstance(t, dict) else getattr(t, "key", "")
        t_val = t.get("value") if isinstance(t, dict) else getattr(t, "value", None)
        t_eff = t.get("effect") if isinstance(t, dict) else getattr(t, "effect", "")
        taints.append({"key": t_key, "value": t_val, "effect": t_eff})

    # Extract status & conditions
    status = node.get("status", {}) if is_dict else getattr(node, "status", None)
    conditions_raw = (status.get("conditions", []) if is_dict else getattr(status, "conditions", None)) or []

    conditions = []
    ready_status = "Unknown"
    is_ready = False
    pressure_detected = False
    issues = []

    for c in conditions_raw:
        c_type = c.get("type") if isinstance(c, dict) else getattr(c, "type", "")
        c_status = c.get("status") if isinstance(c, dict) else getattr(c, "status", "")
        c_reason = c.get("reason") if isinstance(c, dict) else getattr(c, "reason", "")
        c_msg = c.get("message") if isinstance(c, dict) else getattr(c, "message", "")
        c_time = c.get("lastTransitionTime") if is_dict else getattr(c, "last_transition_time", None)
        time_str = c_time.isoformat() if hasattr(c_time, "isoformat") else (str(c_time) if c_time else None)

        conditions.append(
            {
                "type": c_type,
                "status": c_status,
                "reason": c_reason,
                "message": c_msg,
                "last_transition_time": time_str,
            }
        )

        if c_type == "Ready":
            ready_status = "Ready" if c_status == "True" else ("NotReady" if c_status == "False" else "Unknown")
            is_ready = c_status == "True"
            if not is_ready:
                issues.append(
                    f"Node '{name}' is {ready_status} (Reason: {c_reason or 'Unknown'}, Message: {c_msg or 'N/A'})"
                )
        elif c_type in ("MemoryPressure", "DiskPressure", "PIDPressure", "NetworkUnavailable"):
            if c_status == "True":
                pressure_detected = True
                issues.append(
                    f"Node '{name}' condition {c_type} is True (Reason: {c_reason or 'Unknown'}, Message: {c_msg or 'N/A'})"
                )

    for taint in taints:
        t_key = taint.get("key") or ""
        if "not-ready" in t_key or "unreachable" in t_key or "memory-pressure" in t_key or "disk-pressure" in t_key:
            issues.append(
                f"Node '{name}' has critical taint: {t_key}={taint.get('value')}:{taint.get('effect')}"
            )

    # Capacity & Allocatable
    capacity = (status.get("capacity", {}) if is_dict else getattr(status, "capacity", None)) or {}
    allocatable = (status.get("allocatable", {}) if is_dict else getattr(status, "allocatable", None)) or {}

    # Node Info
    node_info_raw = status.get("nodeInfo", {}) if is_dict else getattr(status, "node_info", None)
    if is_dict:
        node_info = {
            "kubelet_version": node_info_raw.get("kubeletVersion", ""),
            "os_image": node_info_raw.get("osImage", ""),
            "container_runtime_version": node_info_raw.get("containerRuntimeVersion", ""),
            "kernel_version": node_info_raw.get("kernelVersion", ""),
            "architecture": node_info_raw.get("architecture", ""),
            "operating_system": node_info_raw.get("operatingSystem", ""),
        } if isinstance(node_info_raw, dict) else {}
    else:
        node_info = {
            "kubelet_version": getattr(node_info_raw, "kubelet_version", "") if node_info_raw else "",
            "os_image": getattr(node_info_raw, "os_image", "") if node_info_raw else "",
            "container_runtime_version": getattr(node_info_raw, "container_runtime_version", "") if node_info_raw else "",
            "kernel_version": getattr(node_info_raw, "kernel_version", "") if node_info_raw else "",
            "architecture": getattr(node_info_raw, "architecture", "") if node_info_raw else "",
            "operating_system": getattr(node_info_raw, "operating_system", "") if node_info_raw else "",
        }

    return {
        "name": name,
        "roles": roles,
        "status": ready_status,
        "ready": is_ready,
        "pressure_detected": pressure_detected,
        "issues": issues,
        "conditions": conditions,
        "capacity": dict(capacity),
        "allocatable": dict(allocatable),
        "taints": taints,
        "node_info": node_info,
        "creation_timestamp": created_str,
    }


def get_nodes_info(
    node_name: str = "",
    impersonate_user: str | None = None,
) -> dict[str, Any]:
    """Retrieves Kubernetes node status, conditions, resource capacity, allocatable limits, and taints.

    Inspects cluster nodes to identify Node NotReady conditions, MemoryPressure,
    DiskPressure, PIDPressure, resource exhaustion, and scheduling taints.

    Args:
        node_name: Name of a specific Kubernetes node to inspect. If empty, retrieves and analyzes all nodes in the cluster.
        impersonate_user: Optional Kubernetes user identity (e.g. SPIFFE ID) to impersonate.

    Returns:
        A dictionary containing the status ('SUCCESS' or 'ERROR'), total_nodes,
        ready_nodes, not_ready_nodes, pressure_nodes, cluster_healthy flag,
        detected node issues, and detailed node information.
    """
    node_name = node_name.strip() if node_name else ""

    # Strategy 1: Attempt retrieval via Kubernetes Python API client
    api_client = _get_k8s_client(impersonate_user=impersonate_user)
    if api_client is not None:
        try:
            from kubernetes.client.exceptions import ApiException

            if node_name:
                node_obj = api_client.read_node(name=node_name)
                parsed_node = _parse_k8s_node(node_obj)
                return {
                    "status": "SUCCESS",
                    "node_name": node_name,
                    "is_ready": parsed_node["ready"],
                    "has_pressure": parsed_node["pressure_detected"],
                    "issues": parsed_node["issues"],
                    "node": parsed_node,
                    "nodes": [parsed_node],
                }
            else:
                node_list = api_client.list_node()
                parsed_nodes = [_parse_k8s_node(n) for n in node_list.items]
                ready_count = sum(1 for n in parsed_nodes if n["ready"])
                not_ready_count = sum(1 for n in parsed_nodes if not n["ready"])
                pressure_count = sum(1 for n in parsed_nodes if n["pressure_detected"])
                all_issues = []
                for n in parsed_nodes:
                    all_issues.extend(n["issues"])

                return {
                    "status": "SUCCESS",
                    "total_nodes": len(parsed_nodes),
                    "ready_nodes": ready_count,
                    "not_ready_nodes": not_ready_count,
                    "pressure_nodes": pressure_count,
                    "cluster_healthy": (not_ready_count == 0 and pressure_count == 0),
                    "issues_detected": all_issues,
                    "nodes": parsed_nodes,
                }
        except ApiException as e:
            return {
                "status": "ERROR",
                "message": _format_k8s_api_error(e),
                "node_name": node_name,
            }
        except Exception:
            # Fall back to kubectl
            pass

    # Strategy 2: Fallback to kubectl CLI
    cmd = ["kubectl", "get", "nodes"] if not node_name else ["kubectl", "get", "node", node_name]
    cmd.extend(["-o", "json"])
    if impersonate_user:
        cmd.append(f"--as={impersonate_user}")

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
            if node_name:
                parsed_node = _parse_k8s_node(data)
                return {
                    "status": "SUCCESS",
                    "node_name": node_name,
                    "is_ready": parsed_node["ready"],
                    "has_pressure": parsed_node["pressure_detected"],
                    "issues": parsed_node["issues"],
                    "node": parsed_node,
                    "nodes": [parsed_node],
                }
            else:
                items = data.get("items", [])
                parsed_nodes = [_parse_k8s_node(item) for item in items]
                ready_count = sum(1 for n in parsed_nodes if n["ready"])
                not_ready_count = sum(1 for n in parsed_nodes if not n["ready"])
                pressure_count = sum(1 for n in parsed_nodes if n["pressure_detected"])
                all_issues = []
                for n in parsed_nodes:
                    all_issues.extend(n["issues"])

                return {
                    "status": "SUCCESS",
                    "total_nodes": len(parsed_nodes),
                    "ready_nodes": ready_count,
                    "not_ready_nodes": not_ready_count,
                    "pressure_nodes": pressure_count,
                    "cluster_healthy": (not_ready_count == 0 and pressure_count == 0),
                    "issues_detected": all_issues,
                    "nodes": parsed_nodes,
                }
        return {
            "status": "ERROR",
            "message": f"kubectl error: {proc.stderr.strip() or proc.stdout.strip()}",
            "node_name": node_name,
        }
    except FileNotFoundError:
        return {
            "status": "ERROR",
            "message": "Neither Kubernetes Python client nor 'kubectl' command is available.",
            "node_name": node_name,
        }
    except Exception as exc:
        return {
            "status": "ERROR",
            "message": f"Failed to retrieve node info: {exc!s}",
            "node_name": node_name,
        }

