# payments-db — real (unplanted) failure scenario for the k8s investigation agent

Purpose: show the team why the agent needs an eval suite before deployment.
Nothing is faked here: real `mysql:8.0` image, real kernel OOM kill, genuine
logs and events. The only "seed" is a realistic, extremely common misconfig —
a memory limit copied from a generic template.

## The scenario

`deployment.yaml` runs stock MySQL 8 with:

```yaml
resources:
  limits:
    memory: "128Mi"   # MySQL 8 needs ~400Mi+ to initialize
```

Result (all genuine):

- Kernel OOM-kills mysqld mid-bootstrap → exit code 137, reason `OOMKilled`.
- Pod cycles: `OOMKilled` → restart → `CrashLoopBackOff`.
- Logs: normal InnoDB initialization, then cut mid-flight (SIGKILL leaves no
  error line).
- Events: only generic `Back-off restarting failed container` — kubelet emits
  NO OOM event.

## The agent's blind spot

The decisive evidence lives in pod status:

```bash
kubectl get pod <pod> -o jsonpath='{.status.containerStatuses[0].lastState.terminated}'
# {"exitCode":137,"reason":"OOMKilled",...}
```

The agent has four tools — logs, events, rollout history, log-regex analysis —
and **none of them can read pod status**. So every surface it can see is
ambiguous, and it must guess.

## Verified result (agents-cli run, 2026-10-04)

Asked: `investigate pod payments-db-685f8489fc-qmkx7 in namespace default`

Agent output:

- Root Cause: **CRASH_LOOP, 95% confidence** — that is the *symptom*, not a cause.
- Leading hypothesis: "Missing mandatory MySQL environment variable
  (e.g. MYSQL_ROOT_PASSWORD)" — **wrong**, the variable is set.
- OOM appears only as guess #2 of 3.
- Its own remediation step 1 says: run `kubectl describe pod` and check
  Last State exit code — the agent telling the user to fetch the evidence
  it has no tool to fetch.

## Demo script

```bash
kubectl apply -f payments-app/
kubectl get pods -l app=payments-db -w        # watch OOMKilled -> CrashLoopBackOff (~1 min)

agents-cli run "investigate pod $(kubectl get pod -l app=payments-db -o name | cut -d/ -f2) in namespace default"

# Reveal ground truth to the room:
kubectl get pod -l app=payments-db -o jsonpath='{.items[0].status.containerStatuses[0].lastState.terminated}'
```

## Lesson for the team

- The agent answered at **95% confidence** while its leading hypothesis was
  wrong and its stated root cause was just the symptom restated.
- Confidence measures how coherent the *visible* story is, not whether the
  evidence is complete.
- The fix is measurable: add a `get_pod_status` tool (containerStatuses,
  lastState, exit codes), then re-run the eval and watch this case go green.
  That loop — scenario, grade, fix, re-grade — is exactly what an eval suite
  automates.

## Cleanup

```bash
kubectl delete -f payments-app/
```
