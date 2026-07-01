# OpenTelemetry metrics (node & pod level)

L4Scope pushes metrics in **OTLP/HTTP (JSON)** to any OpenTelemetry Collector, so
the same agent feeds Azure Monitor, Google Cloud Monitoring, Amazon Managed
Prometheus/CloudWatch, or any vendor-neutral OTLP/Prometheus backend. The agent
sends HTTP to a node-local Collector; the Collector handles TLS/auth and cloud
export. (Prometheus scraping of the agent's `/metrics` on `:9560` remains
available as an alternative — either works.)

## What's exported

Scope `l4scope` (v0.1.0). Metrics:

| Metric | Type | Unit | Attributes | Level |
|--------|------|------|------------|-------|
| `l4scope.packets` | sum (cumulative) | 1 | — | node |
| `l4scope.events` | sum (cumulative) | 1 | `l4.kind`, `severity` | node |
| `l4scope.pod.events` | sum (cumulative) | 1 | `k8s.pod.ip`, `l4.kind`, `severity` | pod |
| `l4scope.pod.packets` | sum (cumulative) | 1 | `k8s.pod.ip` | pod |
| `l4scope.active_flows` | gauge | 1 | — | node |
| `l4scope.half_open_max` | gauge | 1 | — | node |
| `l4scope.rst_per_second` | gauge | 1/s | — | node |
| `l4scope.new_flows_per_second` | gauge | 1/s | — | node |

`l4.kind` is the detector name (`retransmission`, `rst_storm`, `zero_window`, …);
`severity` is `info|warning|critical` (see `DETECTORS.md`).

## Resource attributes

Set once per agent, attached to every datapoint. The agent assembles them from
config (`[otlp] resource_attributes`, `service_name`) and environment:

- `service.name` (from `service_name`)
- `host.name` ← `HOSTNAME`
- `k8s.node.name` ← `K8S_NODE_NAME` / `NODE_NAME`
- `k8s.cluster.name` ← `K8S_CLUSTER_NAME`
- `cloud.provider` / `cloud.region` / `cloud.account.id` ← `CLOUD_*`
- anything in `OTEL_RESOURCE_ATTRIBUTES` (standard OTel env, `k=v,k=v`)

The Collector's `resourcedetection` processor fills in additional cloud/host
attributes (instance id, zone, etc.) automatically.

## Pod-level attribution — how it works

The agent runs once per node (DaemonSet), so it can't rely on the Collector's
per-connection pod mapping. Instead it classifies each flow itself: if a flow
endpoint falls inside a configured **pod CIDR**, the agent tags that datapoint
with `k8s.pod.ip`. The Collector's **`k8sattributes`** processor (configured with
`pod_association: k8s.pod.ip`) then expands it into `k8s.pod.name`,
`k8s.namespace.name`, `k8s.deployment.name`, etc. No K8s API client in the agent.

Set `pod_cidrs` correctly for your platform — this differs by CNI:

- **AKS – kubenet:** the cluster pod CIDR, e.g. `10.244.0.0/16`.
- **AKS – Azure CNI:** pods get IPs from the **VNet subnet** → use that subnet CIDR.
- **GKE:** the cluster's **pod secondary range** (VPC-native), e.g. `10.4.0.0/14`
  — check the cluster's "Pod address range".
- **EKS – VPC CNI (default):** pods get **VPC subnet** IPs → set `pod_cidrs` to your
  node/pod subnet CIDRs (comma-separated). With overlay/Calico it's the pod CIDR.

If unset (or on plain VMs), only node-level metrics are produced.

## Per-provider export

Use `deploy/otel/collector-config.yaml` (contrib image) and enable one exporter:

- **AKS → Azure Monitor:** `azuremonitor` exporter with
  `APPLICATIONINSIGHTS_CONNECTION_STRING`. (Or Azure Managed Prometheus via
  `prometheusremotewrite` to the AMW remote-write endpoint with Entra auth.)
- **GKE → Google Cloud:** `googlecloud` exporter (Cloud Monitoring) or
  `googlemanagedprometheus`. Workload Identity provides credentials; set
  `GCP_PROJECT`.
- **EKS → AWS:** `prometheusremotewrite` to **Amazon Managed Prometheus** with the
  `sigv4auth` extension, or `awsemf` to **CloudWatch**. IRSA provides credentials;
  set `AWS_REGION` / `AMP_REMOTE_WRITE_URL`.
- **Vendor-neutral:** keep the `prometheus` exporter (scrape `:8889`) or
  `otlphttp` to your own gateway/backend.

Deploy: apply `deploy/otel/collector-daemonset.yaml` (Collector + RBAC), create
the config ConfigMap, then apply `deploy/daemonset.yaml` (the agents). Agents
reach the node-local Collector at `http://localhost:4318` via `hostNetwork`.

## Virtual machines (no Kubernetes)

Run the agent as a systemd service (`deploy/l4scope.service`) and a Collector on
the same host (systemd or container). In `l4scope.toml` set
`[otlp] enabled = true`, `endpoint = "http://localhost:4318"`, leave `pod_cidrs`
empty (node-level only), and set `resource_attributes` /`CLOUD_*` env for
`host.name`, `cloud.provider`, `cloud.region`. Point the Collector's exporter at
your backend exactly as above. The Collector's `resourcedetection` (ec2/gcp/azure)
enriches VM metrics with instance metadata.

## Quick local test

```bash
# Terminal 1: a throwaway collector that just logs what it receives
otelcol-contrib --config deploy/otel/collector-config.yaml   # prometheus:8889

# Terminal 2: agent in demo mode pushing OTLP
l4scope --demo --config /dev/stdin <<'EOF'
[capture]
backend = "synthetic"
[otlp]
enabled = true
endpoint = "http://localhost:4318"
EOF

curl -s localhost:8889/metrics | grep l4scope
```
