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

output "gke_cluster_name" {
  description = "Name of the GKE cluster"
  value       = google_container_cluster.primary.name
}

output "gke_cluster_id" {
  description = "ID of the GKE cluster"
  value       = google_container_cluster.primary.id
}

output "gke_cluster_location" {
  description = "Location (region or zone) of the GKE cluster"
  value       = google_container_cluster.primary.location
}

output "gke_cluster_endpoint" {
  description = "Kubernetes control plane endpoint"
  value       = google_container_cluster.primary.endpoint
}

output "gke_cluster_ca_certificate" {
  description = "Base64 encoded public CA certificate for the cluster"
  value       = google_container_cluster.primary.master_auth[0].cluster_ca_certificate
  sensitive   = true
}

output "gke_workload_identity_pool" {
  description = "Workload Identity pool for the GKE cluster"
  value       = "${var.project_id}.svc.id.goog"
}

output "gke_node_service_account_email" {
  description = "Email of the dedicated service account for GKE worker nodes"
  value       = google_service_account.gke_nodes.email
}

output "gke_workload_identity_sa_binding" {
  description = "Workload Identity member binding string"
  value       = "serviceAccount:${var.project_id}.svc.id.goog[${var.k8s_namespace}/${var.k8s_service_account_name}]"
}

output "kubectl_get_credentials_command" {
  description = "Command to configure kubectl credentials for the cluster"
  value       = "gcloud container clusters get-credentials ${google_container_cluster.primary.name} --zone ${google_container_cluster.primary.location} --project ${var.project_id}"
}
