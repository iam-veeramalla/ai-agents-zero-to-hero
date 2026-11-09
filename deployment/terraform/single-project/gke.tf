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

# Dedicated Service Account for GKE Nodes (Least Privilege)
resource "google_service_account" "gke_nodes" {
  account_id   = "${var.project_name}-gke-nodes"
  display_name = "${var.project_name} GKE Node Pool Service Account"
  project      = var.project_id
}

# IAM roles for GKE Node Service Account
locals {
  gke_node_sa_roles = [
    "roles/logging.logWriter",
    "roles/monitoring.metricWriter",
    "roles/monitoring.viewer",
    "roles/artifactregistry.reader",
  ]
}

resource "google_project_iam_member" "gke_node_roles" {
  for_each = toset(local.gke_node_sa_roles)
  project  = var.project_id
  role     = each.value
  member   = "serviceAccount:${google_service_account.gke_nodes.email}"
}

# Private GKE Cluster
resource "google_container_cluster" "primary" {
  name     = var.gke_cluster_name
  location = var.gke_cluster_location
  project  = var.project_id

  # Connect to custom VPC and GKE subnetwork
  network    = google_compute_network.custom_vpc.id
  subnetwork = google_compute_subnetwork.gke_subnet.id

  # We create a separately managed node pool below
  remove_default_node_pool = true
  initial_node_count       = 1

  # VPC-native cluster using the subnetwork secondary ranges
  ip_allocation_policy {
    cluster_secondary_range_name  = var.gke_pods_range_name
    services_secondary_range_name = var.gke_services_range_name
  }

  # Private cluster configuration
  private_cluster_config {
    enable_private_nodes    = true
    enable_private_endpoint = false
    master_ipv4_cidr_block  = var.gke_master_ipv4_cidr_block
  }

  # Enable Workload Identity on the cluster
  workload_identity_config {
    workload_pool = "${var.project_id}.svc.id.goog"
  }

  # Authorized networks for kubectl management access
  master_authorized_networks_config {
    cidr_blocks {
      cidr_block   = "0.0.0.0/0"
      display_name = "All Networks (Public Control Plane Endpoint)"
    }
  }

  addons_config {
    http_load_balancing {
      disabled = false
    }
    network_policy_config {
      disabled = true
    }
  }

  release_channel {
    channel = "REGULAR"
  }

  deletion_protection = false

  depends_on = [
    google_compute_subnetwork.gke_subnet,
    google_compute_router_nat.nat_gateway,
    google_project_iam_member.gke_node_roles,
  ]
}

# GKE Node Pool with Workload Identity enabled
resource "google_container_node_pool" "primary_nodes" {
  name       = "${var.gke_cluster_name}-node-pool"
  location   = google_container_cluster.primary.location
  cluster    = google_container_cluster.primary.name
  project    = var.project_id
  node_count = var.gke_initial_node_count

  autoscaling {
    min_node_count = var.gke_min_node_count
    max_node_count = var.gke_max_node_count
  }

  management {
    auto_repair  = true
    auto_upgrade = true
  }

  node_config {
    machine_type = var.gke_node_machine_type
    disk_size_gb = 50
    disk_type    = "pd-standard"

    service_account = google_service_account.gke_nodes.email
    oauth_scopes = [
      "https://www.googleapis.com/auth/cloud-platform"
    ]

    # Required for Workload Identity on worker nodes
    workload_metadata_config {
      mode = "GKE_METADATA"
    }

    shielded_instance_config {
      enable_secure_boot          = true
      enable_integrity_monitoring = true
    }

    metadata = {
      disable-legacy-endpoints = "true"
    }

    tags = ["gke-node", "${var.project_name}-gke-node"]
  }

  depends_on = [
    google_container_cluster.primary,
  ]
}

# Workload Identity IAM Binding:
# Allows the Kubernetes ServiceAccount in k8s_namespace to impersonate app_sa
resource "google_service_account_iam_member" "workload_identity_user" {
  service_account_id = google_service_account.app_sa.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "serviceAccount:${var.project_id}.svc.id.goog[${var.k8s_namespace}/${var.k8s_service_account_name}]"

  depends_on = [
    google_container_cluster.primary,
  ]
}
