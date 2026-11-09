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

# Custom VPC Network
resource "google_compute_network" "custom_vpc" {
  name                    = "k8s-agent-prod-vpc"
  project                 = var.project_id
  auto_create_subnetworks = false
  routing_mode            = "REGIONAL"
}

# Dedicated Subnet for Private GKE Cluster
resource "google_compute_subnetwork" "gke_subnet" {
  name                     = var.gke_subnet_name
  project                  = var.project_id
  region                   = var.region
  network                  = google_compute_network.custom_vpc.id
  ip_cidr_range            = var.gke_subnet_cidr
  private_ip_google_access = true

  # Secondary IP range for GKE Pods
  secondary_ip_range {
    range_name    = var.gke_pods_range_name
    ip_cidr_range = var.gke_pods_cidr
  }

  # Secondary IP range for GKE Services (ClusterIP)
  secondary_ip_range {
    range_name    = var.gke_services_range_name
    ip_cidr_range = var.gke_services_cidr
  }
}

# Egress Subnet
resource "google_compute_subnetwork" "egress_subnet" {
  name                     = "k8s-agent-prod-egress-subnet"
  project                  = var.project_id
  region                   = var.region
  network                  = google_compute_network.custom_vpc.id
  ip_cidr_range            = "10.10.1.0/24"
  private_ip_google_access = true
}

# Cloud Router for Cloud NAT Gateway
resource "google_compute_router" "nat_router" {
  name    = "k8s-agent-nat-router"
  project = var.project_id
  region  = var.region
  network = google_compute_network.custom_vpc.id
}

# Cloud NAT Gateway for outbound internet access from private GKE nodes and pods
resource "google_compute_router_nat" "nat_gateway" {
  name                               = "k8s-agent-nat"
  project                            = var.project_id
  router                             = google_compute_router.nat_router.name
  region                             = var.region
  nat_ip_allocate_option             = "AUTO_ONLY"
  source_subnetwork_ip_ranges_to_nat = "ALL_SUBNETWORKS_ALL_IP_RANGES"

  log_config {
    enable = true
    filter = "ERRORS_ONLY"
  }
}

# Firewall Rule: Allow internal communication between GKE nodes, pods, and services
resource "google_compute_firewall" "gke_allow_internal" {
  name        = "k8s-agent-allow-internal"
  project     = var.project_id
  network     = google_compute_network.custom_vpc.name
  description = "Allow internal traffic between nodes, pods, and services within the cluster VPC"

  direction = "INGRESS"
  priority  = 1000

  source_ranges = [
    var.gke_subnet_cidr,
    var.gke_pods_cidr,
    var.gke_services_cidr,
    "10.10.1.0/24",
  ]

  allow {
    protocol = "tcp"
  }

  allow {
    protocol = "udp"
  }

  allow {
    protocol = "icmp"
  }
}

# Firewall Rule: Allow GKE Control Plane (Master) to communicate with worker nodes
# Needed for admission webhooks (ports 443, 8443) and kubelet (port 10250)
resource "google_compute_firewall" "gke_allow_master_to_nodes" {
  name        = "k8s-agent-allow-master-to-nodes"
  project     = var.project_id
  network     = google_compute_network.custom_vpc.name
  description = "Allow GKE master control plane to reach worker nodes for webhooks and kubelet"

  direction = "INGRESS"
  priority  = 1000

  source_ranges = [var.gke_master_ipv4_cidr_block]

  allow {
    protocol = "tcp"
    ports    = ["443", "10250", "8443"]
  }
}

# Firewall Rule: Allow Google Cloud Health Checks for Ingress and Load Balancers
resource "google_compute_firewall" "gke_allow_health_checks" {
  name        = "k8s-agent-allow-health-checks"
  project     = var.project_id
  network     = google_compute_network.custom_vpc.name
  description = "Allow Google Cloud Load Balancer and Ingress health checks"

  direction = "INGRESS"
  priority  = 1000

  source_ranges = [
    "130.211.0.0/22",
    "35.191.0.0/16",
  ]

  allow {
    protocol = "tcp"
  }
}

# Firewall Rule: Allow SSH via Identity-Aware Proxy (IAP) for private nodes / bastion
resource "google_compute_firewall" "gke_allow_iap" {
  name        = "k8s-agent-allow-iap"
  project     = var.project_id
  network     = google_compute_network.custom_vpc.name
  description = "Allow SSH access to private instances via Identity-Aware Proxy"

  direction = "INGRESS"
  priority  = 1000

  source_ranges = ["35.235.240.0/20"]

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
}
