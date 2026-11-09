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

output "vpc_name" {
  description = "Name of the custom VPC network"
  value       = google_compute_network.custom_vpc.name
}

output "vpc_id" {
  description = "ID of the custom VPC network"
  value       = google_compute_network.custom_vpc.id
}

output "vpc_self_link" {
  description = "Self link of the custom VPC network"
  value       = google_compute_network.custom_vpc.self_link
}

output "gke_subnet_name" {
  description = "Name of the GKE subnetwork"
  value       = google_compute_subnetwork.gke_subnet.name
}

output "gke_subnet_id" {
  description = "ID of the GKE subnetwork"
  value       = google_compute_subnetwork.gke_subnet.id
}

output "gke_subnet_cidr" {
  description = "Primary CIDR range for GKE nodes"
  value       = google_compute_subnetwork.gke_subnet.ip_cidr_range
}

output "gke_pods_range_name" {
  description = "Name of the secondary IP range for GKE Pods"
  value       = var.gke_pods_range_name
}

output "gke_pods_cidr" {
  description = "Secondary CIDR range for GKE Pods"
  value       = var.gke_pods_cidr
}

output "gke_services_range_name" {
  description = "Name of the secondary IP range for GKE Services"
  value       = var.gke_services_range_name
}

output "gke_services_cidr" {
  description = "Secondary CIDR range for GKE Services"
  value       = var.gke_services_cidr
}

output "gke_master_ipv4_cidr_block" {
  description = "CIDR block for the private GKE cluster control plane (master)"
  value       = var.gke_master_ipv4_cidr_block
}

output "nat_router_name" {
  description = "Name of the Cloud Router for NAT"
  value       = google_compute_router.nat_router.name
}

output "nat_gateway_name" {
  description = "Name of the Cloud NAT gateway"
  value       = google_compute_router_nat.nat_gateway.name
}
