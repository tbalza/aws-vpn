provider "aws" {
  region = "us-east-1"
}

locals {
  client_cidr = "192.168.68.0/22"
}

data "aws_partition" "current" {}

################################################################################
# VPC
################################################################################

module "vpc" { # Creates VPC, subnets, route tables
  source  = "terraform-aws-modules/vpc/aws"
  version = "5.16.0"

  name = "VPC"
  cidr = "10.1.0.0/16"

  azs             = ["us-east-1a", "us-east-1b"]
  private_subnets = ["10.1.1.0/24", "10.1.3.0/24"]
}

################################################################################
# VPN
################################################################################

resource "aws_ec2_client_vpn_endpoint" "cvpn" {
  description            = "Client VPN"
  server_certificate_arn = aws_acm_certificate.server_cert.arn
  client_cidr_block      = local.client_cidr # check
  split_tunnel           = "true"
  security_group_ids     = [module.cvpn_access_security_group.security_group_id]
  vpc_id                 = module.vpc.vpc_id
  self_service_portal    = "disabled"

  authentication_options {
    type                       = "certificate-authentication"
    root_certificate_chain_arn = aws_acm_certificate.server_cert.arn
  }

  connection_log_options {
    enabled = false
  }
}

# Client VPN association can take over the 10 minutes, and reach timeouts
resource "aws_ec2_client_vpn_authorization_rule" "authorize_cvpn_vpc" {
  client_vpn_endpoint_id = aws_ec2_client_vpn_endpoint.cvpn.id
  target_network_cidr    = module.vpc.vpc_cidr_block # check
  authorize_all_groups   = true
}

# For each https://github.com/hashicorp/terraform-provider-aws/issues/14717
resource "aws_ec2_client_vpn_network_association" "associate_subnet_1" {
  client_vpn_endpoint_id = aws_ec2_client_vpn_endpoint.cvpn.id
  subnet_id              = module.vpc.private_subnets[0]
}

resource "aws_ec2_client_vpn_network_association" "associate_subnet_2" {
  client_vpn_endpoint_id = aws_ec2_client_vpn_endpoint.cvpn.id
  subnet_id              = module.vpc.private_subnets[1]
}

################################################################################
# SG
################################################################################

module "cvpn_access_security_group" {
  source  = "terraform-aws-modules/security-group/aws"
  version = "5.2.0"

  name        = "cvpn_access_security_group"
  description = "Security group for CVPN Access"

  vpc_id = module.vpc.vpc_id

  computed_ingress_with_cidr_blocks = [
    {
      description = "VPN TLS"
      from_port   = 443
      to_port     = 443
      protocol    = "udp"
      cidr_blocks = "0.0.0.0/0"
    }
  ]
  number_of_computed_ingress_with_cidr_blocks = 1

  egress_with_cidr_blocks = [
    {
      description = "All"
      from_port   = -1
      to_port     = -1
      protocol    = -1
      cidr_blocks = "0.0.0.0/0"
    }
  ]
}

################################################################################
# Certs
################################################################################

variable "domain_name" {
  default = "example.com"
}

# CA
resource "tls_private_key" "ca_key" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "tls_self_signed_cert" "ca_cert" {
  private_key_pem = tls_private_key.ca_key.private_key_pem

  subject {
    common_name  = "ca.${var.domain_name}"
  }

  is_ca_certificate     = true
  validity_period_hours = 87600
  allowed_uses = [
    "cert_signing",
    "crl_signing",
  ]
}

# Server
resource "tls_private_key" "server_key" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "tls_cert_request" "server_req" {
  private_key_pem = tls_private_key.server_key.private_key_pem

  subject {
    common_name  = "vpn.${var.domain_name}"
  }
}

resource "tls_locally_signed_cert" "server_cert" {
  cert_request_pem     = tls_cert_request.server_req.cert_request_pem
  ca_private_key_pem   = tls_private_key.ca_key.private_key_pem
  ca_cert_pem          = tls_self_signed_cert.ca_cert.cert_pem

  validity_period_hours = 87600
  allowed_uses = [
    "key_encipherment",
    "digital_signature",
    "server_auth",
  ]
}

# Import to ACM for Client VPN use
resource "aws_acm_certificate" "server_cert" {
  private_key      = tls_private_key.server_key.private_key_pem
  certificate_body = tls_locally_signed_cert.server_cert.cert_pem
  certificate_chain = tls_self_signed_cert.ca_cert.cert_pem
}

# Client
resource "tls_private_key" "client_key" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "tls_cert_request" "client_req" {
  private_key_pem = tls_private_key.client_key.private_key_pem

  subject {
    common_name = "client.${var.domain_name}"
  }
}

resource "tls_locally_signed_cert" "client_cert" {
  cert_request_pem     = tls_cert_request.client_req.cert_request_pem
  ca_private_key_pem   = tls_private_key.ca_key.private_key_pem
  ca_cert_pem          = tls_self_signed_cert.ca_cert.cert_pem

  validity_period_hours = 87600
  allowed_uses = [
    "client_auth"
  ]
}

################################################################################
# Download Client Configuration and append necessary tags
################################################################################

resource "null_resource" "download_cvpn_config" {
  depends_on = [aws_ec2_client_vpn_endpoint.cvpn]

  provisioner "local-exec" {
    command = <<EOF
      #!/bin/bash
      set -e  # Exit on error

      # Export the VPN configuration
      aws ec2 export-client-vpn-client-configuration --client-vpn-endpoint-id ${aws_ec2_client_vpn_endpoint.cvpn.id} --output text > ./client-config.ovpn

      # Embed the client certificate
      echo '<cert>' >> ./client-config.ovpn
      echo "${tls_locally_signed_cert.client_cert.cert_request_pem}" >> ./client-config.ovpn
      echo '</cert>' >> ./client-config.ovpn

      # Embed the private key
      echo '<key>' >> ./client-config.ovpn
      echo "${tls_private_key.server_key.private_key_pem}" >> ./client-config.ovpn
      echo '</key>' >> ./client-config.ovpn
    EOF
    interpreter = ["/bin/bash", "-c"]
  }

  triggers = {
    always_run = "${timestamp()}"
  }
}

