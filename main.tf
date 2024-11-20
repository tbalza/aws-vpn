provider "aws" {
  region = "us-east-1"
}

locals {
  client_cidr = "192.168.68.0/22"
}

################################################################################
# VPC
################################################################################

# Creates VPC, subnets, route tables
module "vpc" {
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

# Creates VPN endpoint
resource "aws_ec2_client_vpn_endpoint" "cvpn" {
  description            = "Client VPN Endpoint"
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

# Associates VPN to VPC (can take around ~10 minutes to complete)
resource "aws_ec2_client_vpn_authorization_rule" "authorize_cvpn_vpc" {
  client_vpn_endpoint_id = aws_ec2_client_vpn_endpoint.cvpn.id
  target_network_cidr    = module.vpc.vpc_cidr_block # check
  authorize_all_groups   = true
}

# Associates private subnets recursively
resource "aws_ec2_client_vpn_network_association" "associate_subnet" {
  for_each               = toset(module.vpc.private_subnets)
  client_vpn_endpoint_id = aws_ec2_client_vpn_endpoint.cvpn.id
  subnet_id              = each.value
}

################################################################################
# SG
################################################################################

# Allows external access to VPN
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

### CA

# Creates CA private key
resource "tls_private_key" "ca_key" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

# Creates a self-signed CA TLS certificate in PEM format
resource "tls_self_signed_cert" "ca_cert" {
  private_key_pem = tls_private_key.ca_key.private_key_pem

  subject {
    common_name = "ca.${var.domain_name}"
  }

  is_ca_certificate     = true # can be used to sign other certificates and control certificate revocation lists
  validity_period_hours = 87600
  allowed_uses = [
    "cert_signing",
    "crl_signing",
  ]
}

### Server

# Creates server private key
resource "tls_private_key" "server_key" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

# Generates server CSR used to request cert from CA
resource "tls_cert_request" "server_req" {
  private_key_pem = tls_private_key.server_key.private_key_pem

  subject {
    common_name = "vpn.${var.domain_name}"
  }
}

# Creates server certificate signed by a CA
resource "tls_locally_signed_cert" "server_cert" {
  cert_request_pem   = tls_cert_request.server_req.cert_request_pem
  ca_private_key_pem = tls_private_key.ca_key.private_key_pem
  ca_cert_pem        = tls_self_signed_cert.ca_cert.cert_pem

  validity_period_hours = 87600
  allowed_uses = [
    "key_encipherment",
    "digital_signature",
    "server_auth",
  ]
}

# Uploads server certificate to ACM (used by AWS Client VPN)
resource "aws_acm_certificate" "server_cert" {
  private_key       = tls_private_key.server_key.private_key_pem
  certificate_body  = tls_locally_signed_cert.server_cert.cert_pem
  certificate_chain = tls_self_signed_cert.ca_cert.cert_pem
}

### Client

# Creates client private key
resource "tls_private_key" "client_key" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

# Generates client CSR used to request cert from CA
resource "tls_cert_request" "client_req" {
  private_key_pem = tls_private_key.client_key.private_key_pem

  subject {
    common_name = "client.${var.domain_name}"
  }
}

# Creates client certificate signed by a CA
resource "tls_locally_signed_cert" "client_cert" {
  cert_request_pem   = tls_cert_request.client_req.cert_request_pem
  ca_private_key_pem = tls_private_key.ca_key.private_key_pem
  ca_cert_pem        = tls_self_signed_cert.ca_cert.cert_pem

  validity_period_hours = 87600
  allowed_uses = [
    "client_auth"
  ]
}

################################################################################
# "Client Configuration"
################################################################################

# Uses cli to download `.ovpn` file from AWS and embeds additional tags required for VPN endpoint connection
resource "null_resource" "download_cvpn_config" {
  depends_on = [aws_ec2_client_vpn_endpoint.cvpn]

  provisioner "local-exec" {
    command     = <<EOF
      #!/bin/bash
      set -e  # Exit on error

      # Export the VPN configuration
      aws ec2 export-client-vpn-client-configuration --client-vpn-endpoint-id ${aws_ec2_client_vpn_endpoint.cvpn.id} --output text > ./client-config.ovpn

      # Embed the client certificate
      echo '<cert>' >> ./client-config.ovpn
      echo "${tls_locally_signed_cert.client_cert.cert_pem}" >> ./client-config.ovpn
      echo '</cert>' >> ./client-config.ovpn

      # Embed the private key
      echo '<key>' >> ./client-config.ovpn
      echo "${tls_private_key.client_key.private_key_pem}" >> ./client-config.ovpn
      echo '</key>' >> ./client-config.ovpn
    EOF
    interpreter = ["/bin/bash", "-c"]
  }

  triggers = {
    always_run = "${timestamp()}"
  }
}

