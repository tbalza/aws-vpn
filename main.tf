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
  server_certificate_arn = aws_acm_certificate.cvpn_server_certificate.arn
  client_cidr_block      = local.client_cidr # check
  split_tunnel           = "true"
  security_group_ids     = [module.cvpn_access_security_group.security_group_id]
  vpc_id                 = module.vpc.vpc_id
  self_service_portal    = "disabled"

  authentication_options {
    type                       = "certificate-authentication"
    root_certificate_chain_arn = aws_acm_certificate.root_user_cvpn_client_certificate.arn
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
# Certs: Root CA
################################################################################

# Type set to ROOT

resource "aws_acmpca_certificate_authority" "root_ca" {
  type = "ROOT"

  certificate_authority_configuration {
    key_algorithm     = "RSA_4096"
    signing_algorithm = "SHA512WITHRSA"

    subject {
      common_name = "root.ca.cert.private.mydomain.com"
    }
  }
}

resource "aws_acmpca_certificate" "root_ca_certificate" {
  certificate_authority_arn   = aws_acmpca_certificate_authority.root_ca.arn
  certificate_signing_request = aws_acmpca_certificate_authority.root_ca.certificate_signing_request
  signing_algorithm           = "SHA512WITHRSA"

  template_arn = "arn:${data.aws_partition.current.partition}:acm-pca:::template/RootCACertificate/V1"

  validity {
    type  = "YEARS"
    value = 5
  }
}

resource "aws_acmpca_certificate_authority_certificate" "root_ca_certificate_association" {
  certificate_authority_arn = aws_acmpca_certificate_authority.root_ca.arn

  certificate       = aws_acmpca_certificate.root_ca_certificate.certificate
  certificate_chain = aws_acmpca_certificate.root_ca_certificate.certificate_chain
}

################################################################################
# Certs: CVPN Server Certificate
################################################################################

# certificate_authority_arn = ARN of Root CA

resource "tls_private_key" "cvpn_server_certificate_private_key" {
  algorithm = "RSA"
  rsa_bits  = "2048"
}

resource "tls_cert_request" "cvpn_server_certificate_signing_request" {
  private_key_pem = tls_private_key.cvpn_server_certificate_private_key.private_key_pem

  subject {
    common_name = "cvpn-server.cvpn.cert.private.mydomain.com"
  }
}

resource "aws_acmpca_certificate" "cvpn_server_certificate" {
  certificate_authority_arn   = aws_acmpca_certificate_authority.root_ca.arn # Root CA
  certificate_signing_request = tls_cert_request.cvpn_server_certificate_signing_request.cert_request_pem
  signing_algorithm           = "SHA512WITHRSA"
  validity {
    type  = "YEARS"
    value = 3
  }
}

resource "aws_acm_certificate" "cvpn_server_certificate" {
  private_key       = tls_private_key.cvpn_server_certificate_private_key.private_key_pem
  certificate_body  = aws_acmpca_certificate.cvpn_server_certificate.certificate
  certificate_chain = aws_acmpca_certificate.cvpn_server_certificate.certificate_chain

  lifecycle {
    create_before_destroy = true
  }
}

################################################################################
# Certs: CVPN Client CA
################################################################################

# Type SUBORDINATE,
# certificate_authority_arn = ARN of Root CA

resource "aws_acmpca_certificate_authority" "cvpn_client_ca" {
  type = "SUBORDINATE"

  certificate_authority_configuration {
    key_algorithm     = "RSA_4096"
    signing_algorithm = "SHA512WITHRSA"

    subject {
      common_name = "cvpn-client.ca.cert.private.mydomain.com"
    }
  }

}

resource "aws_acmpca_certificate" "cvpn_client_ca_certificate" {
  certificate_authority_arn   = aws_acmpca_certificate_authority.root_ca.arn # Root CA
  certificate_signing_request = aws_acmpca_certificate_authority.cvpn_client_ca.certificate_signing_request
  signing_algorithm           = "SHA512WITHRSA"

  template_arn = "arn:${data.aws_partition.current.partition}:acm-pca:::template/SubordinateCACertificate_PathLen0/V1"

  validity {
    type  = "YEARS"
    value = 3
  }
}

resource "aws_acmpca_certificate_authority_certificate" "cvpn_client_ca_certificate_association" {
  certificate_authority_arn = aws_acmpca_certificate_authority.cvpn_client_ca.arn
  certificate               = aws_acmpca_certificate.cvpn_client_ca_certificate.certificate
  certificate_chain         = aws_acmpca_certificate.cvpn_client_ca_certificate.certificate_chain
}

################################################################################
# Certs: CVPN Root Client Certificate
################################################################################

# only used as part of the CVPN Server configuration in AWS
# certificate_authority_arn = ARN of Client CA

resource "tls_private_key" "root_user_cvpn_client_certificate_private_key" {
  algorithm = "RSA"
  rsa_bits  = "2048"
}

resource "tls_cert_request" "root_user_cvpn_client_certificate_signing_request" {
  private_key_pem = tls_private_key.root_user_cvpn_client_certificate_private_key.private_key_pem

  subject {
    common_name = "root-user.cvpn.cert.private.mydomain.com"
  }
}

resource "aws_acmpca_certificate" "root_user_cvpn_client_certificate" {
  certificate_authority_arn   = aws_acmpca_certificate_authority.cvpn_client_ca.arn
  certificate_signing_request = tls_cert_request.root_user_cvpn_client_certificate_signing_request.cert_request_pem
  signing_algorithm           = "SHA512WITHRSA"
  validity {
    type  = "YEARS"
    value = 1
  }
}

resource "aws_acm_certificate" "root_user_cvpn_client_certificate" {
  private_key       = tls_private_key.root_user_cvpn_client_certificate_private_key.private_key_pem
  certificate_body  = aws_acmpca_certificate.root_user_cvpn_client_certificate.certificate
  certificate_chain = aws_acmpca_certificate.root_user_cvpn_client_certificate.certificate_chain

  lifecycle {
    create_before_destroy = true
  }
}

################################################################################
# Certs: CVPN Client Certificate
################################################################################

# Enables a clients to connect to the CVPN Server
# certificate_authority_arn = ARN of Client CA

resource "tls_private_key" "user_1_cvpn_client_certificate_private_key" {
  algorithm = "RSA"
  rsa_bits  = "2048"
}

resource "tls_cert_request" "user_1_cvpn_client_certificate_signing_request" {
  private_key_pem = tls_private_key.user_1_cvpn_client_certificate_private_key.private_key_pem

  subject {
    common_name = "user-1.cvpn.cert.private.mydomain.com"
  }
}

resource "aws_acmpca_certificate" "user_1_cvpn_client_certificate" {
  certificate_authority_arn   = aws_acmpca_certificate_authority.cvpn_client_ca.arn
  certificate_signing_request = tls_cert_request.user_1_cvpn_client_certificate_signing_request.cert_request_pem
  signing_algorithm           = "SHA512WITHRSA"
  validity {
    type  = "YEARS"
    value = 1
  }
}

resource "aws_acm_certificate" "user_1_cvpn_client_certificate" {
  private_key       = tls_private_key.user_1_cvpn_client_certificate_private_key.private_key_pem
  certificate_body  = aws_acmpca_certificate.user_1_cvpn_client_certificate.certificate
  certificate_chain = aws_acmpca_certificate.user_1_cvpn_client_certificate.certificate_chain

  lifecycle {
    create_before_destroy = true
  }
}

################################################################################
# Download Client Configuration
################################################################################

resource "null_resource" "download_cvpn_config" {
  # Ensures this runs after the Client VPN endpoint has been created
  depends_on = [aws_ec2_client_vpn_endpoint.cvpn]

  provisioner "local-exec" {
    command = "aws ec2 export-client-vpn-client-configuration --client-vpn-endpoint-id ${aws_ec2_client_vpn_endpoint.cvpn.id} --output text > ${path.module}/client-config.ovpn"
  }

  triggers = {
    # Re-run this script if the Client VPN Endpoint ID changes
    always_run = aws_ec2_client_vpn_endpoint.cvpn.id
  }
}
