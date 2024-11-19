# AWS Client VPN Minimal Setup With Terraform

Creates a VPC and sets up a VPN Client Endpoint using split-tunnel and Mutual Authentication for private subnet access. Also downloads the "configuration file" `client-config.ovpn` programmatically for configuring the [VPN Client](https://aws.amazon.com/vpn/client-vpn-download/).


## Cloning the script
```bash
git clone git@github.com:tbalza/aws-vpn.git 
```

## Running the script
With AWS CLI and Terraform configured:
```bash
terraform init && \
terraform apply
```

## Connecting to the VPN
After the VPN Endpoint is provisioned, Terraform will download `client-config.ovpn` file in the project directory and embed the client cert and key.

With the [VPN Client](https://aws.amazon.com/vpn/client-vpn-download/) installed you can point the file as is and click ***connect***. Only AWS related traffic will be routed through the VPN.

## Destroying Resources
```bash
terraform destroy
```

## Notes
Order of operations
- Authorization Rule for AWS Client VPN
- New entries under Route Tables