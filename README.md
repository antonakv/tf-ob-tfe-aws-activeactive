# tf-ob-tfe-aws-activeactive
Install Prod External Services ( Redis + S3 + DB ) active-active installation AWS

This manual is dedicated to install Prod External Services ( Redis + S3 + DB ) active-active installation AWS

## Requirements

- Hashicorp terraform recent version installed
[Terraform installation manual](https://learn.hashicorp.com/tutorials/terraform/install-cli)

- git installed
[Git installation manual](https://git-scm.com/download/mac)

- Amazon AWS account credentials saved in .aws/credentials file
[Configuration and credential file settings](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html)

- Configured AWS Route53 DNS zone for domain `myname.hashicorp-success.com`
[Amazon Route53: Working with public hosted zones](https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/AboutHZWorkingWith.html)

- Created Amazon EC2 key pair for Linux instance
[Create a key pair using Amazon EC2](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-key-pairs.html#having-ec2-create-your-key-pair)

## Preparation 

- Clone git repository

```bash
git clone https://github.com/antonakv/tfe-aws-online-s3db.git
```

Expected command output looks like this:

```bash
Cloning into 'tfe-aws-online-s3db'...
remote: Enumerating objects: 12, done.
remote: Counting objects: 100% (12/12), done.
remote: Compressing objects: 100% (12/12), done.
remote: Total 12 (delta 1), reused 3 (delta 0), pack-reused 0
Receiving objects: 100% (12/12), done.
Resolving deltas: 100% (1/1), done.
```

- Change folder to tfe-aws-online-s3db

```bash
cd tfe-aws-online-s3db
```

- Create file testing.tfvars with following contents

```
key_name            = "aakulov"
ami                 = "ami-086128e34136c3375"
instance_type       = "t3.2xlarge"
db_instance_type    = "db.t3.medium"
region              = "eu-central-1"
cidr_vpc            = "10.5.0.0/16"
cidr_subnet1        = "10.5.1.0/24"
cidr_subnet2        = "10.5.2.0/24"
cidr_subnet3        = "10.5.3.0/24"
cidr_subnet4        = "10.5.4.0/24"
db_password         = "Password1#"
enc_password        = "Password1#"
tfe_hostname        = "aws10.hashicorp-success.com"
tfe_hostname_jump   = "aws10jump.hashicorp-success.com"
release_sequence    = 550
minio_access_key    = "key"
minio_secret_key    = "key"
ami_minio           = "ami-0b5de643012fe5385"
instance_type_minio = "t3.large"
instance_type_jump  = "t3.medium"
s3_bucket           = "aakulov-aws10-tfe-data"
```

- Change folder to `pre-req`

Follow `pre-req/README.md` manual to prepare assets on Amazon S3 required for the installation

## Run terraform code

- In the same folder you were before, run 

```bash
terraform init
```

Sample result

```
$ terraform init

Initializing the backend...

Initializing provider plugins...
- Finding hashicorp/aws versions matching "~> 3.52"...
- Finding hashicorp/tls versions matching "~> 3.1.0"...
- Finding hashicorp/template versions matching "~> 2.2.0"...
- Installing hashicorp/aws v3.66.0...
- Installed hashicorp/aws v3.66.0 (signed by HashiCorp)
- Installing hashicorp/tls v3.1.0...
- Installed hashicorp/tls v3.1.0 (signed by HashiCorp)
- Installing hashicorp/template v2.2.0...
- Installed hashicorp/template v2.2.0 (signed by HashiCorp)

Terraform has created a lock file .terraform.lock.hcl to record the provider
selections it made above. Include this file in your version control repository
so that Terraform can guarantee to make the same selections by default when
you run "terraform init" in the future.

Terraform has been successfully initialized!

You may now begin working with Terraform. Try running "terraform plan" to see
any changes that are required for your infrastructure. All Terraform commands
should now work.

If you ever set or change modules or backend configuration for Terraform,
rerun this command to reinitialize your working directory. If you forget, other
commands will detect it and remind you to do so if necessary.

```

- Execute `terraform apply`

```
$ terraform apply

Terraform used the selected providers to generate the following execution plan. Resource actions are indicated with the following symbols:
  + create
 <= read (data resources)

Terraform will perform the following actions:

  # data.template_cloudinit_config.aws7_cloudinit will be read during apply
  # (config refers to values not yet known)
 <= data "template_cloudinit_config" "aws7_cloudinit"  {
      + base64_encode = true
      + gzip          = true
      + id            = (known after apply)
      + rendered      = (known after apply)

      + part {
          + content      = (known after apply)
          + content_type = "text/x-shellscript"
          + filename     = "install_tfe.sh"
        }
    }

  # data.template_file.install_tfe_sh will be read during apply
  # (config refers to values not yet known)
 <= data "template_file" "install_tfe_sh"  {
      + id       = (known after apply)
      + rendered = (known after apply)
      + template = <<-EOT
            #!/usr/bin/env bash
            mkdir -p /home/ubuntu/install
            echo "
            {
                \"aws_access_key_id\": {},
                \"aws_instance_profile\": {
                    \"value\": \"1\"
                },
                \"aws_secret_access_key\": {},
                \"azure_account_key\": {},
                \"azure_account_name\": {},
                \"azure_container\": {},
                \"azure_endpoint\": {},
                \"backup_token\": {
                    \"value\": \"3e69c0572c1eddf7f232cf60f6b8634194bf40d09aa9535c78430e64df407ec4\"
                },
                \"ca_certs\": {},
                \"capacity_concurrency\": {
                    \"value\": \"10\"
                },
                \"capacity_memory\": {
                    \"value\": \"512\"
                },
                \"custom_image_tag\": {
                    \"value\": \"hashicorp/build-worker:now\"
                },
                \"disk_path\": {},
                \"enable_active_active\": {
                    \"value\": \"0\"
                },
                \"enable_metrics_collection\": {
                    \"value\": \"1\"
                },
                \"enc_password\": {
                    \"value\": \"${enc_password}\"
                },
                \"extern_vault_addr\": {},
                \"extern_vault_enable\": {
                    \"value\": \"0\"
                },
                \"extern_vault_path\": {},
                \"extern_vault_propagate\": {},
                \"extern_vault_role_id\": {},
                \"extern_vault_secret_id\": {},
                \"extern_vault_token_renew\": {},
                \"extra_no_proxy\": {},
                \"force_tls\": {
                    \"value\": \"0\"
                },
                \"gcs_bucket\": {},
                \"gcs_credentials\": {
                    \"value\": \"{}\"
                },
                \"gcs_project\": {},
                \"hairpin_addressing\": {
                    \"value\": \"0\"
                },
                \"hostname\": {
                    \"value\": \"${hostname}\"
                },
                \"iact_subnet_list\": {},
                \"iact_subnet_time_limit\": {
                    \"value\": \"60\"
                },
                \"installation_type\": {
                    \"value\": \"production\"
                },
                \"pg_dbname\": {
                    \"value\": \"mydbtfe\"
                },
                \"pg_extra_params\": {
                    \"value\": \"sslmode=disable\"
                },
                \"pg_netloc\": {
                    \"value\": \"${pgsqlhostname}\"
                },
                \"pg_password\": {
                    \"value\": \"${pgsqlpassword}\"
                },
                \"pg_user\": {
                    \"value\": \"${pguser}\"
                },
                \"placement\": {
                    \"value\": \"placement_s3\"
                },
                \"production_type\": {
                    \"value\": \"external\"
                },
                \"redis_host\": {},
                \"redis_pass\": {
                    \"value\": \"NGVITSiZJKkmtC9ed1XWjScsVZMnXJx5\"
                },
                \"redis_port\": {},
                \"redis_use_password_auth\": {},
                \"redis_use_tls\": {},
                \"restrict_worker_metadata_access\": {
                    \"value\": \"0\"
                },
                \"s3_bucket\": {
                    \"value\": \"${s3bucket}\"
                },
                \"s3_endpoint\": {},
                \"s3_region\": {
                    \"value\": \"${s3region}\"
                },
                \"s3_sse\": {},
                \"s3_sse_kms_key_id\": {},
                \"tbw_image\": {
                    \"value\": \"default_image\"
                },
                \"tls_ciphers\": {},
                \"tls_vers\": {
                    \"value\": \"tls_1_2_tls_1_3\"
                }
            }
            " > /home/ubuntu/install/settings.json
            
            echo "
            {
                \"DaemonAuthenticationType\":     \"password\",
                \"DaemonAuthenticationPassword\": \"Password1#\",
                \"TlsBootstrapType\":             \"server-path\",
                \"TlsBootstrapHostname\":         \"${hostname}\",
                \"TlsBootstrapCert\":             \"/home/ubuntu/install/server.crt\",
                \"TlsBootstrapKey\":              \"/home/ubuntu/install/server.key\",
                \"BypassPreflightChecks\":        true,
                \"ImportSettingsFrom\":           \"/home/ubuntu/install/settings.json\",
                \"LicenseFileLocation\":          \"/home/ubuntu/install/license.rli\"
            }" > /home/ubuntu/install/replicated.conf
            echo "${cert_pem}" > /home/ubuntu/install/server.crt
            echo "${key_pem}" > /home/ubuntu/install/server.key
            IPADDR=$(hostname -I | awk '{print $1}')
            echo "#!/usr/bin/env bash
            chmod 600 /home/ubuntu/install/server.key
            cd /home/ubuntu/install
            aws s3 cp s3://aakulov-aws7-tfe-tfe . --recursive
            curl -# -o /home/ubuntu/install/install.sh https://install.terraform.io/ptfe/stable
            chmod +x install.sh
            sudo rm -rf /usr/share/keyrings/docker-archive-keyring.gpg
            cp /home/ubuntu/install/replicated.conf /etc/replicated.conf
            cp /home/ubuntu/install/replicated.conf /root/replicated.conf
            chown -R ubuntu: /home/ubuntu/install
            yes | sudo /usr/bin/bash /home/ubuntu/install/install.sh no-proxy private-address=$IPADDR public-address=$IPADDR
            exit 0
            " > /home/ubuntu/install/install_tfe.sh
            
            chmod +x /home/ubuntu/install/install_tfe.sh
            
            sh /home/ubuntu/install/install_tfe.sh &> /home/ubuntu/install/install_tfe.log
        EOT
      + vars     = {
          + "cert_pem"      = (known after apply)
          + "enc_password"  = (sensitive)
          + "hostname"      = "tfe7.anton.hashicorp-success.com"
          + "key_pem"       = (sensitive)
          + "pgsqlhostname" = (known after apply)
          + "pgsqlpassword" = (sensitive)
          + "pguser"        = "postgres"
          + "s3bucket"      = "aakulov-aws7-tfe-data"
          + "s3region"      = "eu-central-1"
        }
    }

  # aws_db_instance.aws7 will be created
  + resource "aws_db_instance" "aws7" {
      + address                               = (known after apply)
      + allocated_storage                     = 20
      + apply_immediately                     = (known after apply)
      + arn                                   = (known after apply)
      + auto_minor_version_upgrade            = true
      + availability_zone                     = (known after apply)
      + backup_retention_period               = (known after apply)
      + backup_window                         = (known after apply)
      + ca_cert_identifier                    = (known after apply)
      + character_set_name                    = (known after apply)
      + copy_tags_to_snapshot                 = false
      + db_subnet_group_name                  = "aakulov-aws7"
      + delete_automated_backups              = true
      + endpoint                              = (known after apply)
      + engine                                = "postgres"
      + engine_version                        = "12.7"
      + engine_version_actual                 = (known after apply)
      + hosted_zone_id                        = (known after apply)
      + id                                    = (known after apply)
      + identifier                            = (known after apply)
      + identifier_prefix                     = (known after apply)
      + instance_class                        = "db.t3.medium"
      + kms_key_id                            = (known after apply)
      + latest_restorable_time                = (known after apply)
      + license_model                         = (known after apply)
      + maintenance_window                    = (known after apply)
      + max_allocated_storage                 = 100
      + monitoring_interval                   = 0
      + monitoring_role_arn                   = (known after apply)
      + multi_az                              = (known after apply)
      + name                                  = "mydbtfe"
      + nchar_character_set_name              = (known after apply)
      + option_group_name                     = (known after apply)
      + parameter_group_name                  = (known after apply)
      + password                              = (sensitive value)
      + performance_insights_enabled          = false
      + performance_insights_kms_key_id       = (known after apply)
      + performance_insights_retention_period = (known after apply)
      + port                                  = (known after apply)
      + publicly_accessible                   = false
      + replicas                              = (known after apply)
      + resource_id                           = (known after apply)
      + skip_final_snapshot                   = true
      + snapshot_identifier                   = (known after apply)
      + status                                = (known after apply)
      + storage_type                          = (known after apply)
      + tags                                  = {
          + "Name" = "aakulov-aws7"
        }
      + tags_all                              = {
          + "Name" = "aakulov-aws7"
        }
      + timezone                              = (known after apply)
      + username                              = "postgres"
      + vpc_security_group_ids                = (known after apply)
    }

  # aws_db_subnet_group.aws7 will be created
  + resource "aws_db_subnet_group" "aws7" {
      + arn         = (known after apply)
      + description = "Managed by Terraform"
      + id          = (known after apply)
      + name        = "aakulov-aws7"
      + name_prefix = (known after apply)
      + subnet_ids  = (known after apply)
      + tags        = {
          + "Name" = "aakulov-aws7"
        }
      + tags_all    = {
          + "Name" = "aakulov-aws7"
        }
    }

  # aws_eip.aws7 will be created
  + resource "aws_eip" "aws7" {
      + allocation_id        = (known after apply)
      + association_id       = (known after apply)
      + carrier_ip           = (known after apply)
      + customer_owned_ip    = (known after apply)
      + domain               = (known after apply)
      + id                   = (known after apply)
      + instance             = (known after apply)
      + network_border_group = (known after apply)
      + network_interface    = (known after apply)
      + private_dns          = (known after apply)
      + private_ip           = (known after apply)
      + public_dns           = (known after apply)
      + public_ip            = (known after apply)
      + public_ipv4_pool     = (known after apply)
      + tags_all             = (known after apply)
      + vpc                  = true
    }

  # aws_iam_instance_profile.aakulov-aws7-ec2-s3 will be created
  + resource "aws_iam_instance_profile" "aakulov-aws7-ec2-s3" {
      + arn         = (known after apply)
      + create_date = (known after apply)
      + id          = (known after apply)
      + name        = "aakulov-aws7-ec2-s3"
      + path        = "/"
      + role        = "aakulov-aws7-iam-role-ec2-s3"
      + tags_all    = (known after apply)
      + unique_id   = (known after apply)
    }

  # aws_iam_role.aakulov-aws7-iam-role-ec2-s3 will be created
  + resource "aws_iam_role" "aakulov-aws7-iam-role-ec2-s3" {
      + arn                   = (known after apply)
      + assume_role_policy    = jsonencode(
            {
              + Statement = [
                  + {
                      + Action    = "sts:AssumeRole"
                      + Effect    = "Allow"
                      + Principal = {
                          + Service = "ec2.amazonaws.com"
                        }
                      + Sid       = ""
                    },
                ]
              + Version   = "2012-10-17"
            }
        )
      + create_date           = (known after apply)
      + force_detach_policies = false
      + id                    = (known after apply)
      + managed_policy_arns   = (known after apply)
      + max_session_duration  = 3600
      + name                  = "aakulov-aws7-iam-role-ec2-s3"
      + name_prefix           = (known after apply)
      + path                  = "/"
      + tags                  = {
          + "tag-key" = "aakulov-aws7-iam-role-ec2-s3"
        }
      + tags_all              = {
          + "tag-key" = "aakulov-aws7-iam-role-ec2-s3"
        }
      + unique_id             = (known after apply)

      + inline_policy {
          + name   = (known after apply)
          + policy = (known after apply)
        }
    }

  # aws_iam_role_policy.aakulov-aws7-ec2-s3 will be created
  + resource "aws_iam_role_policy" "aakulov-aws7-ec2-s3" {
      + id     = (known after apply)
      + name   = "aakulov-aws7-ec2-s3"
      + policy = (known after apply)
      + role   = (known after apply)
    }

  # aws_instance.aws7 will be created
  + resource "aws_instance" "aws7" {
      + ami                                  = "ami-086128e34136c3375"
      + arn                                  = (known after apply)
      + associate_public_ip_address          = true
      + availability_zone                    = (known after apply)
      + cpu_core_count                       = (known after apply)
      + cpu_threads_per_core                 = (known after apply)
      + disable_api_termination              = (known after apply)
      + ebs_optimized                        = (known after apply)
      + get_password_data                    = false
      + host_id                              = (known after apply)
      + iam_instance_profile                 = (known after apply)
      + id                                   = (known after apply)
      + instance_initiated_shutdown_behavior = (known after apply)
      + instance_state                       = (known after apply)
      + instance_type                        = "t3.2xlarge"
      + ipv6_address_count                   = (known after apply)
      + ipv6_addresses                       = (known after apply)
      + key_name                             = "aakulov"
      + monitoring                           = (known after apply)
      + outpost_arn                          = (known after apply)
      + password_data                        = (known after apply)
      + placement_group                      = (known after apply)
      + placement_partition_number           = (known after apply)
      + primary_network_interface_id         = (known after apply)
      + private_dns                          = (known after apply)
      + private_ip                           = (known after apply)
      + public_dns                           = (known after apply)
      + public_ip                            = (known after apply)
      + secondary_private_ips                = (known after apply)
      + security_groups                      = (known after apply)
      + source_dest_check                    = true
      + subnet_id                            = (known after apply)
      + tags                                 = {
          + "Name" = "aakulov-aws7"
        }
      + tags_all                             = {
          + "Name" = "aakulov-aws7"
        }
      + tenancy                              = (known after apply)
      + user_data                            = (known after apply)
      + user_data_base64                     = (known after apply)
      + vpc_security_group_ids               = (known after apply)

      + capacity_reservation_specification {
          + capacity_reservation_preference = (known after apply)

          + capacity_reservation_target {
              + capacity_reservation_id = (known after apply)
            }
        }

      + ebs_block_device {
          + delete_on_termination = (known after apply)
          + device_name           = (known after apply)
          + encrypted             = (known after apply)
          + iops                  = (known after apply)
          + kms_key_id            = (known after apply)
          + snapshot_id           = (known after apply)
          + tags                  = (known after apply)
          + throughput            = (known after apply)
          + volume_id             = (known after apply)
          + volume_size           = (known after apply)
          + volume_type           = (known after apply)
        }

      + enclave_options {
          + enabled = (known after apply)
        }

      + ephemeral_block_device {
          + device_name  = (known after apply)
          + no_device    = (known after apply)
          + virtual_name = (known after apply)
        }

      + metadata_options {
          + http_endpoint               = "enabled"
          + http_put_response_hop_limit = (known after apply)
          + http_tokens                 = "required"
        }

      + network_interface {
          + delete_on_termination = (known after apply)
          + device_index          = (known after apply)
          + network_interface_id  = (known after apply)
        }

      + root_block_device {
          + delete_on_termination = (known after apply)
          + device_name           = (known after apply)
          + encrypted             = (known after apply)
          + iops                  = (known after apply)
          + kms_key_id            = (known after apply)
          + tags                  = (known after apply)
          + throughput            = (known after apply)
          + volume_id             = (known after apply)
          + volume_size           = (known after apply)
          + volume_type           = (known after apply)
        }
    }

  # aws_internet_gateway.igw will be created
  + resource "aws_internet_gateway" "igw" {
      + arn      = (known after apply)
      + id       = (known after apply)
      + owner_id = (known after apply)
      + tags     = {
          + "Name" = "aakulov-aws7"
        }
      + tags_all = {
          + "Name" = "aakulov-aws7"
        }
      + vpc_id   = (known after apply)
    }

  # aws_nat_gateway.nat will be created
  + resource "aws_nat_gateway" "nat" {
      + allocation_id        = (known after apply)
      + connectivity_type    = "public"
      + id                   = (known after apply)
      + network_interface_id = (known after apply)
      + private_ip           = (known after apply)
      + public_ip            = (known after apply)
      + subnet_id            = (known after apply)
      + tags                 = {
          + "Name" = "aakulov-aws7"
        }
      + tags_all             = {
          + "Name" = "aakulov-aws7"
        }
    }

  # aws_route53_record.aws7 will be created
  + resource "aws_route53_record" "aws7" {
      + allow_overwrite = true
      + fqdn            = (known after apply)
      + id              = (known after apply)
      + name            = "tfe7.anton.hashicorp-success.com"
      + records         = (known after apply)
      + ttl             = 300
      + type            = "A"
      + zone_id         = "Z077919913NMEBCGB4WS0"
    }

  # aws_route_table.aws7-private will be created
  + resource "aws_route_table" "aws7-private" {
      + arn              = (known after apply)
      + id               = (known after apply)
      + owner_id         = (known after apply)
      + propagating_vgws = (known after apply)
      + route            = [
          + {
              + carrier_gateway_id         = ""
              + cidr_block                 = "0.0.0.0/0"
              + destination_prefix_list_id = ""
              + egress_only_gateway_id     = ""
              + gateway_id                 = ""
              + instance_id                = ""
              + ipv6_cidr_block            = ""
              + local_gateway_id           = ""
              + nat_gateway_id             = (known after apply)
              + network_interface_id       = ""
              + transit_gateway_id         = ""
              + vpc_endpoint_id            = ""
              + vpc_peering_connection_id  = ""
            },
        ]
      + tags             = {
          + "Name" = "aakulov-aws7-private"
        }
      + tags_all         = {
          + "Name" = "aakulov-aws7-private"
        }
      + vpc_id           = (known after apply)
    }

  # aws_route_table.aws7-public will be created
  + resource "aws_route_table" "aws7-public" {
      + arn              = (known after apply)
      + id               = (known after apply)
      + owner_id         = (known after apply)
      + propagating_vgws = (known after apply)
      + route            = [
          + {
              + carrier_gateway_id         = ""
              + cidr_block                 = "0.0.0.0/0"
              + destination_prefix_list_id = ""
              + egress_only_gateway_id     = ""
              + gateway_id                 = (known after apply)
              + instance_id                = ""
              + ipv6_cidr_block            = ""
              + local_gateway_id           = ""
              + nat_gateway_id             = ""
              + network_interface_id       = ""
              + transit_gateway_id         = ""
              + vpc_endpoint_id            = ""
              + vpc_peering_connection_id  = ""
            },
        ]
      + tags             = {
          + "Name" = "aakulov-aws7-public"
        }
      + tags_all         = {
          + "Name" = "aakulov-aws7-public"
        }
      + vpc_id           = (known after apply)
    }

  # aws_route_table_association.aws7-private will be created
  + resource "aws_route_table_association" "aws7-private" {
      + id             = (known after apply)
      + route_table_id = (known after apply)
      + subnet_id      = (known after apply)
    }

  # aws_route_table_association.aws7-public will be created
  + resource "aws_route_table_association" "aws7-public" {
      + id             = (known after apply)
      + route_table_id = (known after apply)
      + subnet_id      = (known after apply)
    }

  # aws_s3_bucket.aws7 will be created
  + resource "aws_s3_bucket" "aws7" {
      + acceleration_status         = (known after apply)
      + acl                         = "private"
      + arn                         = (known after apply)
      + bucket                      = "aakulov-aws7-tfe-data"
      + bucket_domain_name          = (known after apply)
      + bucket_regional_domain_name = (known after apply)
      + force_destroy               = true
      + hosted_zone_id              = (known after apply)
      + id                          = (known after apply)
      + region                      = (known after apply)
      + request_payer               = (known after apply)
      + tags                        = {
          + "Name" = "aakulov-aws7-tfe-data"
        }
      + tags_all                    = {
          + "Name" = "aakulov-aws7-tfe-data"
        }
      + website_domain              = (known after apply)
      + website_endpoint            = (known after apply)

      + versioning {
          + enabled    = true
          + mfa_delete = false
        }
    }

  # aws_s3_bucket_public_access_block.aws7 will be created
  + resource "aws_s3_bucket_public_access_block" "aws7" {
      + block_public_acls       = true
      + block_public_policy     = true
      + bucket                  = (known after apply)
      + id                      = (known after apply)
      + ignore_public_acls      = true
      + restrict_public_buckets = true
    }

  # aws_security_group.aakulov-aws7 will be created
  + resource "aws_security_group" "aakulov-aws7" {
      + arn                    = (known after apply)
      + description            = "Managed by Terraform"
      + egress                 = [
          + {
              + cidr_blocks      = [
                  + "0.0.0.0/0",
                ]
              + description      = ""
              + from_port        = 0
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "-1"
              + security_groups  = []
              + self             = false
              + to_port          = 0
            },
        ]
      + id                     = (known after apply)
      + ingress                = [
          + {
              + cidr_blocks      = [
                  + "0.0.0.0/0",
                ]
              + description      = ""
              + from_port        = 22
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "tcp"
              + security_groups  = []
              + self             = false
              + to_port          = 22
            },
          + {
              + cidr_blocks      = [
                  + "0.0.0.0/0",
                ]
              + description      = ""
              + from_port        = 443
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "tcp"
              + security_groups  = []
              + self             = false
              + to_port          = 443
            },
          + {
              + cidr_blocks      = [
                  + "0.0.0.0/0",
                ]
              + description      = ""
              + from_port        = 80
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "tcp"
              + security_groups  = []
              + self             = false
              + to_port          = 80
            },
          + {
              + cidr_blocks      = [
                  + "0.0.0.0/0",
                ]
              + description      = ""
              + from_port        = 8800
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "tcp"
              + security_groups  = []
              + self             = false
              + to_port          = 8800
            },
          + {
              + cidr_blocks      = []
              + description      = ""
              + from_port        = 5432
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "tcp"
              + security_groups  = []
              + self             = true
              + to_port          = 5432
            },
        ]
      + name                   = "aakulov-aws7-sg"
      + name_prefix            = (known after apply)
      + owner_id               = (known after apply)
      + revoke_rules_on_delete = false
      + tags                   = {
          + "Name" = "aakulov-aws7-sg"
        }
      + tags_all               = {
          + "Name" = "aakulov-aws7-sg"
        }
      + vpc_id                 = (known after apply)
    }

  # aws_security_group.aws7-internal-sg will be created
  + resource "aws_security_group" "aws7-internal-sg" {
      + arn                    = (known after apply)
      + description            = "Managed by Terraform"
      + egress                 = [
          + {
              + cidr_blocks      = [
                  + "0.0.0.0/0",
                ]
              + description      = ""
              + from_port        = 0
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "-1"
              + security_groups  = []
              + self             = false
              + to_port          = 0
            },
        ]
      + id                     = (known after apply)
      + ingress                = [
          + {
              + cidr_blocks      = [
                  + "0.0.0.0/0",
                ]
              + description      = ""
              + from_port        = -1
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "icmp"
              + security_groups  = []
              + self             = false
              + to_port          = -1
            },
          + {
              + cidr_blocks      = [
                  + "0.0.0.0/0",
                ]
              + description      = ""
              + from_port        = 22
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "tcp"
              + security_groups  = []
              + self             = false
              + to_port          = 22
            },
          + {
              + cidr_blocks      = [
                  + "0.0.0.0/0",
                ]
              + description      = ""
              + from_port        = 443
              + ipv6_cidr_blocks = []
              + prefix_list_ids  = []
              + protocol         = "tcp"
              + security_groups  = []
              + self             = false
              + to_port          = 443
            },
        ]
      + name                   = "aakulov-aws7-internal-sg"
      + name_prefix            = (known after apply)
      + owner_id               = (known after apply)
      + revoke_rules_on_delete = false
      + tags                   = {
          + "Name" = "aakulov-aws7-internal-sg"
        }
      + tags_all               = {
          + "Name" = "aakulov-aws7-internal-sg"
        }
      + vpc_id                 = (known after apply)
    }

  # aws_subnet.subnet_private1 will be created
  + resource "aws_subnet" "subnet_private1" {
      + arn                             = (known after apply)
      + assign_ipv6_address_on_creation = false
      + availability_zone               = "eu-central-1b"
      + availability_zone_id            = (known after apply)
      + cidr_block                      = "10.5.1.0/24"
      + id                              = (known after apply)
      + ipv6_cidr_block_association_id  = (known after apply)
      + map_public_ip_on_launch         = false
      + owner_id                        = (known after apply)
      + tags_all                        = (known after apply)
      + vpc_id                          = (known after apply)
    }

  # aws_subnet.subnet_private2 will be created
  + resource "aws_subnet" "subnet_private2" {
      + arn                             = (known after apply)
      + assign_ipv6_address_on_creation = false
      + availability_zone               = "eu-central-1c"
      + availability_zone_id            = (known after apply)
      + cidr_block                      = "10.5.3.0/24"
      + id                              = (known after apply)
      + ipv6_cidr_block_association_id  = (known after apply)
      + map_public_ip_on_launch         = false
      + owner_id                        = (known after apply)
      + tags_all                        = (known after apply)
      + vpc_id                          = (known after apply)
    }

  # aws_subnet.subnet_public1 will be created
  + resource "aws_subnet" "subnet_public1" {
      + arn                             = (known after apply)
      + assign_ipv6_address_on_creation = false
      + availability_zone               = "eu-central-1b"
      + availability_zone_id            = (known after apply)
      + cidr_block                      = "10.5.2.0/24"
      + id                              = (known after apply)
      + ipv6_cidr_block_association_id  = (known after apply)
      + map_public_ip_on_launch         = false
      + owner_id                        = (known after apply)
      + tags_all                        = (known after apply)
      + vpc_id                          = (known after apply)
    }

  # aws_subnet.subnet_public2 will be created
  + resource "aws_subnet" "subnet_public2" {
      + arn                             = (known after apply)
      + assign_ipv6_address_on_creation = false
      + availability_zone               = "eu-central-1c"
      + availability_zone_id            = (known after apply)
      + cidr_block                      = "10.5.4.0/24"
      + id                              = (known after apply)
      + ipv6_cidr_block_association_id  = (known after apply)
      + map_public_ip_on_launch         = false
      + owner_id                        = (known after apply)
      + tags_all                        = (known after apply)
      + vpc_id                          = (known after apply)
    }

  # aws_vpc.vpc will be created
  + resource "aws_vpc" "vpc" {
      + arn                              = (known after apply)
      + assign_generated_ipv6_cidr_block = false
      + cidr_block                       = "10.5.0.0/16"
      + default_network_acl_id           = (known after apply)
      + default_route_table_id           = (known after apply)
      + default_security_group_id        = (known after apply)
      + dhcp_options_id                  = (known after apply)
      + enable_classiclink               = (known after apply)
      + enable_classiclink_dns_support   = (known after apply)
      + enable_dns_hostnames             = true
      + enable_dns_support               = true
      + id                               = (known after apply)
      + instance_tenancy                 = "default"
      + ipv6_association_id              = (known after apply)
      + ipv6_cidr_block                  = (known after apply)
      + main_route_table_id              = (known after apply)
      + owner_id                         = (known after apply)
      + tags                             = {
          + "Name" = "aakulov-aws7"
        }
      + tags_all                         = {
          + "Name" = "aakulov-aws7"
        }
    }

  # tls_private_key.aws7 will be created
  + resource "tls_private_key" "aws7" {
      + algorithm                  = "RSA"
      + ecdsa_curve                = "P224"
      + id                         = (known after apply)
      + private_key_pem            = (sensitive value)
      + public_key_fingerprint_md5 = (known after apply)
      + public_key_openssh         = (known after apply)
      + public_key_pem             = (known after apply)
      + rsa_bits                   = 2048
    }

  # tls_self_signed_cert.aws7 will be created
  + resource "tls_self_signed_cert" "aws7" {
      + allowed_uses          = [
          + "key_encipherment",
          + "digital_signature",
          + "server_auth",
        ]
      + cert_pem              = (known after apply)
      + dns_names             = [
          + "tfe7.anton.hashicorp-success.com",
        ]
      + early_renewal_hours   = 744
      + id                    = (known after apply)
      + key_algorithm         = "RSA"
      + private_key_pem       = (sensitive value)
      + ready_for_renewal     = true
      + validity_end_time     = (known after apply)
      + validity_period_hours = 8928
      + validity_start_time   = (known after apply)

      + subject {
          + common_name  = "tfe7.anton.hashicorp-success.com"
          + organization = "aakulov sandbox"
        }
    }

Plan: 25 to add, 0 to change, 0 to destroy.

Changes to Outputs:
  + aws_url = "tfe7.anton.hashicorp-success.com"

Do you want to perform these actions?
  Terraform will perform the actions described above.
  Only 'yes' will be accepted to approve.

  Enter a value: yes

tls_private_key.aws7: Creating...
tls_private_key.aws7: Creation complete after 0s [id=42b8301d5b3a0adec852b2a3f49c7396df6d2007]
tls_self_signed_cert.aws7: Creating...
tls_self_signed_cert.aws7: Creation complete after 0s [id=287433814863524592732522140055983667632]
aws_eip.aws7: Creating...
aws_vpc.vpc: Creating...
aws_iam_role.aakulov-aws7-iam-role-ec2-s3: Creating...
aws_s3_bucket.aws7: Creating...
aws_eip.aws7: Creation complete after 1s [id=eipalloc-091801597e997f58a]
aws_iam_role.aakulov-aws7-iam-role-ec2-s3: Creation complete after 3s [id=aakulov-aws7-iam-role-ec2-s3]
aws_iam_instance_profile.aakulov-aws7-ec2-s3: Creating...
aws_s3_bucket.aws7: Creation complete after 3s [id=aakulov-aws7-tfe-data]
aws_s3_bucket_public_access_block.aws7: Creating...
aws_iam_role_policy.aakulov-aws7-ec2-s3: Creating...
aws_s3_bucket_public_access_block.aws7: Creation complete after 1s [id=aakulov-aws7-tfe-data]
aws_iam_role_policy.aakulov-aws7-ec2-s3: Creation complete after 2s [id=aakulov-aws7-iam-role-ec2-s3:aakulov-aws7-ec2-s3]
aws_iam_instance_profile.aakulov-aws7-ec2-s3: Creation complete after 3s [id=aakulov-aws7-ec2-s3]
aws_vpc.vpc: Still creating... [10s elapsed]
aws_vpc.vpc: Creation complete after 13s [id=vpc-03b654ec47950329c]
aws_internet_gateway.igw: Creating...
aws_subnet.subnet_private2: Creating...
aws_subnet.subnet_private1: Creating...
aws_subnet.subnet_public2: Creating...
aws_subnet.subnet_public1: Creating...
aws_security_group.aws7-internal-sg: Creating...
aws_security_group.aakulov-aws7: Creating...
aws_internet_gateway.igw: Creation complete after 0s [id=igw-0b107b5f9ceb07c6e]
aws_subnet.subnet_private1: Creation complete after 0s [id=subnet-0b73fffe142c8a5be]
aws_route_table.aws7-public: Creating...
aws_subnet.subnet_public2: Creation complete after 0s [id=subnet-00fe12afd19b59ffb]
aws_subnet.subnet_public1: Creation complete after 0s [id=subnet-0be90f409f295238e]
aws_subnet.subnet_private2: Creation complete after 0s [id=subnet-0141776b624bdc499]
aws_nat_gateway.nat: Creating...
aws_db_subnet_group.aws7: Creating...
aws_route_table.aws7-public: Creation complete after 1s [id=rtb-00351ff5f07a8255b]
aws_db_subnet_group.aws7: Creation complete after 1s [id=aakulov-aws7]
aws_route_table_association.aws7-public: Creating...
aws_security_group.aakulov-aws7: Creation complete after 1s [id=sg-0c61896d869708944]
aws_security_group.aws7-internal-sg: Creation complete after 1s [id=sg-00b6258815ba6c017]
aws_db_instance.aws7: Creating...
aws_route_table_association.aws7-public: Creation complete after 1s [id=rtbassoc-0ad31c6f90b389ea6]
aws_nat_gateway.nat: Still creating... [10s elapsed]
aws_db_instance.aws7: Still creating... [10s elapsed]
aws_nat_gateway.nat: Still creating... [20s elapsed]
aws_db_instance.aws7: Still creating... [20s elapsed]
aws_nat_gateway.nat: Still creating... [30s elapsed]
aws_db_instance.aws7: Still creating... [30s elapsed]
aws_nat_gateway.nat: Still creating... [40s elapsed]
aws_db_instance.aws7: Still creating... [40s elapsed]
aws_nat_gateway.nat: Still creating... [50s elapsed]
aws_db_instance.aws7: Still creating... [50s elapsed]
aws_nat_gateway.nat: Still creating... [1m0s elapsed]
aws_db_instance.aws7: Still creating... [1m0s elapsed]
aws_nat_gateway.nat: Still creating... [1m10s elapsed]
aws_db_instance.aws7: Still creating... [1m10s elapsed]
aws_nat_gateway.nat: Still creating... [1m20s elapsed]
aws_db_instance.aws7: Still creating... [1m20s elapsed]
aws_nat_gateway.nat: Still creating... [1m30s elapsed]
aws_db_instance.aws7: Still creating... [1m31s elapsed]
aws_nat_gateway.nat: Still creating... [1m40s elapsed]
aws_db_instance.aws7: Still creating... [1m41s elapsed]
aws_nat_gateway.nat: Creation complete after 1m46s [id=nat-027b23171181bc45d]
aws_route_table.aws7-private: Creating...
aws_route_table.aws7-private: Creation complete after 1s [id=rtb-0b05be12d4db1db82]
aws_route_table_association.aws7-private: Creating...
aws_route_table_association.aws7-private: Creation complete after 1s [id=rtbassoc-0356696f2c1e26d4e]
aws_db_instance.aws7: Still creating... [1m51s elapsed]
aws_db_instance.aws7: Still creating... [2m1s elapsed]
aws_db_instance.aws7: Still creating... [2m11s elapsed]
aws_db_instance.aws7: Still creating... [2m21s elapsed]
aws_db_instance.aws7: Still creating... [2m31s elapsed]
aws_db_instance.aws7: Still creating... [2m41s elapsed]
aws_db_instance.aws7: Still creating... [2m51s elapsed]
aws_db_instance.aws7: Still creating... [3m1s elapsed]
aws_db_instance.aws7: Still creating... [3m11s elapsed]
aws_db_instance.aws7: Creation complete after 3m16s [id=terraform-20211122095341487600000001]
data.template_file.install_tfe_sh: Reading...
data.template_file.install_tfe_sh: Read complete after 0s [id=8159b7ef82ca90589a9711d2a5d47c5866c42db319d162267d2f19929be07b4e]
data.template_cloudinit_config.aws7_cloudinit: Reading...
data.template_cloudinit_config.aws7_cloudinit: Read complete after 0s [id=2343644157]
aws_instance.aws7: Creating...
aws_instance.aws7: Still creating... [10s elapsed]
aws_instance.aws7: Creation complete after 13s [id=i-092f86289e90c9a76]
aws_route53_record.aws7: Creating...
aws_route53_record.aws7: Still creating... [10s elapsed]
aws_route53_record.aws7: Still creating... [20s elapsed]
aws_route53_record.aws7: Still creating... [30s elapsed]
aws_route53_record.aws7: Creation complete after 35s [id=Z077919913NMEBCGB4WS0_tfe7.anton.hashicorp-success.com_A]

Apply complete! Resources: 25 added, 0 changed, 0 destroyed.

Outputs:

aws_url = "tfe7.anton.hashicorp-success.com"

```
