# tf-ob-tfe-aws-airgap pre-req

This manual is dedicated to upload Terrafrom Enterprise assets required for the installation to Amazon S3

## Requirements

- Hashicorp terraform recent version installed
[Terraform installation manual](https://learn.hashicorp.com/tutorials/terraform/install-cli)

- git installed
[Git installation manual](https://git-scm.com/download/mac)

- Amazon AWS account credentials saved in .aws/credentials file
[Configuration and credential file settings](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html)

## Preparation 

- Create file testing.tfvars with following contents

```
region        = "eu-central-1"
```

- Create folder `upload`

```bash
mkdir upload
```

- Copy to folder `upload` following files

  - license.rli

## Run terraform code

- Initialize terraform

```bash
terraform init
```

Sample result

```
Initializing the backend...

Initializing provider plugins...
- Reusing previous version of hashicorp/aws from the dependency lock file
- Using previously-installed hashicorp/aws v3.57.0

Terraform has been successfully initialized!

You may now begin working with Terraform. Try running "terraform plan" to see
any changes that are required for your infrastructure. All Terraform commands
should now work.

If you ever set or change modules or backend configuration for Terraform,
rerun this command to reinitialize your working directory. If you forget, other
commands will detect it and remind you to do so if necessary.
```

- Run the `terraform apply` to upload the assets to the Amazon S3 bucket

```bash
terraform apply
```


