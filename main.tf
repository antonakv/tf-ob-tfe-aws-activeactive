locals {
  s3endpoint      = format("http://%s:9000", aws_instance.aws10_minio.private_ip)
  s3endpointlocal = "http://127.0.0.1:9000"
  tfe_hostname = format("%s%s", random_pet.dnsid.id, var.tfe_hostname)
  tfe_hostname_jump = format("%s%s", random_pet.dnsid.id, var.tfe_hostname_jump)
}

provider "aws" {
  region = var.region
}

resource "tls_private_key" "aws10" {
  algorithm = "RSA"
}

resource "tls_self_signed_cert" "aws10" {
  key_algorithm         = tls_private_key.aws10.algorithm
  private_key_pem       = tls_private_key.aws10.private_key_pem
  validity_period_hours = 8928
  early_renewal_hours   = 744

  allowed_uses = [
    "key_encipherment",
    "digital_signature",
    "server_auth",
  ]

  dns_names = [var.tfe_hostname]

  subject {
    common_name  = var.tfe_hostname
    organization = "aakulov sandbox"
  }

}

resource "aws_vpc" "vpc" {
  cidr_block           = var.cidr_vpc
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags = {
    Name = "aakulov-aws10"
  }
}

resource "aws_subnet" "subnet_private1" {
  vpc_id            = aws_vpc.vpc.id
  cidr_block        = var.cidr_subnet1
  availability_zone = "eu-central-1b"
}

resource "aws_subnet" "subnet_private2" {
  vpc_id            = aws_vpc.vpc.id
  cidr_block        = var.cidr_subnet3
  availability_zone = "eu-central-1c"
}

resource "aws_subnet" "subnet_public1" {
  vpc_id            = aws_vpc.vpc.id
  cidr_block        = var.cidr_subnet2
  availability_zone = "eu-central-1b"
}

resource "aws_subnet" "subnet_public2" {
  vpc_id            = aws_vpc.vpc.id
  cidr_block        = var.cidr_subnet4
  availability_zone = "eu-central-1c"
}

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.vpc.id
  tags = {
    Name = "aakulov-aws10"
  }
}

resource "aws_eip" "aws10" {
  vpc = true
  instance = aws_instance.aws10.id
  depends_on = [
    aws_internet_gateway.igw
  ]
}

resource "aws_eip" "aws10jump" {
  vpc = true
  instance = aws_instance.aws10jump.id
  depends_on = [
    aws_internet_gateway.igw
  ]
}

resource "aws_eip" "aws10nat" {
  vpc = true
  depends_on = [
    aws_internet_gateway.igw
  ]
}

resource "aws_nat_gateway" "nat" {
  allocation_id = aws_eip.aws10nat.id
  subnet_id     = aws_subnet.subnet_public1.id
  depends_on    = [aws_internet_gateway.igw]
  tags = {
    Name = "aakulov-aws10"
  }
}

resource "aws_route_table" "aws10-private" {
  vpc_id = aws_vpc.vpc.id


  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.nat.id
  }

  tags = {
    Name = "aakulov-aws10-private"
  }
}

resource "aws_route_table" "aws10-public" {
  vpc_id = aws_vpc.vpc.id


  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }

  tags = {
    Name = "aakulov-aws10-public"
  }
}

resource "aws_route_table_association" "aws10-private" {
  subnet_id      = aws_subnet.subnet_private1.id
  route_table_id = aws_route_table.aws10-private.id
}

resource "aws_route_table_association" "aws10-public" {
  subnet_id      = aws_subnet.subnet_public1.id
  route_table_id = aws_route_table.aws10-public.id
}

resource "aws_security_group" "aws10-internal-sg" {
  vpc_id = aws_vpc.vpc.id
  name   = "aakulov-aws10-internal-sg"
  tags = {
    Name = "aakulov-aws10-internal-sg"
  }

  ingress {
    from_port   = -1
    to_port     = -1
    protocol    = "icmp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    security_groups = [aws_security_group.aws10-lb-sg.id]
  }

  ingress {
    from_port   = 8800
    to_port     = 8800
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port       = 8800
    to_port         = 8800
    protocol        = "tcp"
    security_groups = [aws_security_group.aws10-lb-sg.id]
  }

  ingress {
    from_port = 5432
    to_port   = 5432
    protocol  = "tcp"
    self      = true
  }

  ingress {
    from_port = 9000
    to_port   = 9000
    protocol  = "tcp"
    self      = true
  }

  ingress {
    from_port = 8800
    to_port   = 8800
    protocol  = "tcp"
    self      = true
  }

  ingress {
    from_port = 443
    to_port   = 443
    protocol  = "tcp"
    self      = true
  }

  ingress {
    from_port       = 22
    to_port         = 22
    protocol        = "tcp"
    security_groups = [aws_security_group.aws10-public-sg.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "aws10-public-sg" {
  vpc_id = aws_vpc.vpc.id
  name   = "aakulov-aws10-public-sg"
  tags = {
    Name = "aakulov-aws10-public-sg"
  }

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 8800
    to_port     = 8800
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "random_pet" "dnsid" {
  length = 1
}

resource "aws_route53_record" "aws10" {
  zone_id    = "Z077919913NMEBCGB4WS0"
  name       = var.tfe_hostname
  type       = "CNAME"
  ttl        = "300"
  records    = [aws_lb.aws10.dns_name]
  depends_on = [aws_lb.aws10]
}

resource "aws_route53_record" "aws10jump" {
  zone_id    = "Z077919913NMEBCGB4WS0"
  name       = var.tfe_hostname_jump
  type       = "A"
  ttl        = "300"
  records    = [aws_eip.aws10jump.public_ip]
  depends_on = [aws_instance.aws10jump, aws_eip.aws10jump]
}

resource "aws_route53_record" "cert_validation" {
  for_each = {
    for dvo in aws_acm_certificate.aws10.domain_validation_options : dvo.domain_name => {
      name   = dvo.resource_record_name
      record = dvo.resource_record_value
      type   = dvo.resource_record_type
    }
  }
  zone_id         = "Z077919913NMEBCGB4WS0"
  ttl             = 60
  type            = each.value.type
  name            = each.value.name
  records         = [each.value.record]
  allow_overwrite = true
}

resource "aws_db_subnet_group" "aws10" {
  name       = "aakulov-aws10"
  subnet_ids = [aws_subnet.subnet_public1.id, aws_subnet.subnet_public2.id, aws_subnet.subnet_private1.id, aws_subnet.subnet_private2.id]
  tags = {
    Name = "aakulov-aws10"
  }
}

resource "aws_db_instance" "aws10" {
  allocated_storage      = 20
  max_allocated_storage  = 100
  engine                 = "postgres"
  engine_version         = "12.7"
  db_name                = "mydbtfe"
  username               = "postgres"
  password               = var.db_password
  instance_class         = var.db_instance_type
  db_subnet_group_name   = aws_db_subnet_group.aws10.name
  vpc_security_group_ids = [aws_security_group.aws10-internal-sg.id]
  skip_final_snapshot    = true
  tags = {
    Name = "aakulov-aws10"
  }
}

data "template_file" "configure_minio_sh" {
  template = file("templates/configure_minio.sh.tpl")
  vars = {
    minio_secret_key = var.minio_secret_key
    minio_access_key = var.minio_access_key
    s3bucket         = var.s3_bucket
  }
}

data "template_cloudinit_config" "aws10_minio_cloudinit" {
  gzip          = true
  base64_encode = true

  part {
    filename     = "configure_minio.sh"
    content_type = "text/x-shellscript"
    content      = data.template_file.configure_minio_sh.rendered
  }
}

resource "aws_instance" "aws10_minio" {
  ami                         = var.ami_minio
  instance_type               = var.instance_type_minio
  key_name                    = var.key_name
  vpc_security_group_ids      = [aws_security_group.aws10-internal-sg.id]
  subnet_id                   = aws_subnet.subnet_private1.id
  associate_public_ip_address = true
  user_data                   = data.template_cloudinit_config.aws10_minio_cloudinit.rendered
  metadata_options {
    http_tokens   = "required"
    http_endpoint = "enabled"
  }
  tags = {
    Name = "aakulov-aws10-minio"
  }
}

data "template_file" "install_tfe_minio_sh" {
  template = file("templates/install_tfe_minio.sh.tpl")
  vars = {
    enc_password       = var.enc_password
    hostname           = var.tfe_hostname
    release_sequence   = var.release_sequence
    pgsqlhostname      = aws_db_instance.aws10.address
    pgsqlpassword      = var.db_password
    pguser             = aws_db_instance.aws10.username
    s3bucket           = var.s3_bucket
    s3region           = var.region
    cert_pem           = tls_self_signed_cert.aws10.cert_pem
    key_pem            = tls_private_key.aws10.private_key_pem
    minio_secret_key   = var.minio_secret_key
    minio_access_key   = var.minio_access_key
    s3endpoint         = local.s3endpoint
    tfe_admin_username = var.tfe_admin_username
    tfe_admin_password = var.tfe_admin_password
    tfe_admin_email    = var.tfe_admin_email
    tfe_hostname       = var.tfe_hostname
  }
}

data "template_cloudinit_config" "aws10_cloudinit" {
  gzip          = true
  base64_encode = true

  part {
    filename     = "install_tfe.sh"
    content_type = "text/x-shellscript"
    content      = data.template_file.install_tfe_minio_sh.rendered
  }
}

resource "aws_instance" "aws10" {
  ami                         = var.ami
  instance_type               = var.instance_type
  key_name                    = var.key_name
  vpc_security_group_ids      = [aws_security_group.aws10-internal-sg.id]
  subnet_id                   = aws_subnet.subnet_private1.id
  associate_public_ip_address = true
  user_data                   = data.template_cloudinit_config.aws10_cloudinit.rendered
  iam_instance_profile        = aws_iam_instance_profile.aakulov-aws10-ec2-s3.id
  depends_on = [
    aws_instance.aws10jump, aws_instance.aws10_minio, aws_elasticache_replication_group.aws10, aws_db_instance.aws10
  ]
  metadata_options {
    http_tokens                 = "required"
    http_endpoint               = "enabled"
    http_put_response_hop_limit = 2
  }
  tags = {
    Name = "aakulov-aws10"
  }
}

resource "aws_eip_association" "aws10jump" {
  instance_id   = aws_instance.aws10jump.id
  allocation_id = aws_eip.aws10jump.id
}

resource "aws_eip_association" "aws10" {
  instance_id   = aws_instance.aws10.id
  allocation_id = aws_eip.aws10.id
}

resource "aws_instance" "aws10jump" {
  ami                         = var.ami
  instance_type               = var.instance_type_jump
  key_name                    = var.key_name
  vpc_security_group_ids      = [aws_security_group.aws10-public-sg.id]
  subnet_id                   = aws_subnet.subnet_public1.id
  associate_public_ip_address = true
  metadata_options {
    http_tokens                 = "required"
    http_endpoint               = "enabled"
    http_put_response_hop_limit = 2
  }
  tags = {
    Name = "aakulov-aws10jump"
  }
}

resource "aws_acm_certificate" "aws10" {
  domain_name       = var.tfe_hostname
  validation_method = "DNS"

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_acm_certificate_validation" "aws10" {
  certificate_arn = aws_acm_certificate.aws10.arn
  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_lb_target_group" "aws10-443" {
  name        = "aakulov-aws10-443"
  port        = 443
  protocol    = "HTTPS"
  vpc_id      = aws_vpc.vpc.id
  target_type = "instance"
  slow_start  = 900
  lifecycle {
    create_before_destroy = true
  }
  health_check {
    path                = "/"
    port                = 8800
    healthy_threshold   = 6
    unhealthy_threshold = 2
    timeout             = 2
    interval            = 5
    protocol            = "HTTPS"
    matcher             = "200,302,303"
  }
  stickiness {
    enabled = true
    type    = "lb_cookie"
  }
}

resource "aws_lb_target_group" "aws10-8800" {
  name        = "aakulov-aws10-8800"
  port        = 8800
  protocol    = "HTTPS"
  vpc_id      = aws_vpc.vpc.id
  target_type = "instance"
  slow_start  = 900
  lifecycle {
    create_before_destroy = true
  }
  health_check {
    path                = "/"
    port                = 8800
    healthy_threshold   = 6
    unhealthy_threshold = 2
    timeout             = 2
    interval            = 5
    protocol            = "HTTPS"
    matcher             = "200,302,303"
  }
  stickiness {
    enabled = true
    type    = "lb_cookie"
  }
}

resource "aws_lb" "aws10" {
  name                             = "aakulov-aws10"
  internal                         = false
  load_balancer_type               = "application"
  security_groups                  = [aws_security_group.aws10-lb-sg.id]
  enable_cross_zone_load_balancing = true
  subnets                          = [aws_subnet.subnet_public1.id, aws_subnet.subnet_public2.id]
  enable_deletion_protection       = false
  enable_http2                     = false
}

resource "aws_lb_listener" "aws10-443" {
  load_balancer_arn = aws_lb.aws10.arn
  port              = "443"
  protocol          = "HTTPS"
  certificate_arn   = aws_acm_certificate.aws10.arn
  ssl_policy        = "ELBSecurityPolicy-FS-1-2-Res-2020-10"
  depends_on = [
    aws_lb.aws10
  ]
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.aws10-443.arn
  }
}

resource "aws_lb_listener" "aws10-8800" {
  load_balancer_arn = aws_lb.aws10.arn
  port              = "8800"
  protocol          = "HTTPS"
  certificate_arn   = aws_acm_certificate.aws10.arn
  ssl_policy        = "ELBSecurityPolicy-FS-1-2-Res-2020-10"
  depends_on = [
    aws_lb.aws10
  ]
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.aws10-8800.arn
  }
}

resource "aws_lb_listener_rule" "aws10-8800" {
  listener_arn = aws_lb_listener.aws10-8800.arn
  condition {
    host_header {
      values = [var.tfe_hostname]
    }
  }
  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.aws10-8800.arn
  }
}

resource "aws_lb_listener_rule" "aws10-443" {
  listener_arn = aws_lb_listener.aws10-443.arn
  condition {
    host_header {
      values = [var.tfe_hostname]
    }
  }
  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.aws10-443.arn
  }
}

resource "aws_lb_target_group_attachment" "aws10-443" {
  target_group_arn = aws_lb_target_group.aws10-443.arn
  target_id        = aws_instance.aws10.id
  port             = 443
}

resource "aws_lb_target_group_attachment" "aws10-8800" {
  target_group_arn = aws_lb_target_group.aws10-8800.arn
  target_id        = aws_instance.aws10.id
  port             = 8800
}

resource "aws_security_group" "aws10-lb-sg" {
  vpc_id = aws_vpc.vpc.id
  name   = "aakulov-aws10-lb-sg"
  tags = {
    Name = "aakulov-aws10-lb-sg"
  }

  ingress {
    from_port   = 8800
    to_port     = 8800
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "aws10-redis-sg" {
  vpc_id = aws_vpc.vpc.id
  name   = "aakulov-aws10-redis-sg"
  tags = {
    Name = "aakulov-aws10-redis-sg"
  }

  ingress {
    from_port       = 7480
    to_port         = 7480
    protocol        = "tcp"
    security_groups = [aws_security_group.aws10-internal-sg.id]
  }
}

# Extra security group rules to avoid Cycle error

resource "aws_security_group_rule" "aws10-lb-sg-to-aws10-internal-sg-allow-443" {
  type                     = "egress"
  from_port                = 443
  to_port                  = 443
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.aws10-internal-sg.id
  security_group_id        = aws_security_group.aws10-lb-sg.id
}

resource "aws_security_group_rule" "aws10-lb-sg-to-aws10-internal-sg-allow-8800" {
  type                     = "egress"
  from_port                = 8800
  to_port                  = 8800
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.aws10-internal-sg.id
  security_group_id        = aws_security_group.aws10-lb-sg.id
}

resource "aws_iam_instance_profile" "aakulov-aws10-ec2-s3" {
  name = "aakulov-aws10-ec2-s3"
  role = aws_iam_role.aakulov-aws10-iam-role-ec2-s3.name
}

resource "aws_iam_role_policy" "aakulov-aws10-ec2-s3" {
  name = "aakulov-aws10-ec2-s3"
  role = aws_iam_role.aakulov-aws10-iam-role-ec2-s3.id
  policy = jsonencode({
    "Version" : "2012-10-17",
    "Statement" : [
      {
        "Sid" : "VisualEditor0",
        "Effect" : "Allow",
        "Action" : [
          "s3:DeleteObject",
          "s3:GetObject",
          "s3:PutObject",
          "s3:GetBucketLocation",
          "s3:ListBucket"
        ],
        "Resource" : "*"
      },
      {
        "Sid" : "VisualEditor1",
        "Effect" : "Allow",
        "Action" : "s3:*",
        "Resource" : "arn:aws:s3:::aakulov-aws10-tfe-tfe"
      }
    ]
  })
}

resource "aws_iam_role" "aakulov-aws10-iam-role-ec2-s3" {
  name = "aakulov-aws10-iam-role-ec2-s3"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = ""
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      },
    ]
  })

  tags = {
    tag-key = "aakulov-aws10-iam-role-ec2-s3"
  }
}

resource "aws_elasticache_subnet_group" "aws10" {
  name       = "aakulov-aws10"
  subnet_ids = [aws_subnet.subnet_private1.id, aws_subnet.subnet_private2.id]
}

resource "aws_elasticache_replication_group" "aws10" {
  node_type                  = var.instance_type_redis
  replication_group_id       = "aakulov-aws10"
  description                = "aakulov-aws10"
  apply_immediately          = true
  at_rest_encryption_enabled = true
  auth_token                 = var.redis_token
  automatic_failover_enabled = true
  availability_zones         = ["eu-central-1b", "eu-central-1c"]
  engine                     = "redis"
  engine_version             = "5.0.6"
  num_cache_clusters         = 2
  parameter_group_name       = "default.redis5.0"
  port                       = 7480
  security_group_ids         = [aws_security_group.aws10-redis-sg.id]
  subnet_group_name          = aws_elasticache_subnet_group.aws10.name
  transit_encryption_enabled = true
}

/* output "data_template" {
  value = data.template_file.install_tfe_minio_sh.rendered
} */

output "aws_jump" {
  value = aws_route53_record.aws10jump.fqdn
}

output "tfe_instance_private_ip" {
  value = aws_instance.aws10.private_ip
}

output "aws_url" {
  value = aws_route53_record.aws10.name
}
