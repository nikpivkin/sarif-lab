module "web_sg" {
  source  = "terraform-aws-modules/security-group/aws"
  version = "5.1.2"

  name         = "lab"
  vpc_id       = "vpc-12345678"
  egress_rules = ["https-443-tcp"]
}
