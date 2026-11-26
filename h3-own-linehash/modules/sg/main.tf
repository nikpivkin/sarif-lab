resource "aws_security_group" "this" {
  name        = "lab"
  description = "Lab security group"
}

resource "aws_security_group_rule" "egress_https_anywhere" {
  description       = "HTTPS to anywhere"
  type              = "egress"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.this.id
}
