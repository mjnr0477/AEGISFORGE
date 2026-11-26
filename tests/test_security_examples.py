import tempfile
import unittest
from pathlib import Path
from aegisforge.analyzers import analyze_text
from aegisforge.scanner import scan_directory

class TerraformAdditionalTests(unittest.TestCase):
    def test_flags_public_ipv6_rdp_ingress(self):
        source = '''
resource "aws_security_group" "rdp" {
  ingress {
    from_port = 3389
    to_port = 3389
    protocol = "tcp"
    ipv6_cidr_blocks = ["::/0"]
  }
}
'''
        self.assertIn("AF-TF-001", {f.rule_id for f in analyze_text(source, "network.tf")})

    def test_ignores_commented_out_ingress(self):
        source = '''
resource "aws_security_group" "safe" {
  # ingress {
  # from_port = 22
  # to_port = 22
  # protocol = "tcp"
  # cidr_blocks = ["0.0.0.0/0"]
  # }
}
'''
        self.assertNotIn("AF-TF-001", {f.rule_id for f in analyze_text(source, "network.tf")})

    def test_ignores_ingress_in_unrelated_resource(self):
        source = '''
resource "aws_vpc" "example" {
  ingress {
    from_port = 22
    to_port = 22
    protocol = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
'''
        self.assertNotIn("AF-TF-001", {f.rule_id for f in analyze_text(source, "network.tf")})

class PaymentExampleTests(unittest.TestCase):
    def test_vulnerable_and_hardened_fixtures_are_distinguished(self):
        root = Path(__file__).resolve().parents[1] / "examples" / "payment-webhook-lab"
        vulnerable = scan_directory(root / "vulnerable")
        hardened = scan_directory(root / "hardened")
        self.assertIn("AF-PAY-001", {f.rule_id for f in vulnerable.findings})
        self.assertNotIn("AF-PAY-001", {f.rule_id for f in hardened.findings})

if __name__ == "__main__":
    unittest.main()
