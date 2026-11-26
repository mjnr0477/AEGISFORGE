import unittest
from aegisforge.analyzers import analyze_python, analyze_text

class PaymentSignatureTests(unittest.TestCase):
    def test_flags_ordinary_signature_equality(self):
        source = "if received_signature == expected_signature:\n    accept_payment()\n"
        findings = analyze_python(source, "webhook.py")
        self.assertIn("AF-PAY-001", {item.rule_id for item in findings})

    def test_does_not_flag_constant_time_signature_check(self):
        source = "if hmac.compare_digest(received_signature, expected_signature):\n    accept_payment()\n"
        findings = analyze_python(source, "webhook.py")
        self.assertNotIn("AF-PAY-001", {item.rule_id for item in findings})

class TerraformIngressTests(unittest.TestCase):
    def test_flags_public_ssh_ingress(self):
        source = '''
resource "aws_security_group" "web" {
  ingress {
    from_port = 22
    to_port = 22
    protocol = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
'''
        findings = analyze_text(source, "network.tf")
        self.assertIn("AF-TF-001", {item.rule_id for item in findings})

    def test_does_not_flag_restricted_ssh_ingress(self):
        source = '''
resource "aws_security_group" "web" {
  ingress {
    from_port = 22
    to_port = 22
    protocol = "tcp"
    cidr_blocks = ["10.20.0.0/16"]
  }
}
'''
        findings = analyze_text(source, "network.tf")
        self.assertNotIn("AF-TF-001", {item.rule_id for item in findings})

if __name__ == "__main__":
    unittest.main()
