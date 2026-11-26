import unittest
from aegisforge.analyzers import analyze_python, analyze_text

class UnsafeYamlTests(unittest.TestCase):
    def test_flags_yaml_load_without_safe_loader(self):
        source = "yaml.load(payload)\n"
        findings = analyze_python(source, "config.py")
        self.assertIn("AF-PY-007", {item.rule_id for item in findings})

    def test_flags_yaml_unsafe_load(self):
        source = "yaml.unsafe_load(payload)\n"
        findings = analyze_python(source, "config.py")
        self.assertIn("AF-PY-007", {item.rule_id for item in findings})

    def test_does_not_flag_yaml_safe_load(self):
        source = "yaml.safe_load(payload)\n"
        findings = analyze_python(source, "config.py")
        self.assertNotIn("AF-PY-007", {item.rule_id for item in findings})

    def test_does_not_flag_yaml_load_with_safe_loader(self):
        source = "yaml.load(payload, Loader=yaml.SafeLoader)\n"
        findings = analyze_python(source, "config.py")
        self.assertNotIn("AF-PY-007", {item.rule_id for item in findings})

class ContainerPrivilegeTests(unittest.TestCase):
    def test_flags_privilege_escalation_setting(self):
        source = "allowPrivilegeEscalation: true\n"
        findings = analyze_text(source, "deployment.yaml")
        self.assertIn("AF-CON-003", {item.rule_id for item in findings})

    def test_does_not_flag_disabled_privilege_escalation(self):
        source = "allowPrivilegeEscalation: false\n"
        findings = analyze_text(source, "deployment.yaml")
        self.assertNotIn("AF-CON-003", {item.rule_id for item in findings})

    def test_ignores_commented_privilege_escalation(self):
        source = "# allowPrivilegeEscalation: true\n"
        findings = analyze_text(source, "deployment.yaml")
        self.assertNotIn("AF-CON-003", {item.rule_id for item in findings})

if __name__ == "__main__":
    unittest.main()
