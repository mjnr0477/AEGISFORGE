import tempfile
import unittest
from pathlib import Path

from aegisforge.dataflow import analyze_python_flows
from aegisforge.scanner import scan_directory

class PythonDataFlowTests(unittest.TestCase):
    def test_tracks_request_parameter_through_assignment_into_eval(self):
        source = '''
def endpoint():
    user_value = request.args.get("code")
    copied = user_value
    eval(copied)
'''
        findings=analyze_python_flows(source,"app.py")
        self.assertIn("AF-FLOW-001",{item.rule_id for item in findings})

    def test_tracks_asgi_query_params_into_exec(self):
        source = '''
def endpoint(request):
    payload = request.query_params.get("code")
    exec(payload)
'''
        findings=analyze_python_flows(source,"app.py")
        self.assertIn("AF-FLOW-001",{item.rule_id for item in findings})

    def test_tracks_django_post_data_into_shell_command(self):
        source = '''
def endpoint(request):
    command = request.POST.get("command")
    os.system(command)
'''
        findings=analyze_python_flows(source,"views.py")
        self.assertIn("AF-FLOW-002",{item.rule_id for item in findings})

    def test_tracks_aliased_flask_request_into_shell_command(self):
        source = '''
from flask import request as req
def endpoint():
    command = req.form["command"]
    subprocess.run(command, shell=True)
'''
        findings=analyze_python_flows(source,"app.py")
        self.assertIn("AF-FLOW-002",{item.rule_id for item in findings})

    def test_tracks_tainted_query_expression_into_execute(self):
        source = '''
def endpoint(cursor):
    name = request.args["name"]
    query = "SELECT * FROM users WHERE name='" + name + "'"
    cursor.execute(query)
'''
        findings=analyze_python_flows(source,"app.py")
        self.assertIn("AF-FLOW-003",{item.rule_id for item in findings})

    def test_does_not_flag_parameterized_sql_values(self):
        source = '''
def endpoint(cursor):
    name = request.args.get("name")
    cursor.execute("SELECT * FROM users WHERE name=?", (name,))
'''
        findings=analyze_python_flows(source,"app.py")
        self.assertNotIn("AF-FLOW-003",{item.rule_id for item in findings})

    def test_does_not_flag_untrusted_input_that_never_reaches_sink(self):
        source = '''
def endpoint():
    name = request.args.get("name")
    print(name)
'''
        findings=analyze_python_flows(source,"app.py")
        self.assertEqual(findings,[])

    def test_does_not_flag_constant_eval_as_tainted_flow(self):
        source = "eval('1 + 1')\n"
        findings=analyze_python_flows(source,"app.py")
        self.assertEqual(findings,[])

    def test_directory_scan_includes_dataflow_findings(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            (root/"app.py").write_text(
                "def endpoint():\n"
                "    user = request.args.get('code')\n"
                "    eval(user)\n",
                encoding="utf-8",
            )
            result=scan_directory(root)
        self.assertIn("AF-FLOW-001",{item.rule_id for item in result.findings})

    def test_does_not_flag_tainted_non_command_keyword_arguments(self):
        source = '''
def endpoint(cursor):
    subprocess.run("fixed-command", shell=True, cwd=request.args.get("directory"))
    eval("1 + 1", request.args.get("unused_globals"))
    cursor.execute("SELECT * FROM users", {"name": request.args.get("name")})
'''
        findings=analyze_python_flows(source,"app.py")
        self.assertEqual(findings,[])

    def test_tracks_keyword_command_argument(self):
        source = '''
def endpoint():
    command = request.args.get("command")
    subprocess.run(args=command, shell=True)
'''
        findings=analyze_python_flows(source,"app.py")
        self.assertIn("AF-FLOW-002",{item.rule_id for item in findings})

    def test_tracks_input_function_into_exec(self):
        source = """code = input()
exec(code)
"""
        findings=analyze_python_flows(source,"app.py")
        self.assertIn("AF-FLOW-001",{item.rule_id for item in findings})

    def test_class_body_taint_does_not_leak_into_module_scope(self):
        source = '''
class Handler:
    value = request.args.get("value")
eval("constant expression")
'''
        findings=analyze_python_flows(source,"app.py")
        self.assertEqual(findings,[])

    def test_reports_syntax_errors_to_caller(self):
        with self.assertRaises(SyntaxError):
            analyze_python_flows("def broken(:\n","broken.py")

if __name__ == "__main__":
    unittest.main()
