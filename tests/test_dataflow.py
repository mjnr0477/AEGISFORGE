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
        finding=next(item for item in findings if item.rule_id=="AF-FLOW-001")
        self.assertIn("source line 3",finding.message)
        self.assertIn("eval()",finding.message)

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

    def test_tracks_async_iteration_source_with_provenance(self):
        source = '''
async def endpoint():
    async for item in request.values:
        eval(item)
'''
        findings = analyze_python_flows(source, "app.py")
        finding = next(item for item in findings if item.rule_id == "AF-FLOW-001")
        self.assertIn("source line 3", finding.message)

    def test_lambda_returning_input_is_not_itself_tainted(self):
        source = '''
def endpoint():
    callback = lambda: request.args.get("code")
    eval(callback)
'''
        findings = analyze_python_flows(source, "app.py")
        self.assertNotIn("AF-FLOW-001", {item.rule_id for item in findings})

    def test_sink_inside_lambda_is_still_analyzed(self):
        source = '''
def endpoint():
    callback = lambda: eval(request.args.get("code"))
'''
        findings = analyze_python_flows(source, "app.py")
        self.assertIn("AF-FLOW-001", {item.rule_id for item in findings})

    def test_reports_syntax_errors_to_caller(self):
        with self.assertRaises(SyntaxError):
            analyze_python_flows("def broken(:\n","broken.py")

    def test_tracks_subprocess_module_alias_into_shell_sink(self):
        source = '''
import subprocess as sp
def endpoint():
    command = request.args.get("command")
    sp.run(command, shell=True)
'''
        findings=analyze_python_flows(source,"app.py")
        self.assertIn("AF-FLOW-002",{item.rule_id for item in findings})

    def test_tracks_imported_os_system_alias(self):
        source = '''
from os import system as launch
def endpoint():
    command = request.args.get("command")
    launch(command)
'''
        findings=analyze_python_flows(source,"app.py")
        self.assertIn("AF-FLOW-002",{item.rule_id for item in findings})

    def test_tracks_flask_module_alias_and_os_module_alias(self):
        source = '''
import flask as f
import os as operating_system
def endpoint():
    command = f.request.args.get("command")
    operating_system.system(command)
'''
        findings=analyze_python_flows(source,"app.py")
        self.assertIn("AF-FLOW-002",{item.rule_id for item in findings})

    def test_tracks_imported_subprocess_function_alias(self):
        source = '''
from subprocess import run as launch_process
def endpoint():
    command = request.args.get("command")
    launch_process(command, shell=True)
'''
        findings=analyze_python_flows(source,"app.py")
        self.assertIn("AF-FLOW-002",{item.rule_id for item in findings})

    def test_function_local_import_alias_does_not_leak_to_sibling_scope(self):
        source = '''
def run(command):
    return command

def first():
    from os import system as run
    run("constant")

def second():
    command = request.args.get("command")
    run(command)
'''
        findings=analyze_python_flows(source,"app.py")
        self.assertNotIn("AF-FLOW-002",{item.rule_id for item in findings})

    def test_traces_untrusted_argument_into_helper_function_sink(self):
        source = '''
def execute_command(command):
    subprocess.run(command, shell=True)

def endpoint():
    command = request.args.get("command")
    execute_command(command)
'''
        findings=analyze_python_flows(source,"app.py")
        self.assertIn("AF-FLOW-002",{item.rule_id for item in findings})
        finding=next(item for item in findings if item.rule_id=="AF-FLOW-002")
        self.assertEqual(finding.line,3)
        self.assertIn("source line 6",finding.message)

    def test_traces_through_multiple_local_helper_functions(self):
        source = '''
def final_step(value):
    os.system(value)

def middle_step(value):
    final_step(value)

def endpoint():
    command = request.args.get("command")
    middle_step(command)
'''
        findings=analyze_python_flows(source,"app.py")
        self.assertIn("AF-FLOW-002",{item.rule_id for item in findings})
        finding=next(item for item in findings if item.rule_id=="AF-FLOW-002")
        self.assertIn("source line 9",finding.message)

    def test_traces_tainted_return_value_from_helper(self):
        source = '''
def get_user_code():
    return request.args.get("code")

def endpoint():
    eval(get_user_code())
'''
        findings=analyze_python_flows(source,"app.py")
        self.assertIn("AF-FLOW-001",{item.rule_id for item in findings})
        finding=next(item for item in findings if item.rule_id=="AF-FLOW-001")
        self.assertIn("source line 3",finding.message)

    def test_maps_keyword_arguments_to_helper_parameters(self):
        source = '''
def execute(value):
    os.system(value)

def endpoint():
    command = request.args.get("command")
    execute(value=command)
'''
        findings=analyze_python_flows(source,"app.py")
        self.assertIn("AF-FLOW-002",{item.rule_id for item in findings})

    def test_does_not_flag_constant_passed_to_tainted_sink_helper(self):
        source = '''
def execute(value):
    os.system(value)

def endpoint():
    execute("fixed-command")
'''
        findings=analyze_python_flows(source,"app.py")
        self.assertNotIn("AF-FLOW-002",{item.rule_id for item in findings})

    def test_ambiguous_duplicate_helper_names_are_not_summarized(self):
        source = '''
def execute(value):
    os.system(value)

def execute(value):
    return value

def endpoint():
    command = request.args.get("command")
    execute(command)
'''
        findings=analyze_python_flows(source,"app.py")
        self.assertNotIn("AF-FLOW-002",{item.rule_id for item in findings})

    def test_traces_parameter_through_helper_return_into_eval(self):
        source = '''
def identity(value):
    return value

def endpoint():
    command = request.args.get("code")
    eval(identity(command))
'''
        findings=analyze_python_flows(source,"app.py")
        self.assertIn("AF-FLOW-001",{item.rule_id for item in findings})
        finding=next(item for item in findings if item.rule_id=="AF-FLOW-001")
        self.assertIn("source line 6",finding.message)

    def test_traces_helper_argument_into_sql_query_text(self):
        source = '''
def run_query(cursor, query):
    cursor.execute(query)

def endpoint(cursor):
    name = request.args.get("name")
    query = "SELECT * FROM users WHERE name='" + name + "'"
    run_query(cursor, query)
'''
        findings=analyze_python_flows(source,"app.py")
        self.assertIn("AF-FLOW-003",{item.rule_id for item in findings})
        finding=next(item for item in findings if item.rule_id=="AF-FLOW-003")
        self.assertIn("source line 7",finding.message)

if __name__ == "__main__":
    unittest.main()
