"""Tests for GuardAI security scanners."""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.scanners.injection import InjectionScanner
from src.scanners.secrets import SecretsScanner
from src.scanners.auth import AuthScanner
from src.scanners.xss import XSSScanner
from src.scanners.dependency import DependencyScanner
from src.engine import GuardAIEngine


def test_sql_injection_fstring():
    scanner = InjectionScanner()
    code = '''cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")'''
    findings = scanner.scan_file("app.py", code)
    assert len(findings) >= 1
    assert findings[0].rule_id == "SQL001"
    assert findings[0].severity.value == "critical"


def test_sql_injection_concat():
    scanner = InjectionScanner()
    code = '''db.query("SELECT * FROM users WHERE id=" + request.args.get("id"))'''
    findings = scanner.scan_file("app.js", code)
    assert len(findings) >= 1
    assert findings[0].rule_id == "SQL002"


def test_command_injection_os_system():
    scanner = InjectionScanner()
    code = '''os.system("rm -rf " + user_input)'''
    findings = scanner.scan_file("app.py", code)
    assert len(findings) >= 1
    assert findings[0].rule_id == "CMD001"


def test_eval_injection():
    scanner = InjectionScanner()
    code = '''eval("calculate(" + request.body + ")")'''
    findings = scanner.scan_file("app.js", code)
    assert len(findings) >= 1
    assert findings[0].rule_id == "CMD004"


def test_hardcoded_api_key():
    scanner = SecretsScanner()
    code = '''api_key = "test_fake_key_abc123def456ghi789jkl012"'''
    findings = scanner.scan_file("config.py", code)
    assert len(findings) >= 1


def test_hardcoded_password():
    scanner = SecretsScanner()
    code = '''password = "supersecretpassword123"'''
    findings = scanner.scan_file("config.py", code)
    assert len(findings) >= 1
    assert findings[0].rule_id == "SEC002"


def test_aws_key():
    scanner = SecretsScanner()
    code = '''AWS_KEY = "AKIAIOSFODNN7EXAMPLE"'''
    findings = scanner.scan_file("config.py", code)
    assert len(findings) >= 1
    assert findings[0].rule_id == "SEC004"


def test_github_token():
    scanner = SecretsScanner()
    code = '''token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn"'''
    findings = scanner.scan_file("config.py", code)
    assert len(findings) >= 1
    assert any(f.rule_id == "SEC005" for f in findings)


def test_private_key():
    scanner = SecretsScanner()
    code = '''key = "-----BEGIN RSA PRIVATE KEY-----"'''
    findings = scanner.scan_file("config.py", code)
    assert len(findings) >= 1
    assert findings[0].rule_id == "SEC007"


def test_jwt_none_algorithm():
    scanner = AuthScanner()
    code = '''decoded = jwt.decode(token, algorithms=['none'])'''
    findings = scanner.scan_file("auth.py", code)
    assert len(findings) >= 1
    assert findings[0].rule_id == "AUTH002"


def test_cors_wildcard():
    scanner = AuthScanner()
    code = '''CORS(app, origin="*")'''
    findings = scanner.scan_file("app.py", code)
    assert len(findings) >= 1
    assert findings[0].rule_id == "AUTH003"


def test_md5_hash():
    scanner = AuthScanner()
    code = '''hashed = hashlib.md5(password.encode())'''
    findings = scanner.scan_file("auth.py", code)
    assert len(findings) >= 1
    assert findings[0].rule_id == "AUTH004"


def test_xss_innerhtml():
    scanner = XSSScanner()
    code = '''element.innerHTML = userInput'''
    findings = scanner.scan_file("app.js", code)
    assert len(findings) >= 1
    assert findings[0].rule_id == "XSS001"


def test_xss_dangerously_set():
    scanner = XSSScanner()
    code = '''return <div dangerouslySetInnerHTML={{ __html: content }} />'''
    findings = scanner.scan_file("App.tsx", code)
    assert len(findings) >= 1
    assert any(f.rule_id == "XSS002" for f in findings)


def test_pickle_load():
    scanner = DependencyScanner()
    code = '''data = pickle.load(open("data.pkl", "rb"))'''
    findings = scanner.scan_file("app.py", code)
    assert len(findings) >= 1
    assert findings[0].rule_id == "DEP003"


def test_ssl_verify_false():
    scanner = DependencyScanner()
    code = '''response = requests.get(url, verify=False)'''
    findings = scanner.scan_file("client.py", code)
    assert len(findings) >= 1
    assert findings[0].rule_id == "DEP001"


def test_clean_code_no_findings():
    engine = GuardAIEngine()
    code = '''
import os

def get_user(user_id):
    db = get_database()
    return db.execute("SELECT * FROM users WHERE id = %s", (user_id,))

def main():
    api_key = os.environ["API_KEY"]
    print(f"Starting app with key length: {len(api_key)}")
'''
    # Write to temp and scan
    import tempfile, shutil
    tmp = tempfile.mkdtemp()
    try:
        with open(os.path.join(tmp, "clean.py"), "w") as f:
            f.write(code)
        result = engine.scan(tmp)
        assert result.score >= 90
    finally:
        shutil.rmtree(tmp)


def test_engine_score():
    engine = GuardAIEngine()
    import tempfile, shutil
    tmp = tempfile.mkdtemp()
    try:
        with open(os.path.join(tmp, "bad.py"), "w") as f:
            f.write('''
password = "hardcoded123"
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
os.system("rm " + user_input)
''')
        result = engine.scan(tmp)
        assert result.score < 50
        assert result.critical_count >= 2
    finally:
        shutil.rmtree(tmp)


if __name__ == "__main__":
    tests = [v for k, v in globals().items() if k.startswith("test_")]
    passed = 0
    failed = 0
    for test in tests:
        try:
            test()
            print(f"  PASS: {test.__name__}")
            passed += 1
        except Exception as e:
            print(f"  FAIL: {test.__name__} — {e}")
            failed += 1
    print(f"\n  {passed} passed, {failed} failed out of {len(tests)} tests")
    sys.exit(1 if failed else 0)
