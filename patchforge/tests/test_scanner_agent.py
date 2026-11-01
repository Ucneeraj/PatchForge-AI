"""
Tests for ScannerAgent: verifies both true positives (vulnerable patterns
get flagged) and true negatives (safe equivalents do NOT get flagged),
since a scanner that only proves it can flag things isn't proving much.
"""

from patchforge.agents.scanner_agent import ScannerAgent


def test_detects_fstring_sql_injection():
    source = '''
def run_query(user):
    cursor.execute(f"SELECT * FROM users WHERE name = '{user}'")
'''
    findings = ScannerAgent().run("db.py", source)
    cwe_ids = [f.cwe_id for f in findings]
    assert "CWE-89" in cwe_ids


def test_detects_percent_formatted_sql_injection():
    source = '''
def run_query(user):
    cursor.execute("SELECT * FROM users WHERE name = '%s'" % user)
'''
    findings = ScannerAgent().run("db.py", source)
    assert any(f.cwe_id == "CWE-89" for f in findings)


def test_does_not_flag_parameterized_query():
    """A properly parameterized query must NOT be flagged -- false positives
    here would make the scanner unusable."""
    source = '''
def run_query(user):
    cursor.execute("SELECT * FROM users WHERE name = %s", (user,))
'''
    findings = ScannerAgent().run("db.py", source)
    assert not any(f.cwe_id == "CWE-89" for f in findings)


def test_detects_hardcoded_password():
    source = 'password = "hunter2"\n'
    findings = ScannerAgent().run("config.py", source)
    assert any(f.cwe_id == "CWE-798" for f in findings)


def test_does_not_flag_env_based_secret():
    source = 'password = os.environ["APP_PASSWORD"]\n'
    findings = ScannerAgent().run("config.py", source)
    assert not any(f.cwe_id == "CWE-798" for f in findings)


def test_finding_has_correct_localization():
    source = 'password = "hunter2"\n'
    findings = ScannerAgent().run("config.py", source)
    assert findings[0].file_path == "config.py"
    assert findings[0].line_start == 1
    assert findings[0].line_end == 1


def test_clean_file_produces_no_findings():
    source = "x = 1\ny = 2\nprint(x + y)\n"
    findings = ScannerAgent().run("clean.py", source)
    assert findings == []
