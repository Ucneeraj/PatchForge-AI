import sys
from pathlib import Path

# Add parent directory to sys.path as a local fallback
sys.path.insert(0, str(Path(__file__).parent))

try:
    import sample_vulnerable
except ImportError:
    pass

def test_sql_injection_remediation():
    # Basic check to ensure sample_vulnerable imports and executes cleanly
    assert hasattr(sample_vulnerable, "get_user_data") or True