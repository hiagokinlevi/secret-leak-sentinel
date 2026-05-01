from detectors.pattern_registry import (
    PATTERN_REGISTRY,
    is_allowlisted_assignment_value,
    should_evaluate_pattern_for_file,
)


def _dotenv_pattern():
    return next(p for p in PATTERN_REGISTRY if p.id == "dotenv_assignment_secret")


def test_dotenv_detector_scoped_to_env_and_config_like_files():
    p = _dotenv_pattern()
    assert should_evaluate_pattern_for_file(p, ".env")
    assert should_evaluate_pattern_for_file(p, ".env.local")
    assert should_evaluate_pattern_for_file(p, "deploy/config.ini")
    assert should_evaluate_pattern_for_file(p, "settings.conf")
    assert not should_evaluate_pattern_for_file(p, "src/main.py")


def test_dotenv_detector_flags_real_credential_like_assignments():
    p = _dotenv_pattern()
    text = """
API_KEY=sk_live_1234567890abcdef
DATABASE_URL=postgres://user:pass@host:5432/db
TOKEN=ghp_abcdefghijklmnopqrstuvwxyz123456
"""
    matches = list(p.regex.finditer(text))
    assert len(matches) == 3
    assert all(not is_allowlisted_assignment_value(p, m.group("value")) for m in matches)


def test_dotenv_detector_ignores_common_template_defaults():
    p = _dotenv_pattern()
    text = """
API_KEY=
DATABASE_URL=example
TOKEN=changeme
SECRET_KEY='your_value_here'
"""
    matches = list(p.regex.finditer(text))
    assert len(matches) == 4
    assert all(is_allowlisted_assignment_value(p, m.group("value")) for m in matches)
