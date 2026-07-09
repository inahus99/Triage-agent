import os
from unittest.mock import patch

import pytest

from triage_agent.cli import _load_dotenv, main


def test_main_returns_error_for_missing_file(tmp_path, capsys):
    missing = tmp_path / "does_not_exist.exe"
    exit_code = main([str(missing)])
    assert exit_code == 1
    assert "file not found" in capsys.readouterr().err


def test_main_returns_error_when_no_api_key(tmp_path, monkeypatch, capsys):
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"fake sample bytes")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    # ensure no .env in cwd leaks a real key during this test
    monkeypatch.chdir(tmp_path)

    exit_code = main([str(sample)])
    assert exit_code == 1
    assert "OPENAI_API_KEY not set" in capsys.readouterr().err


def test_main_runs_pipeline_with_mocked_judge(tmp_path, monkeypatch, capsys):
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"kernel32.dll harmless string")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-fake-for-test")

    from triage_agent.models import TriageVerdict

    fake_verdict = TriageVerdict(
        severity="benign", confidence=0.95, reasoning_summary="mocked", needs_human_review=False,
    )
    with patch("triage_agent.cli.render_verdict", return_value=fake_verdict):
        exit_code = main([str(sample), "--db", str(tmp_path / "test.db")])

    assert exit_code == 0
    out = capsys.readouterr().out
    assert "Severity:           benign" in out
    assert "Report saved to" in out


def test_no_db_flag_skips_report_message(tmp_path, monkeypatch, capsys):
    sample = tmp_path / "sample.exe"
    sample.write_bytes(b"kernel32.dll harmless string")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-fake-for-test")

    from triage_agent.models import TriageVerdict

    fake_verdict = TriageVerdict(
        severity="benign", confidence=0.95, reasoning_summary="mocked", needs_human_review=False,
    )
    with patch("triage_agent.cli.render_verdict", return_value=fake_verdict):
        exit_code = main([str(sample), "--no-db"])

    assert exit_code == 0
    assert "Report saved to" not in capsys.readouterr().out


def test_load_dotenv_does_not_override_existing_env(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".env").write_text("OPENAI_API_KEY=from_dotenv\n")
    monkeypatch.setenv("OPENAI_API_KEY", "from_real_env")

    _load_dotenv()

    assert os.environ["OPENAI_API_KEY"] == "from_real_env"


def test_load_dotenv_sets_value_when_not_already_present(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".env").write_text("SOME_TEST_VAR=hello\n")
    monkeypatch.delenv("SOME_TEST_VAR", raising=False)

    _load_dotenv()

    assert os.environ["SOME_TEST_VAR"] == "hello"
