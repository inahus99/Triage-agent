from unittest.mock import Mock, patch

from triage_agent.tools.virustotal import lookup_hash, parse_vt_response


def test_parse_vt_response_extracts_detection_stats():
    payload = {
        "data": {
            "attributes": {
                "last_analysis_stats": {"malicious": 42, "suspicious": 3, "harmless": 10, "undetected": 5},
                "reputation": -87,
            }
        }
    }
    facts = parse_vt_response(payload)
    values = {f.key: f.value for f in facts}
    assert values["vt_known"] == "true"
    assert values["vt_malicious"] == "42"
    assert values["vt_reputation"] == "-87"
    assert all(f.tool == "virustotal" for f in facts)


def test_parse_vt_response_handles_missing_attributes():
    facts = parse_vt_response({"data": {"attributes": {}}})
    assert any(f.key == "vt_known" and f.value == "true" for f in facts)


@patch("triage_agent.tools.virustotal.requests.get")
def test_lookup_hash_returns_known_false_on_404(mock_get, monkeypatch):
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "test-key")
    mock_get.return_value = Mock(status_code=404)

    facts = lookup_hash("deadbeef" * 8)

    assert any(f.key == "vt_known" and f.value == "false" for f in facts)


@patch("triage_agent.tools.virustotal.requests.get")
def test_lookup_hash_parses_a_hit(mock_get, monkeypatch):
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "test-key")
    mock_get.return_value = Mock(
        status_code=200,
        json=lambda: {"data": {"attributes": {"last_analysis_stats": {"malicious": 7}}}},
        raise_for_status=Mock(),
    )

    facts = lookup_hash("deadbeef" * 8)

    values = {f.key: f.value for f in facts}
    assert values["vt_known"] == "true"
    assert values["vt_malicious"] == "7"
    assert mock_get.call_args.kwargs["headers"]["x-apikey"] == "test-key"
