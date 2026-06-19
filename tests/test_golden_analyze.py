"""
Golden characterization of PhishFinder /api/analyze (current behavior frozen).

Boundaries (Gemini HTTP / WHOIS / DNS / GCS) are mocked deterministically in
conftest. Each test asserts: HTTP 200, the x-ndjson content type, the exact
ordered sequence of event `type` values, and (via the `golden` fixture) a
byte-identical match against tests/golden/<name>.ndjson.
"""


def _assert_ndjson_200(resp):
    assert resp.status_code == 200
    assert resp.headers["Content-Type"].startswith("application/x-ndjson")


def test_analyze_url(post_analyze, boundaries, golden):
    resp, body, objects = post_analyze("http://verify-account-security.test/login")
    _assert_ndjson_200(resp)
    types = golden("analyze_url", body)
    assert types == ["domainAge", "mxRecords", "final"]
    final = objects[-1]["content"]
    # Progressive values flow through into the final payload.
    assert final["domainAge"] == "2024-11-02"
    assert final["mxRecords"] == "Yes"
    assert final["rawInput"] == "http://verify-account-security.test/login"
    assert set(final.keys()) == {
        "risk", "summary", "watchFor", "advice",
        "domainAge", "mxRecords", "generated", "rawInput",
    }


def test_analyze_email(post_analyze, boundaries, golden):
    resp, body, objects = post_analyze("billing@paypa1-support.test")
    _assert_ndjson_200(resp)
    types = golden("analyze_email", body)
    assert types == ["domainAge", "mxRecords", "final"]
    assert objects[0] == {"type": "domainAge", "content": "2024-11-02"}
    assert objects[1] == {"type": "mxRecords", "content": "Yes"}


def test_analyze_raw_email(post_analyze, boundaries, golden):
    raw = (
        "Received: from mail.evil-sender.test (unknown)\n"
        "Subject: Your package could not be delivered\n"
        "From: Delivery Team\n"
        "\n"
        "Click here to reschedule your delivery now.\n"
    )
    resp, body, objects = post_analyze(raw)
    _assert_ndjson_200(resp)
    types = golden("analyze_raw_email", body)
    assert types == ["domainAge", "mxRecords", "final"]
    # Raw-email path skips WHOIS/MX -> both stay N/A.
    assert objects[0] == {"type": "domainAge", "content": "N/A"}
    assert objects[1] == {"type": "mxRecords", "content": "N/A"}
    assert objects[-1]["content"]["domainAge"] == "N/A"
    assert objects[-1]["content"]["mxRecords"] == "N/A"


def test_analyze_allowlist_is_empty_stream(post_analyze, boundaries, golden):
    # cyberattribution.ai is in ALLOW_LIST -> generator returns before yielding.
    resp, body, objects = post_analyze("cyberattribution.ai")
    _assert_ndjson_200(resp)
    types = golden("analyze_allowlist", body)
    # FROZEN behavior: completely empty 200 application/x-ndjson stream.
    assert body == ""
    assert objects == []
    assert types == []


def test_analyze_error(post_analyze, boundaries, golden):
    boundaries.gemini_raises()
    resp, body, objects = post_analyze("http://broken-gemini.test")
    _assert_ndjson_200(resp)
    types = golden("analyze_error", body)
    # Progressive events are emitted before the Gemini call fails.
    assert types == ["domainAge", "mxRecords", "error"]
    assert objects[-1]["type"] == "error"
