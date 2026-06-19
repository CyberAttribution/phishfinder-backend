"""
Phase 0 characterization harness for PhishFinder.

Goal: freeze the CURRENT behavior of /api/analyze as byte-identical golden
NDJSON, with every external boundary (Gemini HTTP, WHOIS, DNS, GCS) replaced by
deterministic fixtures. This file does NOT modify runtime behavior — it only
imports the live `app` and patches boundaries at their point of use.

Modes:
  * CAPTURE=1  -> write the produced stream to tests/golden/<name>.ndjson
  * (default)  -> assert the produced stream is byte-identical to the golden
"""
import json
import os
import pathlib

import pytest

# --- Deterministic environment BEFORE importing the live app ---------------
# A key must be present or the live code raises ValueError before the Gemini
# call; the value is never used because requests.post is mocked.
os.environ.setdefault("GEMINI_API_KEY", "test-key-not-used")
# Ensure GCS stays disabled at import time (no credentials file, no bucket).
os.environ.pop("GCS_BUCKET_NAME", None)

import app  # noqa: E402  (import after env is set, by design)
from verity_core import technical_intel as vc_technical_intel  # noqa: E402  (step 2 point of use)
from verity_core import model_router as vc_model_router  # noqa: E402  (final step point of use)

TESTS_DIR = pathlib.Path(__file__).parent
GOLDEN_DIR = TESTS_DIR / "golden"
FIXTURES_DIR = TESTS_DIR / "fixtures"
CAPTURE = os.environ.get("CAPTURE") == "1"


# --- Fixture loading -------------------------------------------------------
def _load_fixture(name):
    with open(FIXTURES_DIR / name) as fh:
        return json.load(fh)


class _FakeResponse:
    """Minimal stand-in for requests.Response as used by app.py."""

    def __init__(self, payload, status_code=200):
        self._payload = payload
        self.status_code = status_code
        self.ok = 200 <= status_code < 300

    def raise_for_status(self):
        if not self.ok:
            raise app.requests.exceptions.HTTPError(f"status {self.status_code}")

    def json(self):
        return self._payload


class _FakeWhois:
    """Stand-in for the object returned by whois.whois(...)."""

    def __init__(self, creation_date):
        self.creation_date = creation_date


@pytest.fixture
def app_module():
    return app


@pytest.fixture
def client():
    app.app.config.update(TESTING=True)
    return app.app.test_client()


@pytest.fixture
def boundaries(monkeypatch):
    """
    Install deterministic boundary mocks. Returns a small controller so each
    test can tune the Gemini behavior (success payload vs. raised error) while
    keeping WHOIS/DNS/GCS fixed and offline.
    """
    from datetime import datetime

    whois_sample = _load_fixture("whois_sample.json")
    creation_dt = datetime.strptime(whois_sample["creation_date"], "%Y-%m-%d")

    # WHOIS + DNS now live in verity_core.technical_intel (Phase 2 step 2);
    # patch the underlying boundaries at their new point of use so the moved
    # get_domain_creation_date / has_mx_records logic actually runs and the
    # golden output (domainAge "2024-11-02", mxRecords "Yes") stays identical.
    monkeypatch.setattr(
        vc_technical_intel.whois, "whois", lambda target: _FakeWhois(creation_dt)
    )
    monkeypatch.setattr(
        vc_technical_intel.dns.resolver, "resolve",
        lambda target, rtype: ["10 mail.example.test."],
    )
    # GCS -> hard no-op (also naturally disabled, but make it explicit/offline).
    monkeypatch.setattr(app, "save_to_gcs", lambda *a, **k: None)

    state = {"raise": False, "payload": _load_fixture("gemini_analyze_result.json")}

    def fake_post(url, headers=None, json=None, timeout=None):
        if state["raise"]:
            raise vc_model_router.requests.exceptions.RequestException("simulated Gemini failure")
        return _FakeResponse(state["payload"])

    # Gemini transport now lives in verity_core.model_router (final step); patch
    # requests.post at its point of use so the 503/retry/parse path is exercised
    # there and the golden output stays byte-identical.
    monkeypatch.setattr(vc_model_router.requests, "post", fake_post)

    class _Controller:
        def gemini_raises(self):
            state["raise"] = True

    return _Controller()


@pytest.fixture
def post_analyze(client):
    """POST to /api/analyze and drain the NDJSON stream deterministically."""

    def _do(prompt, model="flash"):
        resp = client.post("/api/analyze", json={"prompt": prompt, "model": model})
        body = resp.get_data(as_text=True)
        objects = [json.loads(line) for line in body.splitlines() if line.strip()]
        return resp, body, objects

    return _do


@pytest.fixture
def golden():
    """
    CAPTURE=1 -> write tests/golden/<name>.ndjson from the produced body.
    default   -> assert the produced body is byte-identical to the golden file.
    Returns the parsed ordered list of event `type` values for convenience.
    """

    def _check(name, body):
        path = GOLDEN_DIR / f"{name}.ndjson"
        if CAPTURE:
            GOLDEN_DIR.mkdir(parents=True, exist_ok=True)
            path.write_text(body)
        else:
            assert path.exists(), f"missing golden {path}; run with CAPTURE=1 first"
            expected = path.read_text()
            assert body == expected, (
                f"golden mismatch for {name}:\n--- expected ---\n{expected!r}\n"
                f"--- actual ---\n{body!r}"
            )
        return [json.loads(l)["type"] for l in body.splitlines() if l.strip()]

    return _check
