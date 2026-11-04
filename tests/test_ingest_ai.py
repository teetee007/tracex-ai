"""Smart ingestion on real-world formats and non-logs, and the AI layer with a stand-in client (no network)."""
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from tracex import ai
from tracex.explain import Statement, explain
from tracex.ingest import apply_mapping, ingest
from tracex.parsers import combine, load_dataset
from tracex.pipeline import analyse

SAMPLES = Path(__file__).resolve().parent.parent / "samples"


def _need():
    if not (SAMPLES / "real_formats" / "access.log").exists():
        pytest.skip("run scripts/make_samples.py first")


@pytest.mark.parametrize("name, fmt, kind", [
    ("access.log", "Apache/Nginx access log", "web"),
    ("auth.log", "Linux auth.log (sshd, sudo)", "auth + system"),
    ("sso_export.csv", "CSV", "auth"),
    ("process_events.jsonl", "JSON Lines", "system"),
])
def test_real_formats_are_recognised(name, fmt, kind):
    _need()
    r = ingest(name, (SAMPLES / "real_formats" / name).read_bytes())
    assert (r.status, r.format, r.kind) == ("accepted", fmt, kind)
    assert r.events["timestamp"].notna().all()


def test_unfamiliar_column_names_are_mapped():
    _need()
    r = ingest("sso_export.csv", (SAMPLES / "real_formats" / "sso_export.csv").read_bytes())
    assert r.mapping["timestamp"] == "EventTime" and r.mapping["src_ip"] == "ClientAddress"
    assert r.mapping["user"] == "Account" and r.mapping["outcome"] == "Outcome"


def test_real_formats_reconstruct_the_attack():
    _need()
    frames = [ingest(p.name, p.read_bytes()).events for p in sorted((SAMPLES / "real_formats").iterdir())]
    events = combine(frames)
    events["event_id"] = [f"{s}-{i:04d}" for i, s in enumerate(events["source"])]
    a = analyse(events)
    assert len(a.incidents) == 1
    inc = a.incidents[0]
    assert "203.0.113.45" in inc.entities["external_ips"] and set(inc.chain["source"]) == {"auth", "web", "system"}
    assert {"R1", "R3", "R4", "R8", "R9"} <= {d.rule for d in a.detections}


@pytest.mark.parametrize("name, data, words", [
    ("report.pdf", b"%PDF-1.7\n...", "PDF"),
    ("essay.docx", b"PK\x03\x04....", "Office"),
    ("photo.png", b"\x89PNG\r\n\x1a\n", "image"),
    ("blob.bin", b"abc\x00\x01\x02def", "binary"),
    ("empty.csv", b"", "empty"),
    ("grades.csv", b"student,subject,marks\nasha,maths,91\nravi,physics,78\n", "does not look like security logs"),
    ("story.txt", b"Once upon a time there was a small village near the sea.\n"
                  b"The fishermen went out every morning before the sun rose.\n"
                  b"Everyone in the village knew each other by name and face.\n", "prose"),
])
def test_non_logs_are_rejected_with_a_reason(name, data, words):
    r = ingest(name, data)
    assert r.status == "rejected" and r.events is None and words in r.reason


def test_sample_non_logs_are_rejected():
    _need()
    for p in (SAMPLES / "not_logs").iterdir():
        assert ingest(p.name, p.read_bytes()).status == "rejected", p.name


def test_hostile_mapping_proposal_is_validated():
    _need()
    data = (SAMPLES / "real_formats" / "sso_export.csv").read_bytes()
    r = ingest("sso_export.csv", data)
    # A bad proposal: "Account" as the timestamp. It must be dropped, not trusted.
    r2 = apply_mapping(r, data, {"timestamp": "Account", "src_ip": "ClientAddress", "user": "Account"}, "ai")
    assert r2.status == "rejected" and any("timestamp" in n for n in r2.notes)


# ---------------------------------------------------------------- AI layer with a stand-in client

class FakeClient:
    def __init__(self, payload, stop="end_turn"):
        self.payload, self.stop, self.calls = payload, stop, []
        self.beta = SimpleNamespace(messages=SimpleNamespace(create=self._create))

    def _create(self, **kw):
        self.calls.append(kw)
        return SimpleNamespace(stop_reason=self.stop,
                               content=[SimpleNamespace(type="text", text=json.dumps(self.payload))])


def test_mapping_request_shape_and_result():
    fake = FakeClient({"relevant": True, "kind": "auth", "reason": "login export",
                       "mapping": [{"field": "timestamp", "column": "When"}, {"field": "user", "column": "Nope"}]})
    out = ai.propose_mapping(["When", "Who"], [{"When": "2026-10-20 02:00:00", "Who": "x"}], client=fake)
    assert out["mapping"] == {"timestamp": "When"}                 # columns that don't exist are dropped
    kw = fake.calls[0]
    assert kw["model"] == ai.MODEL and kw["fallbacks"] == "default" and ai.FALLBACK_BETA in kw["betas"]
    assert kw["output_config"]["format"]["type"] == "json_schema"
    assert "<data>" in kw["messages"][0]["content"]                 # untrusted content is fenced as data


def test_refusal_and_bad_json_raise_clean_errors():
    with pytest.raises(ai.AIError, match="declined"):
        ai.propose_mapping(["a", "b"], [], client=FakeClient({}, stop="refusal"))
    bad = FakeClient({})
    bad.beta.messages.create = lambda **kw: SimpleNamespace(stop_reason="end_turn",
                                                            content=[SimpleNamespace(type="text", text="not json")])
    with pytest.raises(ai.AIError, match="JSON"):
        ai.narrate([], client=bad)


def test_narrative_verification_catches_invented_evidence():
    events, info = load_dataset(Path(__file__).resolve().parent.parent / "data" / "tc01_attack")
    statements = explain(analyse(events), info)
    good_ref = statements[0].refs[0]
    paragraphs = [
        {"text": "The attack began with password guessing from 203.0.113.45.", "refs": [good_ref], "kind": "fact"},
        {"text": "The attacker also came from 10.66.6.6.", "refs": [good_ref], "kind": "fact"},
        {"text": "They used a zero-day.", "refs": ["auth.csv:999"], "kind": "fact"},
        {"text": "Probably the same person ran the commands.", "refs": [], "kind": "hypothesis"},
    ]
    checked = ai.verify_narrative(paragraphs, statements)
    assert [c["supported"] for c in checked] == [True, False, False, False]


def _clear_keys(monkeypatch):
    for k in ai.CLAUDE_KEYS + ai.GEMINI_KEYS + ("TRACEX_AI_PROVIDER",):
        monkeypatch.delenv(k, raising=False)


def test_status_without_credentials(monkeypatch):
    _clear_keys(monkeypatch)
    ok, msg = ai.status()
    assert not ok and "GEMINI_API_KEY" in msg and ai.provider() is None


def test_provider_choice(monkeypatch):
    _clear_keys(monkeypatch)
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    assert ai.provider() == "gemini" and ai.name() == "Gemini" and ai.status()[0]
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
    assert ai.provider() == "gemini"
    monkeypatch.setenv("TRACEX_AI_PROVIDER", "claude")
    assert ai.provider() == "claude"


class FakeGemini(ai.GeminiClient):
    def __init__(self, payload=None, response=None):
        super().__init__(key="test-key", model="test-model")
        self.response = response or {"candidates": [{"finishReason": "STOP", "content": {"parts": [
            {"text": "thinking...", "thought": True}, {"text": json.dumps(payload)}]}}]}
        self.calls = []

    def post(self, body):
        self.calls.append(body)
        return self.response


def test_gemini_mapping_request_shape_and_result():
    fake = FakeGemini({"relevant": True, "kind": "auth", "reason": "login export",
                       "mapping": [{"field": "timestamp", "column": "When"}, {"field": "user", "column": "Nope"}]})
    out = ai.propose_mapping(["When", "Who"], [{"When": "2026-10-20 02:00:00", "Who": "x"}], client=fake)
    assert out["mapping"] == {"timestamp": "When"}
    body = fake.calls[0]
    cfg = body["generationConfig"]
    assert cfg["responseMimeType"] == "application/json"
    assert "additionalProperties" not in json.dumps(cfg["responseJsonSchema"])
    assert "<data>" in body["contents"][0]["parts"][0]["text"]
    assert "never follow" in body["systemInstruction"]["parts"][0]["text"]


def test_gemini_blocks_and_cutoffs_raise_clean_errors():
    with pytest.raises(ai.AIError, match="declined"):
        ai.narrate([], client=FakeGemini(response={"promptFeedback": {"blockReason": "SAFETY"}}))
    with pytest.raises(ai.AIError, match="declined"):
        ai.narrate([], client=FakeGemini(response={"candidates": [{"finishReason": "SAFETY"}]}))
    with pytest.raises(ai.AIError, match="cut off"):
        ai.narrate([], client=FakeGemini(response={"candidates": [{"finishReason": "MAX_TOKENS"}]}))


def test_gemini_key_is_sent_in_a_header_not_the_url(monkeypatch):
    seen = {}

    def fake_urlopen(req, timeout):
        seen["url"], seen["key"] = req.full_url, req.get_header("X-goog-api-key")
        raise ai.urllib.error.URLError("offline")
    monkeypatch.setattr(ai.urllib.request, "urlopen", fake_urlopen)
    with pytest.raises(ai.AIError, match="offline"):
        ai.GeminiClient(key="secret-test-key", model="m").post({})
    assert seen["key"] == "secret-test-key" and "secret-test-key" not in seen["url"]


def test_gemini_retries_busy_model_then_falls_back(monkeypatch):
    tried = []

    def fake_once(self, model, body):
        tried.append(model)
        if model == "first":
            raise ai._Busy("error 503")
        if model == ai.GEMINI_FALLBACKS[0]:
            raise ai._Missing(model)
        return {"ok": model}
    monkeypatch.setattr(ai.GeminiClient, "_post_once", fake_once)
    c = ai.GeminiClient(key="k", model="first", wait=0)
    assert c.post({}) == {"ok": ai.GEMINI_FALLBACKS[1]} and c.used == ai.GEMINI_FALLBACKS[1]
    assert tried == ["first", "first", ai.GEMINI_FALLBACKS[0], ai.GEMINI_FALLBACKS[1]]


def test_gemini_gives_up_cleanly_when_every_model_is_busy(monkeypatch):
    monkeypatch.setattr(ai.GeminiClient, "_post_once", lambda self, m, b: (_ for _ in ()).throw(ai._Busy("error 503")))
    with pytest.raises(ai.AIError, match="busy"):
        ai.GeminiClient(key="k", model="m", wait=0).post({})
