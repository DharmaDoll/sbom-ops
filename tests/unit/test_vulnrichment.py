import json
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from io import BytesIO
from pathlib import Path
from types import SimpleNamespace
from urllib.error import HTTPError, URLError
from urllib.request import Request

import pytest

from sbom_ops.clients.vulnrichment import (
    MAX_RESPONSE_BYTES,
    VulnrichmentClient,
    _NoRedirect,
)
from sbom_ops.domain.triage_evidence import (
    TriageEvidenceStatus,
    TriageFactor,
    TriageValue,
)
from sbom_ops.domain.vulnrichment import (
    VulnrichmentError,
    VulnrichmentReport,
    interpret_vulnrichment,
)
from sbom_ops.services.vulnrichment import fetch_vulnrichment

CVE = "CVE-2026-0001"
REVISION = "a" * 40
NOW = datetime(2026, 10, 22, tzinfo=UTC)
MAX_AGE = timedelta(days=7)
FIXTURE = Path(__file__).parents[1] / "fixtures/vulnrichment_synthetic.json"


def payload() -> dict:
    return json.loads(FIXTURE.read_text())


def content(record: dict) -> dict:
    return record["containers"]["adp"][0]["metrics"][0]["other"]["content"]


def interpret(record: dict, **kwargs: object) -> VulnrichmentReport:
    return interpret_vulnrichment(
        record,
        cve=CVE,
        revision=REVISION,
        retrieved_at=NOW,
        max_age=kwargs.get("max_age", MAX_AGE),
    )


def test_poc_is_not_known_exploitation_or_kev() -> None:
    report = interpret_vulnrichment(
        json.loads(FIXTURE.read_text()),
        cve=CVE,
        revision=REVISION,
        retrieved_at=NOW,
        max_age=MAX_AGE,
    )
    values = {item.factor: item.value for item in report.observations}
    assert values == {
        TriageFactor.AUTOMATABLE: TriageValue.YES,
        TriageFactor.TECHNICAL_IMPACT: TriageValue.TOTAL,
        TriageFactor.KNOWN_EXPLOITATION: TriageValue.UNKNOWN,
    }
    assert report.exploitation == "poc"
    assert report.assessed_at == datetime(2026, 10, 21, 12, tzinfo=UTC)
    assert report.retrieved_at == NOW


@pytest.mark.parametrize("exploitation", ["none", "poc", "active"])
def test_exploitation_is_separate_and_does_not_infer_negative(
    exploitation: str,
) -> None:
    record = payload()
    content(record)["options"][0]["Exploitation"] = exploitation
    result = interpret(record)
    assert result.exploitation == exploitation
    expected = TriageValue.YES if exploitation == "active" else TriageValue.UNKNOWN
    assert result.observations[2].value is expected
    assert all(item.factor is not TriageFactor.KEV for item in result.observations)


def test_age_comes_from_assessment_not_download_and_keeps_provenance() -> None:
    record = payload()
    before = deepcopy(record)
    result = interpret(record, max_age=timedelta(hours=12))
    assert record == before
    assert len(result.observations) == 3
    for item in result.observations:
        assert item.status_at(NOW) is TriageEvidenceStatus.EXPIRED
        assert item.source_revision == REVISION
        assert item.source == "https://github.com/cisagov/vulnrichment"
        assert item.source_record == f"{CVE}#/containers/adp/0/metrics/0/other/content"
        assert item.vulnerability.identifier == CVE
        assert item.vulnerability.namespace == "CVE"
        assert item.observed_at == result.assessed_at
    later = interpret_vulnrichment(
        record,
        cve=CVE,
        revision=REVISION,
        retrieved_at=NOW + timedelta(days=1),
        max_age=timedelta(hours=12),
    )
    assert later.observations == result.observations


def test_missing_options_never_fall_back_to_cvss_or_poc() -> None:
    record = payload()
    content(record)["options"] = [{"Exploitation": "poc"}]
    result = interpret(record)
    assert all(item.value is TriageValue.UNKNOWN for item in result.observations)
    assert "missing_Automatable" in result.reasons
    assert "missing_Technical Impact" in result.reasons


def test_absent_options_keep_all_factors_unknown() -> None:
    record = payload()
    del content(record)["options"]
    result = interpret(record)
    assert all(item.value is TriageValue.UNKNOWN for item in result.observations)
    assert result.reasons == (
        "missing_Automatable",
        "missing_Exploitation",
        "missing_Technical Impact",
    )


def test_other_publisher_and_cna_metrics_are_not_cisa_reports() -> None:
    record = payload()
    record["containers"]["adp"][0]["providerMetadata"]["orgId"] = "other-org"
    record["containers"]["cna"]["metrics"] = record["containers"]["adp"][0]["metrics"]
    result = interpret(record)
    assert not result.observations
    assert result.reasons == ("missing_cisa_ssvc",)
    assert result.assessed_at is None


def test_missing_adp_and_unrelated_metrics_are_not_negative() -> None:
    record = payload()
    del record["containers"]["adp"]
    assert not interpret(record).observations
    record = payload()
    record["containers"]["adp"][0]["metrics"] = [{"other": {"type": "kev"}}]
    assert not interpret(record).observations


@pytest.mark.parametrize(
    ("path", "value", "code"),
    [
        (("dataType",), "other", "unsupported_record_format"),
        (("dataVersion",), "5.2", "unsupported_record_format"),
        (("cveMetadata", "cveId"), "CVE-2026-0002", "cve_mismatch"),
        (("cveMetadata", "state"), "REJECTED", "record_not_published"),
        (("cveMetadata", "state"), "RESERVED", "record_not_published"),
        (("containers", "adp"), {}, "invalid_record_structure"),
        (("containers", "adp"), [None], "invalid_record_structure"),
    ],
)
def test_bad_record_is_rejected(
    path: tuple[str, ...], value: object, code: str
) -> None:
    record = payload()
    target = record
    for part in path[:-1]:
        target = target[part]
    target[path[-1]] = value
    with pytest.raises(VulnrichmentError, match=code):
        interpret(record)


@pytest.mark.parametrize(
    ("field", "value", "code"),
    [
        ("id", "CVE-2026-0002", "ssvc_cve_mismatch"),
        ("role", "other", "unsupported_ssvc"),
        ("version", "2.0.4", "unsupported_ssvc"),
        ("timestamp", "2026-10-21", "invalid_assessment_time"),
        ("timestamp", None, "invalid_assessment_time"),
        ("timestamp", "2026-10-23T00:00:00Z", "future_assessment"),
        ("options", [{"Automatable": True}], "unsupported_ssvc_option"),
        ("options", [{"Automatable": "unknown"}], "unsupported_ssvc_option"),
        ("options", [{"Decision": "Act"}], "unsupported_ssvc_option"),
        (
            "options",
            [{"Automatable": "yes", "Exploitation": "active"}],
            "invalid_ssvc_option",
        ),
        (
            "options",
            [{"Automatable": "yes"}, {"Automatable": "no"}],
            "duplicate_ssvc_option",
        ),
        ("options", [{}], "invalid_ssvc_option"),
        ("options", None, "invalid_record_structure"),
        ("options", [{}] * 1001, "invalid_record_structure"),
    ],
)
def test_bad_ssvc_is_rejected(field: str, value: object, code: str) -> None:
    record = payload()
    content(record)[field] = value
    with pytest.raises(VulnrichmentError, match=code):
        interpret(record)


@pytest.mark.parametrize("duplicate", ["container", "metric"])
def test_ambiguous_source_is_not_silently_selected(duplicate: str) -> None:
    record = payload()
    array = record["containers"]["adp"]
    if duplicate == "metric":
        array = array[0]["metrics"]
    array.append(deepcopy(array[0]))
    with pytest.raises(VulnrichmentError, match="ambiguous_"):
        interpret(record)


class Reply(BytesIO):
    status = 200


def test_client_to_domain_service_uses_exact_pinned_request() -> None:
    calls = []
    client = VulnrichmentClient()

    def opened(request: Request, timeout: int) -> Reply:
        calls.append((request, timeout))
        return Reply(FIXTURE.read_bytes())

    client._opener = SimpleNamespace(open=opened)
    result = fetch_vulnrichment(
        client,
        cve=CVE,
        revision=REVISION,
        max_age=MAX_AGE,
        clock=lambda: NOW,
    )
    assert result.exploitation == "poc"
    assert len(calls) == 1
    request, timeout = calls[0]
    assert request.full_url == (
        f"https://raw.githubusercontent.com/cisagov/vulnrichment/{REVISION}/"
        "2026/0xxx/CVE-2026-0001.json"
    )
    assert request.get_method() == "GET"
    assert timeout == 30
    assert request.data is None
    assert not request.has_header("Authorization")
    assert not request.has_header("X-Api-Key")
    assert (
        _NoRedirect().redirect_request(request, None, 302, "", {}, "https://elsewhere")
        is None
    )


@pytest.mark.parametrize(
    ("cve", "revision"),
    [
        ("../other", REVISION),
        ("cve-2026-0001", REVISION),
        ("CVE-2026-１２３４", REVISION),
        (CVE, "develop"),
        (CVE, "../main"),
        (CVE, "a" * 39),
        (None, REVISION),
    ],
)
def test_invalid_target_is_rejected_before_network(cve: str, revision: str) -> None:
    client = VulnrichmentClient()
    client._opener = SimpleNamespace(open=lambda *a, **k: pytest.fail("network"))
    with pytest.raises(VulnrichmentError):
        client.get_record(cve, revision)


@pytest.mark.parametrize(
    ("body", "error"),
    [
        (b'{"key":1,"key":2}', "invalid_json"),
        (b'{"v":NaN}', "invalid_json"),
        (b"not-json", "invalid_json"),
        (b"\xff", "invalid_json"),
        (b"[" * 2000, "invalid_json"),
        (b"x" * (MAX_RESPONSE_BYTES + 1), "response_too_large"),
    ],
)
def test_client_rejects_invalid_or_oversized_json(body: bytes, error: str) -> None:
    client = VulnrichmentClient()
    client._opener = SimpleNamespace(open=lambda *a, **k: Reply(body))
    with pytest.raises(VulnrichmentError, match=error):
        client.get_record(CVE, REVISION)


@pytest.mark.parametrize("status", [301, 302, 404, 429, 500])
def test_http_failure_does_not_become_negative_evidence(status: int) -> None:
    client = VulnrichmentClient()
    error = HTTPError(
        "https://example.invalid", status, "private detail", {}, BytesIO()
    )

    def fail(*args: object, **kwargs: object) -> None:
        raise error

    client._opener = SimpleNamespace(open=fail)
    with pytest.raises(VulnrichmentError) as caught:
        client.get_record(CVE, REVISION)
    assert caught.value.code == "http_error"
    assert caught.value.status == status
    assert "private detail" not in str(caught.value)
    assert error.closed


def test_transport_failure_is_sanitized() -> None:
    client = VulnrichmentClient()

    def fail(*args: object, **kwargs: object) -> None:
        raise URLError("private detail")

    client._opener = SimpleNamespace(open=fail)
    with pytest.raises(VulnrichmentError, match="^transport_error$"):
        client.get_record(CVE, REVISION)


@pytest.mark.parametrize("max_age", [timedelta(0), timedelta(days=-1), "7"])
def test_invalid_age_rejected_before_fetch(max_age: object) -> None:
    client = SimpleNamespace(get_record=lambda *a: pytest.fail("network"))
    with pytest.raises(VulnrichmentError, match="invalid_max_age"):
        fetch_vulnrichment(
            client, cve=CVE, revision=REVISION, max_age=max_age, clock=lambda: NOW
        )


def test_explicit_no_and_partial_are_preserved() -> None:
    record = payload()
    content(record)["options"] = [
        {"Automatable": "no"},
        {"Technical Impact": "partial"},
    ]
    result = interpret(record)
    assert [item.value for item in result.observations] == [
        TriageValue.NO,
        TriageValue.PARTIAL,
        TriageValue.UNKNOWN,
    ]
    assert result.exploitation is None
    assert result.reasons == ("missing_Exploitation",)


def test_invalid_retrieval_time_and_age_overflow_are_rejected() -> None:
    with pytest.raises(VulnrichmentError, match="invalid_retrieval_time"):
        interpret_vulnrichment(
            payload(),
            cve=CVE,
            revision=REVISION,
            retrieved_at=NOW.replace(tzinfo=None),
            max_age=MAX_AGE,
        )
    with pytest.raises(VulnrichmentError, match="invalid_max_age"):
        interpret(payload(), max_age=timedelta.max)
