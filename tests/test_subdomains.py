import asyncio

import dns.exception
import dns.resolver
import pytest
from pydantic import ValidationError

from atalaya.core.finding import EvaluationStatus, ScanResult
from atalaya.modules.subdomains import SubdomainsInput, SubdomainsModule


@pytest.mark.parametrize(
    "domain", ["127.0.0.1", "https://example.org", "*.example.org", "a..org", "local"]
)
def test_domain_validation(domain):
    with pytest.raises(ValidationError):
        SubdomainsInput(domain=domain)


def test_idna():
    assert SubdomainsInput(domain="ESPAÑA.example.").domain == "xn--espaa-rta.example"


def run_mock(monkeypatch, tmp_path, mapping, controls=(set(), True)):
    seen = []

    async def resolve(self, resolver, host, timeout):
        seen.append(host)
        return controls if host.startswith("atalaya-") else mapping[host]

    monkeypatch.setattr(SubdomainsModule, "_resolve", resolve)
    wordlist = tmp_path / "dns.txt"
    wordlist.write_text("api\nmissing\n# comment\napi\n", encoding="utf-8")
    result = SubdomainsModule().scan(SubdomainsInput(domain="example.org", wordlist=wordlist))
    return result, seen


def test_positive_and_nxdomain(monkeypatch, tmp_path):
    result, seen = run_mock(
        monkeypatch,
        tmp_path,
        {
            "api.example.org": ({"192.0.2.1", "2001:db8::1"}, True),
            "missing.example.org": (set(), True),
        },
    )
    assert result.status is EvaluationStatus.COMPLETE
    assert len(seen) == 4
    assert all(host.endswith(".example.org") for host in seen)
    assert result.findings[0].location == "api.example.org"


def test_wildcard_is_not_confirmed_subdomain(monkeypatch, tmp_path):
    result, _ = run_mock(
        monkeypatch,
        tmp_path,
        {
            "api.example.org": ({"192.0.2.1"}, True),
            "missing.example.org": ({"192.0.2.2"}, True),
        },
        controls=({"192.0.2.1"}, True),
    )
    assert result.status is EvaluationStatus.INCOMPLETE
    assert all("Candidato" in f.title for f in result.findings if f.rule_id == "dns.subdomain")


def test_failed_control_does_not_confirm_names(monkeypatch, tmp_path):
    result, _ = run_mock(
        monkeypatch,
        tmp_path,
        {
            "api.example.org": ({"192.0.2.1"}, True),
            "missing.example.org": (set(), False),
        },
        controls=(set(), False),
    )
    assert result.grade is None
    assert result.coverage()["undetermined"] == 3


def test_dns_exceptions_are_not_conflated():
    class Resolver:
        def __init__(self, error):
            self.error = error

        async def resolve(self, *args, **kwargs):
            raise self.error

    module = SubdomainsModule()
    assert asyncio.run(module._resolve(Resolver(dns.resolver.NXDOMAIN()), "x.example", 1)) == (
        set(),
        True,
    )
    assert asyncio.run(module._resolve(Resolver(dns.exception.Timeout()), "x.example", 1)) == (
        set(),
        False,
    )


def test_deadline_is_reported(monkeypatch):
    async def resolve(*args):
        await asyncio.sleep(10)

    monkeypatch.setattr(SubdomainsModule, "_resolve", resolve)
    output = asyncio.run(
        SubdomainsModule()._scan(SubdomainsInput(domain="example.org", total_timeout=0.01), ["api"])
    )
    result = ScanResult(
        module_id="subdomains", module_name="DNS", target="example.org", **output.model_dump()
    )
    assert result.status is EvaluationStatus.NOT_EVALUATED


def test_wordlist_cannot_escape_domain(tmp_path):
    path = tmp_path / "dns.txt"
    path.write_text("../outside.example", encoding="utf-8")
    result = SubdomainsModule().scan(SubdomainsInput(domain="example.org", wordlist=path))
    assert result.error
