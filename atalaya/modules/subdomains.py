"""Descubrimiento DNS acotado, con controles de wildcard y cobertura por nombre."""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import re
from pathlib import Path
from uuid import uuid4

import dns.asyncresolver
import dns.exception
import dns.resolver
from pydantic import BaseModel, ConfigDict, Field, field_validator

from ..core.finding import Finding, ScanOutput, Severity
from ..core.module import Category, Coverage, ScanModule

DEFAULT_NAMES = (
    "www,api,app,admin,mail,smtp,webmail,vpn,dev,staging,"
    "test,portal,cdn,static,docs,status,git,shop,blog,auth"
)


def domain_name(value: str) -> str:
    value = value.strip().rstrip(".").encode("idna").decode("ascii").lower()
    try:
        ipaddress.ip_address(value)
    except ValueError:
        pass
    else:
        raise ValueError("Se necesita un dominio, no una dirección IP.")
    if (
        len(value) > 253
        or "." not in value
        or any(
            not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", p) for p in value.split(".")
        )
    ):
        raise ValueError("Dominio DNS no válido.")
    return value


class SubdomainsInput(BaseModel):
    model_config = ConfigDict(allow_inf_nan=False)
    domain: str = Field(description="Dominio bajo el que buscar nombres DNS.")
    wordlist: Path | None = Field(
        default=None, description="Archivo de prefijos DNS, uno por línea."
    )
    timeout: float = Field(default=3, gt=0, le=15, description="Segundos por consulta DNS.")
    concurrency: int = Field(
        default=4, ge=1, le=16, description="Nombres consultados simultáneamente."
    )
    total_timeout: float = Field(
        default=45, gt=0, le=300, description="Presupuesto total en segundos."
    )

    @field_validator("domain")
    @classmethod
    def valid_domain(cls, value):
        return domain_name(value)


class SubdomainsModule(ScanModule):
    id = "subdomains"
    name = "Descubridor de subdominios"
    description = "Resuelve candidatos DNS A/AAAA y separa las respuestas de wildcard."
    category = Category.RECON
    InputModel = SubdomainsInput
    show_info = True

    def run(self, inputs: SubdomainsInput) -> ScanOutput:
        names = DEFAULT_NAMES.split(",")
        if inputs.wordlist:
            with inputs.wordlist.open("rb") as source:
                raw = source.read(65537)
            if len(raw) > 65536:
                raise ValueError("Diccionario DNS demasiado grande (máximo 64 KiB).")
            names = [
                s.strip().lower()
                for s in raw.decode("utf-8-sig").splitlines()
                if s.strip() and not s.lstrip().startswith("#")
            ]
        names = list(dict.fromkeys(names))
        if not 1 <= len(names) <= 256:
            raise ValueError("El diccionario debe tener entre 1 y 256 prefijos únicos.")
        for name in names:
            if domain_name(f"{name}.{inputs.domain}") != f"{name}.{inputs.domain}":
                raise ValueError("Prefijo DNS no válido.")
        return asyncio.run(self._scan(inputs, names))

    async def _resolve(self, resolver, host: str, timeout: float) -> tuple[set[str], bool]:
        addresses = set()
        complete = True
        for record in ("A", "AAAA"):
            try:
                answer = await resolver.resolve(host + ".", record, lifetime=timeout, search=False)
                addresses.update(str(r) for r in answer)
            except dns.resolver.NXDOMAIN:
                return set(), True
            except dns.resolver.NoAnswer:
                pass
            except (dns.exception.DNSException, OSError):
                complete = False
        return addresses, complete

    async def _scan(self, inputs: SubdomainsInput, names: list[str]) -> ScanOutput:
        resolver = dns.asyncresolver.Resolver()
        controls: list[tuple[set[str], bool]] = []
        results: dict[str, tuple[set[str], bool]] = {}

        async def execute():
            for _ in range(2):
                controls.append(
                    await self._resolve(
                        resolver, f"atalaya-{uuid4().hex}.{inputs.domain}", inputs.timeout
                    )
                )
            pending = iter(names)

            async def worker():
                for name in pending:
                    results[name] = await self._resolve(
                        resolver, f"{name}.{inputs.domain}", inputs.timeout
                    )

            await asyncio.gather(*(worker() for _ in range(min(inputs.concurrency, len(names)))))

        with contextlib.suppress(asyncio.TimeoutError):
            await asyncio.wait_for(execute(), inputs.total_timeout)
        cov = Coverage()
        controls_ok = len(controls) == 2 and all(c[1] for c in controls)
        wildcard = set.union(*(c[0] for c in controls)) if controls else set()
        if controls_ok:
            cov.done("dns-wildcard", "Control de wildcard DNS")
        else:
            cov.undetermined("dns-wildcard", "Control de wildcard DNS", "Consultas no concluyentes")
        findings = []
        if wildcard:
            findings.append(
                Finding(
                    severity=Severity.INFO,
                    rule_id="dns.wildcard",
                    location=inputs.domain,
                    title="El dominio resuelve nombres aleatorios (wildcard DNS)",
                    description="Los nombres que comparten sus direcciones quedan como candidatos.",
                    evidence=", ".join(sorted(wildcard)),
                )
            )
        for name in names:
            host = f"{name}.{inputs.domain}"
            ips, complete = results.get(name, (set(), False))
            ambiguous = bool(ips and (not controls_ok or wildcard))
            if complete and not ambiguous:
                cov.done(host, host, "Resuelto" if ips else "Sin registros A/AAAA")
            else:
                cov.undetermined(host, host, "Wildcard o consulta incompleta")
            if ips:
                findings.append(
                    Finding(
                        severity=Severity.INFO,
                        rule_id="dns.subdomain",
                        location=host,
                        attributes={"addresses": ",".join(sorted(ips)), "wildcard": str(ambiguous)},
                        title=f"{'Candidato DNS' if ambiguous else 'Subdominio resuelto'}: {host}",
                        description="Resolución DNS observada; "
                        "no confirma propiedad ni vulnerabilidad.",
                        evidence=", ".join(sorted(ips)),
                    )
                )
        return cov.output(findings, {"Candidatos": str(len(names)), "Consultas": "A y AAAA"})
