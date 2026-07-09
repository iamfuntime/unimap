from __future__ import annotations

import xml.etree.ElementTree as ET

from ..models import Finding, Service
from .base import HostContext, Phase, Plugin, register


def parse_nmap_xml(xml_text: str) -> tuple[list[Service], list[Finding]]:
    services: list[Service] = []
    findings: list[Finding] = []
    root = ET.fromstring(xml_text)
    for host in root.findall("host"):
        for port in host.findall("./ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            portid = int(port.get("portid", "0"))
            proto = port.get("protocol", "tcp")
            svc = port.find("service")
            name = svc.get("name", "") if svc is not None else ""
            product = svc.get("product", "") if svc is not None else ""
            version = svc.get("version", "") if svc is not None else ""
            tunnel = svc.get("tunnel", "") if svc is not None else ""
            services.append(
                Service(port=portid, proto=proto, name=name, product=product, version=version, tunnel=tunnel)
            )
            for script in port.findall("script"):
                findings.append(
                    Finding(
                        source_tool="nmap",
                        severity="info",
                        title=f"{portid}/{proto} {script.get('id')}",
                        detail=(script.get("output") or "").strip(),
                    )
                )
    return services, findings


@register
class NmapServiceScan(Plugin):
    name = "nmap-service"
    phase = Phase.SERVICE_ID
    requires = ["nmap"]

    def matches(self, ctx: HostContext) -> bool:
        return bool(ctx.open_ports)

    async def run(self, ctx: HostContext, runner) -> list[Finding]:
        ports = ",".join(str(p) for p in sorted(ctx.open_ports))
        xml_path = ctx.outdir / "artifacts" / "nmap-service.xml"
        # Clear any stale XML so a failed/timed-out run can't be read as fresh.
        xml_path.unlink(missing_ok=True)
        argv = ["nmap", "-sV", "-sC", "-Pn", "-p", ports, "-oX", str(xml_path), ctx.target.host]
        result = await runner.run("nmap-service", argv, timeout=ctx.config.tool_timeout)
        try:
            xml_text = xml_path.read_text(encoding="utf-8", errors="replace")
        except FileNotFoundError:
            xml_text = result.stdout
        try:
            services, script_findings = parse_nmap_xml(xml_text)
        except ET.ParseError:
            return [
                Finding(
                    source_tool="nmap",
                    severity="error",
                    title="nmap XML parse failed",
                    detail=result.stderr[:500],
                    evidence_path=result.artifact_path,
                )
            ]
        ctx.services.extend(services)
        findings: list[Finding] = []
        for s in services:
            findings.append(
                Finding(
                    source_tool="nmap",
                    severity="info",
                    title=f"{s.port}/{s.proto} {s.name}".strip(),
                    detail=" ".join(x for x in (s.product, s.version) if x),
                    evidence_path=result.artifact_path,
                )
            )
        for f in script_findings:
            f.evidence_path = result.artifact_path
            findings.append(f)
        return findings
