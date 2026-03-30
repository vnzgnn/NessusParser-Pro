#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NessusParser Pro v3.1
Advanced Nessus vulnerability report generator with dual-layer reporting
and threat intelligence enrichment (EPSS + CISA KEV).

Layer 1 — Executive: KPI dashboard, risk matrices, charts, executive narrative.
Layer 2 — Operational: Priority queue, remediation plan, quick wins.

Supports multiple .nessus files as input (files, directories, glob patterns).

Usage:
    python nessusparser_pro.py -i scan1.nessus scan2.nessus -o report
    python nessusparser_pro.py -i ./scans/ -o report
    python nessusparser_pro.py -i "./scans/*.nessus" -o report
    python nessusparser_pro.py -i ./scans/ -o report --enrich
    python nessusparser_pro.py -i ./scans/ -o report --enrich --exclude-ids 12345,67890
"""

import argparse, glob, json, logging, math, os, re, sys, time
import urllib.request, urllib.error
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import lxml.etree as ET
import xlsxwriter

__version__ = "3.1.0"

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s", datefmt="%H:%M:%S")
log = logging.getLogger("nessusparser")

SEVERITY_MAP = {0: "Informational", 1: "Low", 2: "Medium", 3: "High", 4: "Critical"}
SEVERITY_COLORS = {"Critical": "#B8504B", "High": "#E9A23A", "Medium": "#F7F552", "Low": "#58BF65", "Informational": "#618ECD"}
SEVERITY_TAB_COLORS = {"Critical": "red", "High": "orange", "Medium": "yellow", "Low": "green", "Informational": "blue"}


# ─── Threat Intelligence ─────────────────────────────────────────────────────

class ThreatIntel:
    """Fetches and caches EPSS scores and CISA KEV catalog for CVE enrichment."""

    EPSS_API = "https://api.first.org/data/v1/epss"
    KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    def __init__(self):
        self.epss_scores: Dict[str, float] = {}
        self.epss_percentiles: Dict[str, float] = {}
        self.kev_set: Set[str] = set()
        self.kev_details: Dict[str, Dict] = {}
        self._epss_loaded = self._kev_loaded = False

    def enrich(self, cve_list: List[str]) -> None:
        unique = sorted(set(c for c in cve_list if c.startswith("CVE-")))
        if not unique:
            return
        log.info("Enriching %d unique CVEs with threat intelligence...", len(unique))
        self._fetch_kev()
        self._fetch_epss(unique)
        log.info("  EPSS: %d/%d scored", len([c for c in unique if c in self.epss_scores]), len(unique))
        log.info("  CISA KEV: %d/%d matched", len([c for c in unique if c in self.kev_set]), len(unique))

    def _fetch_epss(self, cves: List[str]) -> None:
        for i in range(0, len(cves), 100):
            batch = cves[i:i + 100]
            try:
                req = urllib.request.Request(
                    f"{self.EPSS_API}?cve={','.join(batch)}",
                    headers={"Accept": "application/json"},
                )
                with urllib.request.urlopen(req, timeout=15) as resp:
                    data = json.loads(resp.read().decode())
                for item in data.get("data", []):
                    self.epss_scores[item["cve"]] = float(item.get("epss", 0))
                    self.epss_percentiles[item["cve"]] = float(item.get("percentile", 0))
                self._epss_loaded = True
            except Exception as e:
                log.warning("EPSS unavailable: %s — continuing without", e)
                break
            if i + 100 < len(cves):
                time.sleep(0.3)

    def _fetch_kev(self) -> None:
        try:
            req = urllib.request.Request(self.KEV_URL, headers={"Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=20) as resp:
                data = json.loads(resp.read().decode())
            for v in data.get("vulnerabilities", []):
                cid = v.get("cveID", "")
                self.kev_set.add(cid)
                self.kev_details[cid] = {
                    "vendor": v.get("vendorProject", ""),
                    "product": v.get("product", ""),
                    "name": v.get("vulnerabilityName", ""),
                    "action": v.get("requiredAction", ""),
                    "due_date": v.get("dueDate", ""),
                }
            self._kev_loaded = True
            log.info("  KEV catalog loaded: %d entries", len(self.kev_set))
        except Exception as e:
            log.warning("KEV unavailable: %s — continuing without", e)

    def max_epss(self, cves: List[str]) -> float:
        return max((self.epss_scores.get(c, 0) for c in cves), default=0)

    def any_kev(self, cves: List[str]) -> bool:
        return any(c in self.kev_set for c in cves)

    @property
    def is_available(self) -> bool:
        return self._epss_loaded or self._kev_loaded


# ─── Data Structures ─────────────────────────────────────────────────────────

@dataclass
class VulnRecord:
    """Single vulnerability finding from a Nessus scan."""

    host_ip: str = ""
    host_fqdn: str = ""
    netbios_name: str = ""
    port: int = 0
    severity: int = 0
    risk_factor: str = ""
    plugin_id: str = ""
    plugin_name: str = ""
    plugin_family: str = ""
    description: str = ""
    synopsis: str = ""
    solution: str = ""
    plugin_output: str = ""
    exploit_available: str = ""
    exploitability_ease: str = ""
    exploited_by_malware: str = ""
    vuln_publication_date: str = ""
    plugin_publication_date: str = ""
    plugin_modification_date: str = ""
    cve_list: List[str] = field(default_factory=list)
    bid_list: List[str] = field(default_factory=list)
    cvss_base_score: float = 0.0
    cvss_temporal_score: float = 0.0
    source_file: str = ""
    # Enrichment fields
    epss_score: Optional[float] = None
    epss_percentile: Optional[float] = None
    in_cisa_kev: bool = False

    @property
    def severity_name(self) -> str:
        return SEVERITY_MAP.get(self.severity, "Unknown")

    @property
    def vuln_age_days(self) -> int:
        if not self.vuln_publication_date:
            return 0
        try:
            return (datetime.now() - datetime.strptime(self.vuln_publication_date, "%Y/%m/%d")).days
        except (ValueError, TypeError):
            return 0

    @property
    def priority_score(self) -> float:
        """Weighted priority: CVSS × exploit × age × EPSS × KEV."""
        s = self.cvss_base_score
        if not s:
            return 0.0
        if self.exploit_available.lower() == "true":
            s *= 1.5
        if self.exploited_by_malware.lower() == "true":
            s *= 1.3
        s *= 1.0 + self.vuln_age_days / 365.0
        if self.epss_score and self.epss_score > 0:
            s *= 1.0 + self.epss_score * 2.0
        if self.in_cisa_kev:
            s *= 2.0
        return round(s, 2)

    @property
    def cve_str(self) -> str:
        return ";\n".join(self.cve_list)

    @property
    def bid_str(self) -> str:
        return ";\n".join(self.bid_list)


@dataclass
class DeviceRecord:
    host_ip: str = ""
    host_fqdn: str = ""
    netbios_name: str = ""
    device_type: str = ""
    confidence_level: int = 0
    source_file: str = ""


@dataclass
class ProcessRecord:
    host_ip: str = ""
    host_fqdn: str = ""
    netbios_name: str = ""
    process_line: str = ""
    source_file: str = ""


@dataclass
class HostCVSS:
    host_ip: str = ""
    source_file: str = ""
    scores: Dict[int, Dict[str, float]] = field(default_factory=dict)


# ─── Nessus XML Parser ───────────────────────────────────────────────────────

class NessusParser:
    """Parses .nessus files and aggregates vulnerability data."""

    def __init__(self, ignored_ids: Optional[Set[str]] = None):
        self.ignored_ids: Set[str] = ignored_ids or set()
        self.vulns: List[VulnRecord] = []
        self.devices: List[DeviceRecord] = []
        self.processes: List[ProcessRecord] = []
        self.host_cvss: List[HostCVSS] = []
        self.unique_ips: Set[str] = set()
        self.total_ips_seen: int = 0
        self.plugin_counts: Dict[str, Tuple[str, int]] = {}
        self.files_parsed: List[str] = []

    @staticmethod
    def _ct(elem, tag: str) -> str:
        c = elem.find(tag)
        return c.text if c is not None and c.text else ""

    @staticmethod
    def _at(elem, attr: str) -> str:
        return elem.get(attr, "")

    @staticmethod
    def resolve_inputs(inputs: List[str]) -> List[str]:
        """Resolve files, directories, and glob patterns to .nessus paths."""
        files: List[str] = []
        for inp in inputs:
            p = Path(inp)
            if p.is_file() and p.suffix in (".nessus", ".xml"):
                files.append(str(p.resolve()))
            elif p.is_dir():
                for f in sorted(p.iterdir()):
                    if f.suffix in (".nessus", ".xml"):
                        files.append(str(f.resolve()))
            else:
                for m in sorted(glob.glob(inp, recursive=True)):
                    mp = Path(m)
                    if mp.is_file() and mp.suffix in (".nessus", ".xml"):
                        files.append(str(mp.resolve()))
        seen: Set[str] = set()
        unique: List[str] = []
        for f in files:
            if f not in seen:
                seen.add(f)
                unique.append(f)
        return unique

    def parse_files(self, file_list: List[str]) -> None:
        for i, fp in enumerate(file_list, 1):
            log.info("Parsing %d/%d: %s", i, len(file_list), os.path.basename(fp))
            try:
                self._parse_single(fp)
                self.files_parsed.append(fp)
            except ET.XMLSyntaxError as e:
                log.error("XML error in %s: %s", fp, e)
            except Exception as e:
                log.error("Failed %s: %s", fp, e)
            log.info("Progress: %.1f%%", i / len(file_list) * 100)

    def _parse_single(self, fpath: str) -> None:
        ctx = ET.iterparse(fpath, events=("start", "end"))
        ctx = iter(ctx)
        _, root = next(ctx)
        if root.tag != "NessusClientData_v2":
            log.warning("Skip %s: not Nessus v2", fpath)
            return
        fname = os.path.basename(fpath)
        start_tag = None
        for event, elem in ctx:
            if event == "start" and elem.tag == "ReportHost" and start_tag is None:
                start_tag = elem.tag
                continue
            if event == "end" and elem.tag == start_tag:
                self._process_host(elem, fname)
                elem.clear()
                for a in elem.xpath("ancestor-or-self::*"):
                    while a.getprevious() is not None:
                        del a.getparent()[0]
                start_tag = None
        del ctx

    def _process_host(self, he, fname: str) -> None:
        ip = fq = nb = ""
        hn = self._at(he, "name")
        props = he.find("HostProperties")
        if props is not None:
            for t in props:
                n = t.get("name", "")
                if n == "host-ip" and t.text:
                    ip = t.text
                elif n == "host-fqdn" and t.text:
                    fq = t.text
                elif n == "netbios-name" and t.text:
                    nb = t.text
        if not ip:
            ip = hn
        self.total_ips_seen += 1
        self.unique_ips.add(ip)

        cvss_agg: Dict[int, Dict[str, float]] = {
            i: {"cvss_base_score": 0.0, "cvss_temporal_score": 0.0} for i in range(5)
        }

        for item in he.iter("ReportItem"):
            pid = self._at(item, "pluginID")
            if pid in self.ignored_ids:
                continue
            pname = self._at(item, "pluginName")
            sev = int(self._at(item, "severity") or "0")

            # Plugin counts
            if pname not in self.plugin_counts:
                self.plugin_counts[pname] = (pid, 0)
            _pid, cnt = self.plugin_counts[pname]
            self.plugin_counts[pname] = (_pid, cnt + 1)

            # CVSS
            bs = self._ct(item, "cvss_base_score")
            ts = self._ct(item, "cvss_temporal_score")
            bsf = round(float(bs), 2) if bs else 0.0
            tsf = round(float(ts), 2) if ts else 0.0
            if bs:
                cvss_agg[sev]["cvss_base_score"] += bsf
            if ts:
                cvss_agg[sev]["cvss_temporal_score"] += tsf

            cves = [c.text for c in item.iter("cve") if c.text]
            bids = [b.text for b in item.iter("bid") if b.text]

            vuln = VulnRecord(
                host_ip=ip, host_fqdn=fq, netbios_name=nb,
                port=int(self._at(item, "port") or "0"), severity=sev,
                risk_factor=self._ct(item, "risk_factor"),
                plugin_id=pid, plugin_name=pname,
                plugin_family=self._at(item, "pluginFamily"),
                description=self._ct(item, "description"),
                synopsis=self._ct(item, "synopsis"),
                solution=self._ct(item, "solution"),
                plugin_output=self._ct(item, "plugin_output"),
                exploit_available=self._ct(item, "exploit_available"),
                exploitability_ease=self._ct(item, "exploitability_ease"),
                exploited_by_malware=self._ct(item, "exploited_by_malware"),
                vuln_publication_date=self._ct(item, "vuln_publication_date"),
                plugin_publication_date=self._ct(item, "plugin_publication_date"),
                plugin_modification_date=self._ct(item, "plugin_modification_date"),
                cve_list=cves, bid_list=bids,
                cvss_base_score=bsf, cvss_temporal_score=tsf,
                source_file=fname,
            )
            self.vulns.append(vuln)

            # Device info (plugin 54615)
            if pid == "54615":
                out = self._ct(item, "plugin_output").replace("\n", " ")
                dtype = conf = ""
                m = re.search(r"(?<=type : )(.*)(?=Confidence )", out)
                if m:
                    dtype = m.group(1).strip()
                m2 = re.search(r"Confidence level : (\d+)", out)
                conf = int(m2.group(1)) if m2 else 0
                self.devices.append(DeviceRecord(ip, fq, nb, dtype, conf, fname))

            # MS Process info (plugin 70329)
            if pid == "70329":
                po = self._ct(item, "plugin_output")
                po = po.replace("Process Overview : \n", "").replace("SID: Process (PID)", "")
                po = re.sub(r"Process_Information.*", "", po).replace("\n\n\n", "")
                for ln in po.split("\n"):
                    ln = ln.strip()
                    if ln:
                        self.processes.append(ProcessRecord(ip, fq, nb, ln, fname))

        self.host_cvss.append(HostCVSS(ip, fname, cvss_agg))

    # ── Enrichment ──

    def enrich(self, ti: ThreatIntel) -> None:
        """Apply EPSS and KEV data to all VulnRecords."""
        all_cves = [c for v in self.vulns for c in v.cve_list]
        ti.enrich(all_cves)
        enriched = 0
        for v in self.vulns:
            if not v.cve_list:
                continue
            me = ti.max_epss(v.cve_list)
            if me > 0:
                v.epss_score = me
                v.epss_percentile = max(
                    (ti.epss_percentiles.get(c, 0) for c in v.cve_list), default=0
                )
                enriched += 1
            if ti.any_kev(v.cve_list):
                v.in_cisa_kev = True
                enriched += 1
        log.info("Enrichment applied to %d records", enriched)

    # ── Analytics ──

    def severity_totals(self) -> Dict[str, int]:
        t = {n: 0 for n in SEVERITY_MAP.values()}
        for v in self.vulns:
            t[v.severity_name] += 1
        return t

    def unique_sev_counts(self) -> Dict[str, int]:
        u: Dict[str, Set[str]] = {n: set() for n in SEVERITY_MAP.values()}
        for v in self.vulns:
            u[v.severity_name].add(v.plugin_name)
        return {k: len(s) for k, s in u.items()}

    def top_vulns(self, sev_name: str, n: int = 10) -> List[Tuple[str, int]]:
        c: Dict[str, int] = defaultdict(int)
        for v in self.vulns:
            if v.severity_name == sev_name:
                c[v.plugin_name] += 1
        return sorted(c.items(), key=lambda x: x[1], reverse=True)[:n]

    def host_sev_matrix(self) -> Dict[str, Dict[str, int]]:
        m: Dict[str, Dict[str, int]] = defaultdict(lambda: {n: 0 for n in SEVERITY_MAP.values()})
        for v in self.vulns:
            m[v.host_ip][v.severity_name] += 1
        return dict(m)

    def host_risk_scores(self) -> Dict[str, float]:
        s: Dict[str, float] = defaultdict(float)
        for v in self.vulns:
            if v.severity >= 1:
                s[v.host_ip] += v.priority_score
        return dict(s)

    def remediation_groups(self) -> Dict[str, List[VulnRecord]]:
        g: Dict[str, List[VulnRecord]] = defaultdict(list)
        for v in self.vulns:
            if v.severity >= 2 and v.solution and v.solution.lower() != "n/a":
                g[v.solution].append(v)
        return dict(g)

    def quick_wins(self, min_hosts: int = 3) -> List[Tuple]:
        pd: Dict[str, Dict] = {}
        for v in self.vulns:
            if v.severity < 2 or not v.solution or v.solution.lower() == "n/a":
                continue
            if v.plugin_name not in pd:
                pd[v.plugin_name] = {
                    "sol": v.solution, "hosts": set(),
                    "cvss": 0.0, "pid": v.plugin_id,
                }
            d = pd[v.plugin_name]
            d["hosts"].add(v.host_ip)
            d["cvss"] = max(d["cvss"], v.cvss_base_score)
        results = []
        for pn, d in pd.items():
            if len(d["hosts"]) >= min_hosts:
                impact = d["cvss"] * len(d["hosts"])
                results.append((pn, d["sol"], len(d["hosts"]), d["cvss"], impact, d["pid"]))
        return sorted(results, key=lambda x: x[4], reverse=True)

    def exploitable_vulns(self) -> List[VulnRecord]:
        return sorted(
            [v for v in self.vulns if v.exploit_available.lower() == "true"],
            key=lambda v: v.priority_score, reverse=True,
        )


# ─── Excel Report Generator ──────────────────────────────────────────────────

class ExcelReportGenerator:
    """Generates Excel report with executive + operational layers."""

    def __init__(self, parser: NessusParser, output_path: str,
                 threat_intel: Optional[ThreatIntel] = None):
        self.p = parser
        self.output_path = output_path
        self.ti = threat_intel
        self.wb: Optional[xlsxwriter.Workbook] = None
        self.f: Dict[str, Any] = {}

    def generate(self) -> str:
        fp = self.output_path
        if not fp.endswith(".xlsx"):
            fp += ".xlsx"
        if os.path.exists(fp):
            fp = f"{fp.rsplit('.xlsx', 1)[0]}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
            log.warning("File exists — saving as %s", fp)

        self.wb = xlsxwriter.Workbook(fp, {"strings_to_urls": False})
        self._create_formats()
        try:
            log.info("Generating Executive layer...")
            self._exec_summary()
            self._exec_charts()
            self._risk_matrix()
            if self.ti and self.ti.is_available:
                log.info("Generating Threat Intelligence...")
                self._threat_intel()
            log.info("Generating Operational layer...")
            self._priority_queue()
            self._remediation_plan()
            self._quick_wins_sheet()
            log.info("Generating Reference sheets...")
            self._full_report()
            for si, sn in SEVERITY_MAP.items():
                self._severity_sheet(sn, si)
            self._cvss_overview()
            self._device_types()
            self._ms_processes()
            self._plugin_counts()
        finally:
            self.wb.close()
        log.info("Report saved: %s", fp)
        return fp

    def _create_formats(self) -> None:
        wb = self.wb
        self.f = {
            "hdr": wb.add_format({"bg_color": "#1D365A", "font_color": "white", "bold": 1, "italic": 1, "border": 1, "text_wrap": 1, "valign": "vcenter"}),
            "title": wb.add_format({"bg_color": "#1D365A", "font_color": "white", "font_size": 20, "bold": 1, "border": 1, "align": "center", "valign": "vcenter"}),
            "sub": wb.add_format({"bg_color": "#1D365A", "font_color": "white", "font_size": 12, "bold": 1, "border": 1}),
            "lbl": wb.add_format({"bg_color": "#9AB3D4", "font_color": "black", "font_size": 12, "border": 1}),
            "w": wb.add_format({"border": 1, "text_wrap": 1, "valign": "top"}),
            "n": wb.add_format({"border": 1, "num_format": "0", "valign": "top"}),
            "d": wb.add_format({"border": 1, "num_format": "0.00", "valign": "top"}),
            "pct": wb.add_format({"border": 1, "num_format": "0.0%", "valign": "top"}),
            "epct": wb.add_format({"border": 1, "num_format": "0.00%", "valign": "top"}),
            "sc": wb.add_format({"bg_color": "#B8504B", "font_color": "white", "bold": 1, "border": 1, "align": "center"}),
            "sh": wb.add_format({"bg_color": "#E9A23A", "font_color": "white", "bold": 1, "border": 1, "align": "center"}),
            "sm": wb.add_format({"bg_color": "#F7F552", "font_color": "#333", "bold": 1, "border": 1, "align": "center"}),
            "sl": wb.add_format({"bg_color": "#58BF65", "font_color": "white", "bold": 1, "border": 1, "align": "center"}),
            "si": wb.add_format({"bg_color": "#618ECD", "font_color": "white", "bold": 1, "border": 1, "align": "center"}),
            "kv": wb.add_format({"font_size": 28, "bold": 1, "align": "center", "valign": "vcenter", "border": 1, "num_format": "0"}),
            "kl": wb.add_format({"font_size": 11, "align": "center", "valign": "top", "border": 1, "text_wrap": 1, "bg_color": "#F2F2F2"}),
            "kr": wb.add_format({"font_size": 28, "bold": 1, "align": "center", "valign": "vcenter", "border": 1, "num_format": "0", "font_color": "#B8504B"}),
            "ko": wb.add_format({"font_size": 28, "bold": 1, "align": "center", "valign": "vcenter", "border": 1, "num_format": "0", "font_color": "#E9A23A"}),
            "sec": wb.add_format({"bg_color": "#2E4057", "font_color": "white", "font_size": 13, "bold": 1, "border": 1}),
            "rh": wb.add_format({"bg_color": "#FADBD8", "border": 1, "num_format": "0.0", "align": "center"}),
            "rm": wb.add_format({"bg_color": "#FEF9E7", "border": 1, "num_format": "0.0", "align": "center"}),
            "rl": wb.add_format({"bg_color": "#D5F5E3", "border": 1, "num_format": "0.0", "align": "center"}),
            "bw": wb.add_format({"border": 1, "text_wrap": 1, "bold": 1, "valign": "top"}),
            "dn": wb.add_format({"bg_color": "#E74C3C", "font_color": "white", "bold": 1, "border": 1, "align": "center"}),
            "nar": wb.add_format({"text_wrap": 1, "font_size": 11, "valign": "top", "border": 0}),
        }

    def _sf(self, sn: str):
        return {"Critical": self.f["sc"], "High": self.f["sh"], "Medium": self.f["sm"],
                "Low": self.f["sl"], "Informational": self.f["si"]}.get(sn, self.f["w"])

    # ══════════════════════════════════════════════════════════════════════════
    # EXECUTIVE LAYER
    # ══════════════════════════════════════════════════════════════════════════

    def _exec_summary(self) -> None:
        ws = self.wb.add_worksheet("Executive Summary")
        ws.hide_gridlines(2)
        ws.set_tab_color("#1D365A")
        f = self.f

        tot = self.p.severity_totals()
        uniq = self.p.unique_sev_counts()
        expl = self.p.exploitable_vulns()
        kev_n = len([v for v in self.p.vulns if v.in_cisa_kev])

        for c in range(8):
            ws.set_column(c, c, 18)

        # Title
        ws.merge_range("A1:H2", "Vulnerability Assessment — Executive Summary", f["title"])
        enote = "  |  Enriched: EPSS + CISA KEV" if self.ti and self.ti.is_available else ""
        ws.merge_range("A3:H3",
                        f"Generated: {datetime.now():%Y-%m-%d %H:%M}  |  "
                        f"Files: {len(self.p.files_parsed)}  |  "
                        f"Hosts: {len(self.p.unique_ips)}{enote}", f["sub"])

        # KPIs
        r = 4
        ws.merge_range(r, 0, r, 7, "Key Performance Indicators", f["sec"])
        r += 1
        kpis = [
            (len(self.p.unique_ips), "Unique hosts", f["kv"]),
            (tot["Critical"], "Critical", f["kr"]),
            (tot["High"], "High", f["ko"]),
            (tot["Critical"] + tot["High"], "Crit + High", f["kr"]),
            (len(expl), "With Exploit", f["kr"]),
            (kev_n, "In CISA KEV", f["kr"] if kev_n else f["kv"]),
            (tot["Medium"], "Medium", f["kv"]),
            (sum(tot.values()), "Total findings", f["kv"]),
        ]
        ws.set_row(r, 50)
        for c, (val, lab, fmt) in enumerate(kpis):
            ws.write(r, c, val, fmt)
            ws.write(r + 1, c, lab, f["kl"])
        r += 3

        # Executive narrative
        ws.merge_range(r, 0, r, 7, "Executive Narrative", f["sec"])
        r += 1
        ta = sum(tot.values())
        tc = tot["Critical"] + tot["High"]
        hc = len({v.host_ip for v in self.p.vulns if v.severity == 4})
        he = len({v.host_ip for v in expl if v.severity >= 3})
        pc = round(hc / max(len(self.p.unique_ips), 1) * 100, 1)

        lines = [
            f"This assessment scanned {len(self.p.unique_ips)} unique hosts across "
            f"{len(self.p.files_parsed)} file(s), identifying {ta:,} total findings.",
            "",
            f"{tot['Critical']:,} Critical and {tot['High']:,} High severity findings "
            f"represent {round(tc / max(ta, 1) * 100, 1)}% of the total.",
            "",
            f"{pc}% of hosts ({hc}/{len(self.p.unique_ips)}) have at least one "
            f"Critical vulnerability.",
            "",
            f"{len(expl)} findings have publicly available exploits; "
            f"{he} impact Critical/High hosts.",
        ]
        if kev_n:
            kev_hosts = len({v.host_ip for v in self.p.vulns if v.in_cisa_kev})
            lines += [
                "",
                f"WARNING: {kev_n} findings match the CISA Known Exploited Vulnerabilities "
                f"catalog, affecting {kev_hosts} host(s). These are confirmed actively exploited "
                f"and should be treated as highest priority.",
            ]
        for ln in lines:
            ws.merge_range(r, 0, r, 7, ln, f["nar"])
            r += 1
        r += 1

        # Severity breakdown
        ws.merge_range(r, 0, r, 7, "Severity Breakdown", f["sec"])
        r += 1
        for c, h in enumerate(["Severity", "Total", "Unique Vulns", "% of Total",
                                "Hosts Affected", "With Exploit", "In CISA KEV", ""]):
            ws.write(r, c, h, f["hdr"])
        r += 1
        for sn in ["Critical", "High", "Medium", "Low", "Informational"]:
            sv = [v for v in self.p.vulns if v.severity_name == sn]
            ts = tot[sn]
            ws.write(r, 0, sn, self._sf(sn))
            ws.write(r, 1, ts, f["n"])
            ws.write(r, 2, uniq[sn], f["n"])
            ws.write(r, 3, ts / max(ta, 1), f["pct"])
            ws.write(r, 4, len({v.host_ip for v in sv}), f["n"])
            ws.write(r, 5, len([v for v in sv if v.exploit_available.lower() == "true"]), f["n"])
            ws.write(r, 6, len([v for v in sv if v.in_cisa_kev]), f["n"])
            r += 1
        r += 1

        # Top 10
        ws.merge_range(r, 0, r, 7, "Top 10 Vulnerabilities by Impact", f["sec"])
        r += 1
        for c, h in enumerate(["Plugin Name", "Severity", "CVSS", "Hosts",
                                "Exploit?", "CISA KEV", "Max EPSS", "Priority"]):
            ws.write(r, c, h, f["hdr"])
        r += 1

        agg: Dict[str, Dict] = {}
        for v in self.p.vulns:
            if v.severity < 3:
                continue
            if v.plugin_name not in agg:
                agg[v.plugin_name] = {
                    "sev": v.severity_name, "cvss": 0.0, "hosts": set(),
                    "exploit": False, "kev": False, "pri": 0.0, "epss": 0.0,
                }
            a = agg[v.plugin_name]
            a["hosts"].add(v.host_ip)
            a["cvss"] = max(a["cvss"], v.cvss_base_score)
            a["pri"] = max(a["pri"], v.priority_score)
            a["epss"] = max(a["epss"], v.epss_score or 0.0)
            if v.exploit_available.lower() == "true":
                a["exploit"] = True
            if v.in_cisa_kev:
                a["kev"] = True

        top10 = sorted(agg.items(), key=lambda x: x[1]["pri"] * (1 + math.log2(max(len(x[1]["hosts"]), 1))), reverse=True)[:10]
        for pn, d in top10:
            ws.write(r, 0, pn, f["w"])
            ws.write(r, 1, d["sev"], self._sf(d["sev"]))
            ws.write(r, 2, d["cvss"], f["d"])
            ws.write(r, 3, len(d["hosts"]), f["n"])
            ws.write(r, 4, "Yes" if d["exploit"] else "No", f["w"])
            ws.write(r, 5, "YES" if d["kev"] else "", f["dn"] if d["kev"] else f["w"])
            ws.write(r, 6, d["epss"], f["epct"])
            ws.write(r, 7, d["pri"], f["d"])
            r += 1

    def _exec_charts(self) -> None:
        ws = self.wb.add_worksheet("Charts")
        ws.hide_gridlines(2)
        ws.set_tab_color("#1D365A")
        dw = self.wb.add_worksheet("_ChartData")
        dw.hide()

        tot = self.p.severity_totals()
        so = ["Critical", "High", "Medium", "Low", "Informational"]
        colors = ["#B8504B", "#E9A23A", "#F7F552", "#58BF65", "#618ECD"]

        # ── Pie chart data ──
        r = 0
        dw.write(r, 0, "Severity")
        dw.write(r, 1, "Count")
        r += 1
        for sn in so:
            dw.write(r, 0, sn)
            dw.write(r, 1, tot[sn])
            r += 1

        pie = self.wb.add_chart({"type": "pie"})
        pie.set_size({"width": 520, "height": 380})
        pie.add_series({
            "name": "By Severity",
            "categories": ["_ChartData", 1, 0, 5, 0],
            "values": ["_ChartData", 1, 1, 5, 1],
            "data_labels": {"percentage": 1, "category": 1, "separator": "\n", "font": {"size": 9}},
            "points": [{"fill": {"color": c}} for c in colors],
        })
        pie.set_title({"name": "Vulnerability Distribution by Severity"})
        pie.set_legend({"position": "bottom"})
        pie.set_style(10)
        ws.insert_chart("A1", pie)

        # ── Stacked bar: top 20 hosts ──
        hm = self.p.host_sev_matrix()
        sh = sorted(hm.items(),
                     key=lambda x: x[1]["Critical"] * 100 + x[1]["High"] * 10 + x[1]["Medium"],
                     reverse=True)[:20]
        dr = 8
        dw.write(dr, 0, "Host")
        for ci, sn in enumerate(so):
            dw.write(dr, ci + 1, sn)
        dr += 1
        hs = dr
        for hip, sc in sh:
            dw.write(dr, 0, hip)
            for ci, sn in enumerate(so):
                dw.write(dr, ci + 1, sc.get(sn, 0))
            dr += 1
        he = dr - 1
        if sh:
            bar = self.wb.add_chart({"type": "bar", "subtype": "stacked"})
            bar.set_size({"width": 520, "height": 500})
            for ci, sn in enumerate(so):
                bar.add_series({
                    "name": sn,
                    "categories": ["_ChartData", hs, 0, he, 0],
                    "values": ["_ChartData", hs, ci + 1, he, ci + 1],
                    "fill": {"color": colors[ci]}, "gap": 80,
                })
            bar.set_title({"name": "Top 20 Hosts — Vulnerabilities by Severity"})
            bar.set_x_axis({"name": "Count"})
            bar.set_legend({"position": "bottom"})
            bar.set_style(10)
            ws.insert_chart("A22", bar)

        # ── Top 20 most common vulns ──
        at = []
        for sn in ["Critical", "High", "Medium"]:
            at.extend(self.p.top_vulns(sn, 20))
        at.sort(key=lambda x: x[1], reverse=True)
        at = at[:20]
        dr += 2
        dw.write(dr, 0, "Vuln")
        dw.write(dr, 1, "Count")
        dr += 1
        vs = dr
        for vn, vc in at:
            dw.write(dr, 0, (vn[:60] + "..." if len(vn) > 60 else vn))
            dw.write(dr, 1, vc)
            dr += 1
        ve = dr - 1
        if at:
            hb = self.wb.add_chart({"type": "bar"})
            hb.set_size({"width": 520, "height": 500})
            hb.add_series({
                "name": "Count",
                "categories": ["_ChartData", vs, 0, ve, 0],
                "values": ["_ChartData", vs, 1, ve, 1],
                "fill": {"color": "#2E4057"}, "gap": 60,
            })
            hb.set_title({"name": "Top 20 Most Common Vulns (Crit/High/Med)"})
            hb.set_legend({"none": 1})
            hb.set_style(10)
            ws.insert_chart("I1", hb)

        # ── Exploitability breakdown ──
        dr += 2
        dw.write(dr, 0, "Severity")
        dw.write(dr, 1, "Exploitable")
        dw.write(dr, 2, "Not Exploitable")
        dr += 1
        es = dr
        for sn in ["Critical", "High", "Medium", "Low"]:
            ts = tot[sn]
            ex = len([v for v in self.p.vulns
                      if v.severity_name == sn and v.exploit_available.lower() == "true"])
            dw.write(dr, 0, sn)
            dw.write(dr, 1, ex)
            dw.write(dr, 2, ts - ex)
            dr += 1
        ee = dr - 1
        ec = self.wb.add_chart({"type": "column", "subtype": "stacked"})
        ec.set_size({"width": 520, "height": 400})
        ec.add_series({
            "name": "Exploitable",
            "categories": ["_ChartData", es, 0, ee, 0],
            "values": ["_ChartData", es, 1, ee, 1],
            "fill": {"color": "#B8504B"},
        })
        ec.add_series({
            "name": "Not Exploitable",
            "categories": ["_ChartData", es, 0, ee, 0],
            "values": ["_ChartData", es, 2, ee, 2],
            "fill": {"color": "#AEBFCF"},
        })
        ec.set_title({"name": "Exploitability by Severity"})
        ec.set_legend({"position": "bottom"})
        ec.set_style(10)
        ws.insert_chart("I22", ec)

    def _risk_matrix(self) -> None:
        ws = self.wb.add_worksheet("Risk Matrix")
        ws.set_tab_color("#B8504B")
        f = self.f

        ws.merge_range("A1:H2", "Host Risk Matrix", f["title"])
        hdrs = ["Rank", "Host IP", "Risk Score", "Critical", "High",
                "Medium", "Low", "Exploitable"]
        r = 3
        for c, h in enumerate(hdrs):
            ws.write(r, c, h, f["hdr"])
        ws.set_column("A:A", 8)
        ws.set_column("B:B", 18)
        ws.set_column("C:H", 13)
        ws.freeze_panes("C5")
        ws.autofilter(r, 0, r, 7)

        hm = self.p.host_sev_matrix()
        hr = self.p.host_risk_scores()
        ep: Dict[str, int] = defaultdict(int)
        for v in self.p.vulns:
            if v.exploit_available.lower() == "true":
                ep[v.host_ip] += 1

        r = 4
        for rk, (hip, rs) in enumerate(sorted(hr.items(), key=lambda x: x[1], reverse=True), 1):
            sd = hm.get(hip, {})
            rf = f["rh"] if rs > 50 else (f["rm"] if rs > 20 else f["rl"])
            ws.write(r, 0, rk, f["n"])
            ws.write(r, 1, hip, f["w"])
            ws.write(r, 2, round(rs, 1), rf)
            ws.write(r, 3, sd.get("Critical", 0), f["n"])
            ws.write(r, 4, sd.get("High", 0), f["n"])
            ws.write(r, 5, sd.get("Medium", 0), f["n"])
            ws.write(r, 6, sd.get("Low", 0), f["n"])
            ws.write(r, 7, ep.get(hip, 0), f["n"])
            r += 1

    # ══════════════════════════════════════════════════════════════════════════
    # THREAT INTELLIGENCE
    # ══════════════════════════════════════════════════════════════════════════

    def _threat_intel(self) -> None:
        ws = self.wb.add_worksheet("Threat Intelligence")
        ws.set_tab_color("#922B21")
        f = self.f

        ws.merge_range("A1:I2", "Threat Intelligence — EPSS & CISA KEV", f["title"])
        ws.set_column("A:A", 16)
        ws.set_column("B:B", 7)
        ws.set_column("C:C", 11)
        ws.set_column("D:D", 50)
        ws.set_column("E:E", 16)
        ws.set_column("F:F", 8)
        ws.set_column("G:G", 9)
        ws.set_column("H:H", 60)
        ws.set_column("I:I", 12)

        # KEV section
        kv = sorted([v for v in self.p.vulns if v.in_cisa_kev],
                     key=lambda v: v.priority_score, reverse=True)
        r = 3
        ws.merge_range(r, 0, r, 8, f"CISA KEV Findings — {len(kv)}", f["sec"])
        r += 1
        if kv:
            for c, h in enumerate(["Host", "Port", "Severity", "Plugin", "CVE",
                                    "CVSS", "EPSS", "KEV Action", "Priority"]):
                ws.write(r, c, h, f["hdr"])
            r += 1
            seen: Set[str] = set()
            for v in kv:
                k = f"{v.host_ip}|{v.plugin_id}"
                if k in seen:
                    continue
                seen.add(k)
                ka = ""
                if self.ti:
                    for cve in v.cve_list:
                        d = self.ti.kev_details.get(cve)
                        if d:
                            ka = d.get("action", "")
                            break
                ws.write(r, 0, v.host_ip, f["w"])
                ws.write(r, 1, v.port, f["n"])
                ws.write(r, 2, v.severity_name, self._sf(v.severity_name))
                ws.write(r, 3, v.plugin_name, f["w"])
                ws.write(r, 4, v.cve_str, f["w"])
                ws.write(r, 5, v.cvss_base_score, f["d"])
                ws.write(r, 6, v.epss_score or 0, f["epct"])
                ws.write(r, 7, ka, f["w"])
                ws.write(r, 8, v.priority_score, f["d"])
                r += 1
        else:
            ws.merge_range(r, 0, r, 8, "No findings match the CISA KEV catalog.", f["nar"])
            r += 1
        r += 1

        # Top EPSS
        ev = sorted([v for v in self.p.vulns if v.epss_score and v.epss_score > 0 and v.severity >= 2],
                     key=lambda v: v.epss_score or 0, reverse=True)
        ws.merge_range(r, 0, r, 8, "Highest EPSS Scores (top 50)", f["sec"])
        r += 1
        for c, h in enumerate(["Host", "Port", "Severity", "Plugin", "CVE",
                                "CVSS", "EPSS Score", "EPSS %ile", "Priority"]):
            ws.write(r, c, h, f["hdr"])
        r += 1
        seen = set()
        cnt = 0
        for v in ev:
            k = f"{v.host_ip}|{v.plugin_id}"
            if k in seen:
                continue
            seen.add(k)
            ws.write(r, 0, v.host_ip, f["w"])
            ws.write(r, 1, v.port, f["n"])
            ws.write(r, 2, v.severity_name, self._sf(v.severity_name))
            ws.write(r, 3, v.plugin_name, f["w"])
            ws.write(r, 4, v.cve_str, f["w"])
            ws.write(r, 5, v.cvss_base_score, f["d"])
            ws.write(r, 6, v.epss_score or 0, f["epct"])
            ws.write(r, 7, v.epss_percentile or 0, f["epct"])
            ws.write(r, 8, v.priority_score, f["d"])
            r += 1
            cnt += 1
            if cnt >= 50:
                break

    # ══════════════════════════════════════════════════════════════════════════
    # OPERATIONAL LAYER
    # ══════════════════════════════════════════════════════════════════════════

    def _priority_queue(self) -> None:
        ws = self.wb.add_worksheet("Priority Queue")
        ws.set_tab_color("#E9A23A")
        f = self.f
        hti = self.ti and self.ti.is_available

        hdrs = ["#", "Score", "Host IP", "Port", "Severity", "Plugin Name",
                "CVSS", "Exploit?", "Age (d)"]
        if hti:
            hdrs += ["EPSS", "CISA KEV"]
        hdrs.append("Solution")

        ws.merge_range(0, 0, 1, len(hdrs) - 1,
                        "Vulnerability Priority Queue — Remediation Order", f["title"])
        r = 2
        for c, h in enumerate(hdrs):
            ws.write(r, c, h, f["hdr"])

        widths = [6, 10, 16, 7, 11, 55, 7, 9, 8]
        if hti:
            widths += [9, 10]
        widths.append(70)
        for c, w in enumerate(widths):
            ws.set_column(c, c, w)
        ws.freeze_panes("C4")
        ws.autofilter(r, 0, r, len(hdrs) - 1)

        pv = sorted([v for v in self.p.vulns if v.severity >= 2],
                     key=lambda v: v.priority_score, reverse=True)
        r = 3
        for rk, v in enumerate(pv, 1):
            c = 0
            ws.write(r, c, rk, f["n"]); c += 1
            ws.write(r, c, v.priority_score, f["d"]); c += 1
            ws.write(r, c, v.host_ip, f["w"]); c += 1
            ws.write(r, c, v.port, f["n"]); c += 1
            ws.write(r, c, v.severity_name, self._sf(v.severity_name)); c += 1
            ws.write(r, c, v.plugin_name, f["w"]); c += 1
            ws.write(r, c, v.cvss_base_score, f["d"]); c += 1
            ws.write(r, c, "Yes" if v.exploit_available.lower() == "true" else "No", f["w"]); c += 1
            ws.write(r, c, v.vuln_age_days, f["n"]); c += 1
            if hti:
                ws.write(r, c, v.epss_score or 0, f["epct"]); c += 1
                ws.write(r, c, "YES" if v.in_cisa_kev else "",
                         f["dn"] if v.in_cisa_kev else f["w"]); c += 1
            ws.write(r, c, v.solution, f["w"])
            r += 1

    def _remediation_plan(self) -> None:
        ws = self.wb.add_worksheet("Remediation Plan")
        ws.set_tab_color("#58BF65")
        f = self.f

        ws.merge_range("A1:G2", "Remediation Plan — Grouped by Solution", f["title"])
        ws.set_column("A:A", 8)
        ws.set_column("B:B", 80)
        ws.set_column("C:C", 12)
        ws.set_column("D:D", 16)
        ws.set_column("E:E", 50)
        ws.set_column("F:F", 8)
        ws.set_column("G:G", 12)

        groups = self.p.remediation_groups()
        sg = sorted(groups.items(),
                     key=lambda x: sum(v.priority_score for v in x[1]), reverse=True)

        r = 3
        for an, (sol, vulns) in enumerate(sg, 1):
            ha = {v.host_ip for v in vulns}
            ms = max(v.severity for v in vulns)
            msn = SEVERITY_MAP.get(ms, "?")
            ti = sum(v.priority_score for v in vulns)
            kev = any(v.in_cisa_kev for v in vulns)
            tag = "  *** CISA KEV ***" if kev else ""

            ws.merge_range(r, 0, r, 6,
                            f"ACTION #{an}  |  {len(ha)} host(s)  |  "
                            f"Max: {msn}  |  Impact: {round(ti, 1)}{tag}", f["sec"])
            r += 1
            ws.merge_range(r, 0, r, 6, f"Solution: {sol[:200]}", f["bw"])
            ws.set_row(r, 40)
            r += 1

            for c, h in enumerate(["#", "Plugin Name", "Severity", "Host IP",
                                    "Synopsis", "Port", "CVSS"]):
                ws.write(r, c, h, f["hdr"])
            r += 1

            seen: Set[str] = set()
            idx = 0
            for v in sorted(vulns, key=lambda x: x.priority_score, reverse=True):
                k = f"{v.host_ip}|{v.plugin_id}"
                if k in seen:
                    continue
                seen.add(k)
                idx += 1
                ws.write(r, 0, idx, f["n"])
                ws.write(r, 1, v.plugin_name, f["w"])
                ws.write(r, 2, v.severity_name, self._sf(v.severity_name))
                ws.write(r, 3, v.host_ip, f["w"])
                ws.write(r, 4, (v.synopsis[:150] if v.synopsis else ""), f["w"])
                ws.write(r, 5, v.port, f["n"])
                ws.write(r, 6, v.cvss_base_score, f["d"])
                r += 1
            r += 1

    def _quick_wins_sheet(self) -> None:
        ws = self.wb.add_worksheet("Quick Wins")
        ws.set_tab_color("#2E86C1")
        f = self.f

        ws.merge_range("A1:G2", "Quick Wins — Single Fix, 3+ Hosts", f["title"])
        hdrs = ["Rank", "Vulnerability", "Plugin ID", "Hosts", "Max CVSS", "Impact", "Solution"]
        r = 3
        for c, h in enumerate(hdrs):
            ws.write(r, c, h, f["hdr"])
        ws.set_column("A:A", 8)
        ws.set_column("B:B", 55)
        ws.set_column("C:C", 10)
        ws.set_column("D:D", 8)
        ws.set_column("E:E", 10)
        ws.set_column("F:F", 10)
        ws.set_column("G:G", 80)
        ws.freeze_panes("B5")
        ws.autofilter(r, 0, r, 6)

        qw = self.p.quick_wins(3)
        r = 4
        for rk, (pn, sol, nh, mc, imp, pid) in enumerate(qw, 1):
            ws.write(r, 0, rk, f["n"])
            ws.write(r, 1, pn, f["w"])
            ws.write(r, 2, int(pid) if pid.isdigit() else pid, f["n"])
            ws.write(r, 3, nh, f["n"])
            ws.write(r, 4, mc, f["d"])
            ws.write(r, 5, round(imp, 1), f["d"])
            ws.write(r, 6, sol[:300], f["w"])
            r += 1

    # ══════════════════════════════════════════════════════════════════════════
    # REFERENCE SHEETS
    # ══════════════════════════════════════════════════════════════════════════

    def _full_report(self) -> None:
        ws = self.wb.add_worksheet("Full Report")
        ws.set_tab_color("#5D6D7E")
        f = self.f
        hti = self.ti and self.ti.is_available

        hdrs = ["#", "File", "Host IP", "Port", "FQDN", "Vuln Pub Date", "Age (d)",
                "Severity", "Risk Factor", "Plugin ID", "Plugin Family", "Plugin Name",
                "Description", "Synopsis", "Plugin Output", "Solution",
                "Exploit Available", "Exploitability Ease", "Exploited by Malware",
                "Plugin Pub Date", "Plugin Mod Date", "CVE", "Bugtraq ID",
                "CVSS Base", "CVSS Temporal", "Priority Score"]
        if hti:
            hdrs += ["EPSS Score", "CISA KEV"]

        r = 0
        for c, h in enumerate(hdrs):
            ws.write(r, c, h, f["hdr"])
        widths = [8, 25, 16, 8, 25, 14, 10, 10, 12, 10, 20, 60,
                  40, 25, 30, 40, 12, 15, 15, 14, 14, 20, 15, 10, 10, 12]
        if hti:
            widths += [10, 10]
        for c, w in enumerate(widths):
            ws.set_column(c, c, w)
        ws.freeze_panes("C2")
        ws.autofilter(0, 0, 0, len(hdrs) - 1)

        r = 1
        for i, v in enumerate(self.p.vulns, 1):
            c = 0
            for val, fmt in [
                (i, f["n"]), (v.source_file, f["w"]), (v.host_ip, f["w"]),
                (v.port, f["n"]), (v.host_fqdn, f["w"]),
                (v.vuln_publication_date, f["w"]), (v.vuln_age_days, f["n"]),
                (v.severity_name, self._sf(v.severity_name)),
                (v.risk_factor, f["w"]),
                (int(v.plugin_id) if v.plugin_id.isdigit() else v.plugin_id, f["n"]),
                (v.plugin_family, f["w"]), (v.plugin_name, f["w"]),
                (v.description, f["w"]), (v.synopsis, f["w"]),
                (v.plugin_output, f["w"]), (v.solution, f["w"]),
                (v.exploit_available, f["w"]), (v.exploitability_ease, f["w"]),
                (v.exploited_by_malware, f["w"]),
                (v.plugin_publication_date, f["w"]),
                (v.plugin_modification_date, f["w"]),
                (v.cve_str, f["w"]), (v.bid_str, f["w"]),
                (v.cvss_base_score, f["d"]), (v.cvss_temporal_score, f["d"]),
                (v.priority_score, f["d"]),
            ]:
                ws.write(r, c, val, fmt)
                c += 1
            if hti:
                ws.write(r, c, v.epss_score or 0, f["epct"]); c += 1
                ws.write(r, c, "YES" if v.in_cisa_kev else "", f["w"]); c += 1
            r += 1

    def _severity_sheet(self, sn: str, si: int) -> None:
        ws = self.wb.add_worksheet(sn)
        ws.set_tab_color(SEVERITY_TAB_COLORS.get(sn, "gray"))
        f = self.f

        hdrs = ["#", "File", "Host IP", "Port", "Vuln Pub Date", "Plugin ID",
                "Plugin Name", "Exploit Available", "Exploited by Malware",
                "CVE", "Bugtraq ID", "Priority Score"]
        for c, h in enumerate(hdrs):
            ws.write(0, c, h, f["hdr"])
        widths = [8, 25, 16, 8, 14, 10, 70, 14, 14, 20, 15, 12]
        for c, w in enumerate(widths):
            ws.set_column(c, c, w)
        ws.freeze_panes("C2")
        ws.autofilter(0, 0, 0, len(hdrs) - 1)

        fl = sorted([v for v in self.p.vulns if v.severity == si],
                     key=lambda v: v.priority_score, reverse=True)
        r = 1
        for i, v in enumerate(fl, 1):
            ws.write(r, 0, i, f["n"])
            ws.write(r, 1, v.source_file, f["w"])
            ws.write(r, 2, v.host_ip, f["w"])
            ws.write(r, 3, v.port, f["n"])
            ws.write(r, 4, v.vuln_publication_date, f["w"])
            ws.write(r, 5, int(v.plugin_id) if v.plugin_id.isdigit() else v.plugin_id, f["n"])
            ws.write(r, 6, v.plugin_name, f["w"])
            ws.write(r, 7, v.exploit_available, f["w"])
            ws.write(r, 8, v.exploited_by_malware, f["w"])
            ws.write(r, 9, v.cve_str, f["w"])
            ws.write(r, 10, v.bid_str, f["w"])
            ws.write(r, 11, v.priority_score, f["d"])
            r += 1

    def _cvss_overview(self) -> None:
        ws = self.wb.add_worksheet("CVSS Overview")
        ws.set_tab_color("#F3E2D3")
        f = self.f

        hdrs = ["#", "File", "Host IP", "Total", "Base Total", "Temporal Total"]
        for sn in ["Critical", "High", "Medium", "Low", "Informational"]:
            hdrs += [f"Base {sn[:4]}", f"Temporal {sn[:4]}"]
        for c, h in enumerate(hdrs):
            ws.write(0, c, h, f["hdr"])
        for c in range(len(hdrs)):
            ws.set_column(c, c, 14)
        ws.freeze_panes("D2")
        ws.autofilter(0, 0, 0, len(hdrs) - 1)

        r = 1
        for i, hc in enumerate(self.p.host_cvss, 1):
            ws.write(r, 0, i, f["n"])
            ws.write(r, 1, hc.source_file, f["w"])
            ws.write(r, 2, hc.host_ip, f["w"])
            bt = sum(hc.scores.get(j, {}).get("cvss_base_score", 0) for j in range(5))
            tt = sum(hc.scores.get(j, {}).get("cvss_temporal_score", 0) for j in range(5))
            ws.write(r, 3, round(bt + tt, 2), f["d"])
            ws.write(r, 4, round(bt, 2), f["d"])
            ws.write(r, 5, round(tt, 2), f["d"])
            c = 6
            for si in [4, 3, 2, 1, 0]:
                sc = hc.scores.get(si, {"cvss_base_score": 0, "cvss_temporal_score": 0})
                ws.write(r, c, round(sc["cvss_base_score"], 2), f["d"])
                ws.write(r, c + 1, round(sc["cvss_temporal_score"], 2), f["d"])
                c += 2
            r += 1

    def _device_types(self) -> None:
        ws = self.wb.add_worksheet("Device Type")
        ws.set_tab_color("#BDE1ED")
        f = self.f
        for c, h in enumerate(["#", "File", "Host IP", "FQDN", "NetBIOS", "Type", "Confidence"]):
            ws.write(0, c, h, f["hdr"])
        for c, w in enumerate([8, 25, 16, 30, 20, 20, 12]):
            ws.set_column(c, c, w)
        ws.freeze_panes("C2")
        ws.autofilter(0, 0, 0, 6)
        r = 1
        for i, d in enumerate(self.p.devices, 1):
            ws.write(r, 0, i, f["n"])
            ws.write(r, 1, d.source_file, f["w"])
            ws.write(r, 2, d.host_ip, f["w"])
            ws.write(r, 3, d.host_fqdn, f["w"])
            ws.write(r, 4, d.netbios_name, f["w"])
            ws.write(r, 5, d.device_type, f["w"])
            ws.write(r, 6, d.confidence_level, f["n"])
            r += 1

    def _ms_processes(self) -> None:
        ws = self.wb.add_worksheet("MS Processes")
        ws.set_tab_color("#9EC3FF")
        f = self.f
        for c, h in enumerate(["#", "File", "Host IP", "FQDN", "NetBIOS", "Process"]):
            ws.write(0, c, h, f["hdr"])
        for c, w in enumerate([8, 25, 16, 30, 20, 80]):
            ws.set_column(c, c, w)
        ws.freeze_panes("C2")
        ws.autofilter(0, 0, 0, 5)
        r = 1
        for i, p in enumerate(self.p.processes, 1):
            ws.write(r, 0, i, f["n"])
            ws.write(r, 1, p.source_file, f["w"])
            ws.write(r, 2, p.host_ip, f["w"])
            ws.write(r, 3, p.host_fqdn, f["w"])
            ws.write(r, 4, p.netbios_name, f["w"])
            ws.write(r, 5, p.process_line, f["w"])
            r += 1

    def _plugin_counts(self) -> None:
        ws = self.wb.add_worksheet("Plugin Counts")
        ws.set_tab_color("#D1B7FF")
        f = self.f
        for c, h in enumerate(["Plugin Name", "Plugin ID", "Occurrences"]):
            ws.write(0, c, h, f["hdr"])
        ws.set_column(0, 0, 80)
        ws.set_column(1, 1, 12)
        ws.set_column(2, 2, 16)
        ws.freeze_panes("A2")
        ws.autofilter(0, 0, 0, 2)
        r = 1
        for pn, (pid, cnt) in sorted(self.p.plugin_counts.items(),
                                       key=lambda x: x[1][1], reverse=True):
            ws.write(r, 0, pn, f["w"])
            ws.write(r, 1, int(pid) if pid.isdigit() else pid, f["n"])
            ws.write(r, 2, cnt, f["n"])
            r += 1


# ─── CLI ──────────────────────────────────────────────────────────────────────

def build_cli() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description=f"NessusParser Pro v{__version__} — Vulnerability report generator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  %(prog)s -i scan.nessus -o report
  %(prog)s -i ./scans/ -o report --enrich
  %(prog)s -i scan1.nessus scan2.nessus -o report --exclude-ids 12345,67890
  %(prog)s -i "./scans/*.nessus" -o report --enrich --min-severity 2
""",
    )
    p.add_argument("-i", "--input", nargs="+", required=True,
                   help="Input .nessus files, directories, or glob patterns")
    p.add_argument("-o", "--output", required=True,
                   help="Output filename (without .xlsx)")
    p.add_argument("--enrich", action="store_true",
                   help="Enrich CVEs with EPSS scores and CISA KEV (requires internet)")
    p.add_argument("--exclude-ids", default="",
                   help="Comma-separated Plugin IDs to exclude")
    p.add_argument("--exclude-ids-file", default="",
                   help="File with Plugin IDs to exclude (one per line)")
    p.add_argument("--min-severity", type=int, default=0, choices=[0, 1, 2, 3, 4],
                   help="Minimum severity to include (0=Info, 1=Low, 2=Med, 3=High, 4=Crit)")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="Enable debug logging")
    return p


def main() -> None:
    cli = build_cli()
    args = cli.parse_args()
    if args.verbose:
        logging.getLogger("nessusparser").setLevel(logging.DEBUG)

    log.info("NessusParser Pro v%s", __version__)

    # Resolve inputs
    files = NessusParser.resolve_inputs(args.input)
    if not files:
        log.error("No .nessus/.xml files found")
        sys.exit(1)
    log.info("Found %d file(s) to parse", len(files))

    # Excluded IDs
    ignored: Set[str] = set()
    if args.exclude_ids:
        for pid in args.exclude_ids.split(","):
            pid = pid.strip()
            if pid:
                ignored.add(pid)
    if args.exclude_ids_file:
        try:
            with open(args.exclude_ids_file) as fh:
                for ln in fh:
                    pid = ln.strip()
                    if pid:
                        ignored.add(pid)
        except IOError as e:
            log.error("Cannot read exclude IDs file: %s", e)
            sys.exit(1)
    if ignored:
        log.info("Excluding %d Plugin ID(s)", len(ignored))

    # Parse
    parser = NessusParser(ignored_ids=ignored)
    parser.parse_files(files)

    if not parser.vulns:
        log.warning("No vulnerabilities found")

    # Severity filter
    if args.min_severity > 0:
        before = len(parser.vulns)
        parser.vulns = [v for v in parser.vulns if v.severity >= args.min_severity]
        log.info("Severity filter: %d → %d findings", before, len(parser.vulns))

    # Threat intel enrichment
    ti: Optional[ThreatIntel] = None
    if args.enrich:
        ti = ThreatIntel()
        parser.enrich(ti)

    # Summary
    totals = parser.severity_totals()
    log.info("── Scan Summary ──")
    log.info("  Files:       %d", len(parser.files_parsed))
    log.info("  Unique hosts: %d", len(parser.unique_ips))
    log.info("  Total vulns:  %d", len(parser.vulns))
    for sn in ["Critical", "High", "Medium", "Low", "Informational"]:
        log.info("    %-15s %d", sn, totals[sn])

    # Generate report
    report = ExcelReportGenerator(parser, args.output, threat_intel=ti)
    output_file = report.generate()
    log.info("Done! Report: %s", output_file)


if __name__ == "__main__":
    main()
