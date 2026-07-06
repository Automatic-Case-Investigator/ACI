"""Preprocess Wazuh indexer dumps and merge in AMiner-derived alerts.

Each input file (ait_ads/<prefix>_wazuh.json) is a JSON dump where every line is a
single alert object (originally the value stored under an OpenSearch document's
"_source" key). For each line we rebuild the full OpenSearch document shape:

    {
        "_index": "wazuh-alerts-4.x-<year>-<month>-<day>",  # from alert timestamp
        "_id":    "<opensearch-style 20-char id>",
        "_score": 1,
        "_source": <alert object>
    }

In addition, if a sibling ait_ads/<prefix>_aminer.json exists, every AMiner anomaly
event in it is converted into a NATIVE-LOOKING Wazuh alert (see "AMiner -> Wazuh"
below) and folded into the same output dump, producing a larger combined dump that
contains alerts from both sources, indistinguishable in shape. The combined stream
is merged by "@timestamp" so the two sources are interleaved chronologically.

Outputs (in the "preprocessed" directory):
    <prefix>_wazuh.json          combined Wazuh + AMiner-derived alert dump
    <prefix>_aminer.labels.json  ground-truth sidecar for the AMiner-derived alerts,
                                 keyed by the synthesized Wazuh alert id, holding the
                                 AMiner detector metadata stripped from the alert.

AMiner -> Wazuh conversion:
  * The AMiner `AnalysisComponent` block is discarded from the alert (its detector
    type/name, scores and `/model/...` parse-model paths are AMiner fingerprints)
    and written to the sidecar instead.
  * Each alert is rebuilt from the raw log line as Wazuh's own pipeline would, using
    the ACTUAL Wazuh default ruleset (ids/levels/descriptions/groups/compliance taken
    verbatim from github.com/wazuh/wazuh-ruleset, rules/*.xml). Rule selection mirrors
    real Wazuh behaviour: matched sources get their genuine rule; a line containing
    Wazuh's $BAD_WORDS with no more specific match gets rule 1002; a benign unmatched
    line gets the level-0 base template rule 1.
  * Event time is parsed from the raw line (as Wazuh does) so @timestamp,
    predecoder.timestamp and full_log stay mutually consistent.
"""

import base64
import collections
import glob
import heapq
import json
import os
import re
import secrets
from datetime import datetime, timezone

INPUT_DIR = "ait_ads"
OUTPUT_DIR = "preprocessed"

# Synthesized Wazuh alert-id epoch for AMiner-derived alerts. Native ids look like
# "<processing-epoch>.<counter>"; the epoch is the manager's processing time, not the
# event time. We use a value outside the dumps' own id range so the two never collide.
ALERT_ID_EPOCH = 1700000000
ALERT_ID_SEQ_START = 100000

# Wazuh $BAD_WORDS list (0020-syslog_rules.xml, rule 1002).
BAD_WORDS = re.compile(
    r"core_dumped|failure|error|attack| bad |illegal |denied|refused|"
    r"unauthorized|fatal|failed|Segmentation Fault|Corrupted")


# --------------------------------------------------------------------------- #
# OpenSearch document envelope (original preprocess behaviour).               #
# --------------------------------------------------------------------------- #
def make_id() -> str:
    """OpenSearch-style auto id: 15 random bytes, url-safe base64, no padding."""
    return base64.urlsafe_b64encode(secrets.token_bytes(15)).decode("ascii").rstrip("=")


def make_index(source: dict) -> str:
    """Daily index name "wazuh-alerts-4.x-<year>-<month>-<day>" from @timestamp."""
    date_part = source.get("@timestamp", "").split("T", 1)[0]
    year, month, day = date_part.split("-")
    return f"wazuh-alerts-4.x-{year}-{month}-{day}"


def to_wazuh_timestamp(at_timestamp: str) -> str:
    """ISO "@timestamp" -> Wazuh native "timestamp" ("...T...:....000+0000")."""
    dt = datetime.strptime(at_timestamp, "%Y-%m-%dT%H:%M:%S.%f%z")
    millis = dt.strftime("%f")[:3]
    return dt.strftime(f"%Y-%m-%dT%H:%M:%S.{millis}%z")


def wrap(source: dict) -> dict:
    """Add the native "timestamp" field and wrap a _source in the OpenSearch doc."""
    if "timestamp" not in source and "@timestamp" in source:
        source["timestamp"] = to_wazuh_timestamp(source["@timestamp"])
    return {"_index": make_index(source), "_id": make_id(), "_score": 1, "_source": source}


# --------------------------------------------------------------------------- #
# Wazuh default ruleset definitions (verbatim from wazuh-ruleset rules/*.xml). #
# --------------------------------------------------------------------------- #
RULE_DEFS = {
    "1": {"level": 0, "description": "Generic template for all syslog rules.",
          "groups": ["syslog"]},
    "1002": {"level": 2, "description": "Unknown problem somewhere in the system.",
             "groups": ["syslog", "errors"], "gpg13": ["4.3"]},
    "5100": {"level": 0, "description": "Pre-match rule for kernel messages.",
             "groups": ["syslog"]},
    "5500": {"level": 0, "description": "Grouping of the pam_unix rules.",
             "groups": ["pam", "syslog"]},
    "5501": {"level": 3, "description": "PAM: Login session opened.",
             "groups": ["pam", "syslog", "authentication_success"],
             "pci_dss": ["10.2.5"], "gpg13": ["7.8", "7.9"], "gdpr": ["IV_32.2"],
             "hipaa": ["164.312.b"], "nist_800_53": ["AU.14", "AC.7"],
             "tsc": ["CC6.8", "CC7.2", "CC7.3"]},
    "5502": {"level": 3, "description": "PAM: Login session closed.",
             "groups": ["pam", "syslog"],
             "pci_dss": ["10.2.5"], "gpg13": ["7.8", "7.9"], "gdpr": ["IV_32.2"],
             "hipaa": ["164.312.b"], "nist_800_53": ["AU.14", "AC.7"],
             "tsc": ["CC6.8", "CC7.2", "CC7.3"]},
    "9300": {"level": 0, "description": "Grouping for the Horde imp rules.",
             "groups": ["syslog", "hordeimp"]},
    "9303": {"level": 5, "description": "Horde IMP error message.",
             "groups": ["syslog", "hordeimp"], "gdpr": ["IV_35.7.d"]},
    "9305": {"level": 3, "description": "Horde IMP successful login.",
             "groups": ["syslog", "hordeimp", "authentication_success"],
             "pci_dss": ["10.2.5"], "gpg13": ["7.1", "7.2"], "gdpr": ["IV_32.2"],
             "hipaa": ["164.312.b"], "nist_800_53": ["AU.14", "AC.7"],
             "tsc": ["CC6.8", "CC7.2", "CC7.3"]},
    "9306": {"level": 5, "description": "Horde IMP Failed login.",
             "groups": ["syslog", "hordeimp", "authentication_failed"],
             "pci_dss": ["10.2.4", "10.2.5"], "gpg13": ["7.1"],
             "gdpr": ["IV_35.7.d", "IV_32.2"], "hipaa": ["164.312.b"],
             "nist_800_53": ["AU.14", "AC.7"], "tsc": ["CC6.1", "CC6.8", "CC7.2", "CC7.3"]},
    "9700": {"level": 0, "description": "Dovecot Messages Grouped.", "groups": ["dovecot"]},
    "9701": {"level": 3, "description": "Dovecot Authentication Success.",
             "groups": ["dovecot", "authentication_success"],
             "pci_dss": ["10.2.5"], "gpg13": ["7.1", "7.2"], "gdpr": ["IV_32.2"],
             "hipaa": ["164.312.b"], "nist_800_53": ["AU.14", "AC.7"],
             "tsc": ["CC6.8", "CC7.2", "CC7.3"]},
    "20101": {"level": 6, "description": "IDS event.", "groups": ["ids"]},
    "31100": {"level": 0, "description": "Access log messages grouped.",
              "groups": ["web", "accesslog"]},
    "31101": {"level": 5, "description": "Web server 400 error code.",
              "groups": ["web", "accesslog", "attack"],
              "pci_dss": ["6.5", "11.4"], "gdpr": ["IV_35.7.d"],
              "nist_800_53": ["SA.11", "SI.4"],
              "tsc": ["CC6.6", "CC7.1", "CC8.1", "CC6.1", "CC6.8", "CC7.2", "CC7.3"]},
    "31102": {"level": 0, "description": "Ignored extensions on 400 error codes.",
              "groups": ["web", "accesslog"]},
    "31108": {"level": 0, "description": "Ignored URLs (simple queries).",
              "groups": ["web", "accesslog"]},
    "31120": {"level": 5, "description": "Web server 500 error code (server error).",
              "groups": ["web", "accesslog"]},
    "31121": {"level": 4, "description": "Web server 501 error code (Not Implemented).",
              "groups": ["web", "accesslog"]},
    "31122": {"level": 5, "description": "Web server 500 error code (Internal Error).",
              "groups": ["web", "accesslog", "system_error"]},
    "31123": {"level": 4, "description": "Web server 503 error code (Service unavailable).",
              "groups": ["web", "accesslog"]},
    "30100": {"level": 0, "description": "Apache messages grouped.", "groups": ["apache"]},
    "30301": {"level": 0, "description": "Apache error messages grouped.", "groups": ["apache"]},
    "30302": {"level": 0, "description": "Apache warn messages grouped.", "groups": ["apache"]},
    "30305": {"level": 5, "description": "Apache: Attempt to access forbidden file or directory.",
              "groups": ["apache", "access_denied"],
              "pci_dss": ["6.5.8", "10.2.4"], "gdpr": ["IV_35.7.d"], "hipaa": ["164.312.b"],
              "nist_800_53": ["SA.11", "AU.14", "AC.7"],
              "tsc": ["CC6.6", "CC7.1", "CC6.1", "CC6.8", "CC7.2", "CC7.3"]},
    "30306": {"level": 5, "description": "Apache: Attempt to access forbidden directory index.",
              "groups": ["apache", "access_denied"],
              "pci_dss": ["6.5.8", "10.2.4"], "gdpr": ["IV_35.7.d"], "hipaa": ["164.312.b"],
              "nist_800_53": ["SA.11", "AU.14", "AC.7"],
              "tsc": ["CC6.6", "CC7.1", "CC6.1", "CC6.8", "CC7.2", "CC7.3"]},
    "30318": {"level": 5, "description": "Apache: PHP Notice in Apache log", "groups": ["apache"]},
    "52501": {"level": 0, "description": "ClamAV: database update",
              "groups": ["clamd", "freshclam", "virus"]},
    "52507": {"level": 3, "description": "ClamAV database update",
              "groups": ["clamd", "freshclam", "virus"],
              "pci_dss": ["5.2"], "tsc": ["A1.2"], "nist_800_53": ["SI.3"],
              "gpg13": ["4.4"], "gdpr": ["IV_35.7.d"]},
    "52508": {"level": 3, "description": "ClamAV database updated",
              "groups": ["clamd", "freshclam", "virus"],
              "pci_dss": ["5.2"], "tsc": ["A1.2"], "nist_800_53": ["SI.3"],
              "gpg13": ["4.4"], "gdpr": ["IV_35.7.d"]},
    "80700": {"level": 0, "description": "Audit: messages grouped.", "groups": ["audit"]},
    "81800": {"level": 0, "description": "OpenVPN messages grouped.", "groups": ["openvpn"]},
    "81801": {"level": 3, "description": "OpenVPN: User logged in",
              "groups": ["openvpn", "authentication_success"],
              "pci_dss": ["10.2.5"], "gpg13": ["7.1", "7.2"], "gdpr": ["IV_32.2"],
              "hipaa": ["164.312.b"], "nist_800_53": ["AU.14", "AC.7"],
              "tsc": ["CC6.8", "CC7.2", "CC7.3"]},
    "81803": {"level": 4, "description": "OpenVPN: Connection Certificate Failed",
              "groups": ["openvpn", "openvpn-error"], "gdpr": ["IV_35.7.d"]},
}

_COMPLIANCE_KEYS = ("pci_dss", "gpg13", "gdpr", "hipaa", "nist_800_53", "tsc")


def make_rule(rule_id: str, fired: int) -> dict:
    d = RULE_DEFS[rule_id]
    r = {"firedtimes": fired, "mail": False, "level": d["level"]}
    for ck in _COMPLIANCE_KEYS:
        if ck in d:
            r[ck] = d[ck]
    r["description"] = d["description"]
    r["groups"] = d["groups"]
    r["id"] = rule_id
    return r


# --------------------------------------------------------------------------- #
# Agent map (authoritative IP -> id/name from the prefix's native Wazuh dump). #
# --------------------------------------------------------------------------- #
def build_agent_map(wazuh_path: str) -> dict:
    amap = {}
    with open(wazuh_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                a = json.loads(line).get("agent", {})
            except json.JSONDecodeError:
                continue
            ip = a.get("ip")
            if ip and ip not in amap:
                amap[ip] = {"id": a.get("id"), "name": a.get("name", "wazuh-client")}
    return amap


class AgentResolver:
    def __init__(self, amap: dict):
        self.amap = dict(amap)
        known = [int(v["id"]) for v in amap.values() if str(v["id"]).isdigit()]
        self._next = max(known) + 1 if known else 100

    def resolve(self, ip: str) -> dict:
        if ip not in self.amap:
            self.amap[ip] = {"id": str(self._next), "name": "wazuh-client"}
            self._next += 1
        a = self.amap[ip]
        return {"ip": ip, "name": a["name"], "id": a["id"]}


# --------------------------------------------------------------------------- #
# Event-time parsing (take the time from the raw log, as Wazuh does).         #
# --------------------------------------------------------------------------- #
MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
     "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], start=1)}

RE_SYSLOG = re.compile(r"^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\s")
RE_APACHE_ACCESS = re.compile(r"\[(\d{2})/([A-Z][a-z]{2})/(\d{4}):(\d{2}):(\d{2}):(\d{2})\s")
RE_APACHE_ERROR = re.compile(
    r"^\[[A-Z][a-z]{2}\s+([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\.(\d+)\s+(\d{4})\]")
RE_SURICATA = re.compile(r"^(\d{2})/(\d{2})/(\d{4})-(\d{2}):(\d{2}):(\d{2})\.(\d+)")
RE_ISO_SPACE = re.compile(r"^(\d{4})-(\d{2})-(\d{2})\s(\d{2}):(\d{2}):(\d{2})")


def _utc(dt: datetime) -> datetime:
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)


def parse_event_time(raw: str, location: str, fallback_epoch: float):
    """Return (datetime_utc, predecoder_timestamp | None)."""
    fb_year = datetime.fromtimestamp(fallback_epoch, tz=timezone.utc).year if fallback_epoch else 2022

    if raw.startswith("{"):
        try:
            ts = json.loads(raw).get("@timestamp")
            if ts:
                return _utc(datetime.strptime(ts.replace("Z", "+0000"),
                                              "%Y-%m-%dT%H:%M:%S.%f%z")), None
        except (json.JSONDecodeError, ValueError):
            pass

    m = RE_SURICATA.match(raw)
    if m:
        mo, d, y, hh, mm, ss, frac = m.groups()
        return datetime(int(y), int(mo), int(d), int(hh), int(mm), int(ss),
                        int((frac + "000000")[:6]), tzinfo=timezone.utc), raw[:m.end()]

    m = RE_APACHE_ERROR.match(raw)
    if m:
        mon, d, hh, mm, ss, frac, y = m.groups()
        return datetime(int(y), MONTHS[mon], int(d), int(hh), int(mm), int(ss),
                        int((frac + "000000")[:6]), tzinfo=timezone.utc), None

    m = RE_APACHE_ACCESS.search(raw)
    if m:
        d, mon, y, hh, mm, ss = m.groups()
        return datetime(int(y), MONTHS[mon], int(d), int(hh), int(mm), int(ss),
                        tzinfo=timezone.utc), None

    m = RE_ISO_SPACE.match(raw)
    if m:
        y, mo, d, hh, mm, ss = m.groups()
        return datetime(int(y), int(mo), int(d), int(hh), int(mm), int(ss),
                        tzinfo=timezone.utc), None

    m = RE_SYSLOG.match(raw)
    if m:
        mon, d, hh, mm, ss = m.groups()
        return datetime(fb_year, MONTHS[mon], int(d), int(hh), int(mm), int(ss),
                        tzinfo=timezone.utc), raw[:m.end() - 1]

    return datetime.fromtimestamp(fallback_epoch, tz=timezone.utc), None


def iso_z(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond:06d}Z"


# --------------------------------------------------------------------------- #
# Syslog header parsing.                                                      #
# --------------------------------------------------------------------------- #
RE_SYSLOG_HDR = re.compile(r"^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+(?P<rest>.*)$")
RE_PROG = re.compile(r"^(?P<prog>[\w./\-]+)(?:\[\d+\])?:\s")


def parse_syslog_header(raw: str):
    """Return (hostname|None, program_name|None)."""
    m = RE_SYSLOG_HDR.match(raw)
    if not m:
        return None, None
    rest = m.group("rest")
    pm = RE_PROG.match(rest)
    if pm:
        return None, pm.group("prog")
    parts = rest.split(None, 1)
    prog = None
    if len(parts) > 1:
        pm = RE_PROG.match(parts[1])
        if pm:
            prog = pm.group("prog")
    return parts[0], prog


# --------------------------------------------------------------------------- #
# Field extractors + rule selection (native Wazuh decoders/rules).            #
# --------------------------------------------------------------------------- #
RE_WEB = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[[^\]]+\]\s+"(?P<req>[^"]*)"\s+'
    r'(?P<status>\d{3}|-)\s+\S+\s+"[^"]*"\s+"[^"]*"')
STATIC_EXT = (".jpg", ".jpeg", ".gif", ".png", ".css", ".js")
RE_SNORT = re.compile(
    r"\[\*\*\]\s+\[(?P<sid>\d+:\d+:\d+)\].*?\{\w+\}\s+"
    r"(?P<src>\d+\.\d+\.\d+\.\d+):\d+\s+->\s+(?P<dst>\d+\.\d+\.\d+\.\d+:\d+)")
RE_AUDIT_TYPE = re.compile(r"^type=(\S+)\s")
RE_AUDIT_ID = re.compile(r"msg=audit\([0-9.]+:(\d+)\)")


def web_rule_id(status: int, url: str) -> str:
    if 400 <= status <= 499:
        u = url.lower().split("?", 1)[0]
        if u.endswith(STATIC_EXT) or u.endswith("favicon.ico") or u.endswith("robots.txt"):
            return "31102"
        return "31101"
    if status == 501:
        return "31121"
    if status == 500:
        return "31122"
    if status == 503:
        return "31123"
    if 500 <= status <= 599:
        return "31120"
    if 200 <= status <= 399:
        return "31108"
    return "31100"


def build_web_access(raw: str, location: str):
    line = raw
    if location.endswith("other_vhosts_access.log") and " " in raw:
        line = raw.split(" ", 1)[1]
    m = RE_WEB.match(line)
    data, status, url = None, 0, "-"
    if m:
        req, status_s = m.group("req"), m.group("status")
        url = req.split(" ")[1] if " " in req else "-"
        status = int(status_s) if status_s.isdigit() else 0
        data = {"srcip": m.group("ip"), "id": status_s, "url": url}
    return {"name": "web-accesslog"}, web_rule_id(status, url), data


def build_apache_error(raw: str):
    data = None
    mip = re.search(r"\[client (\d+\.\d+\.\d+\.\d+)", raw)
    if mip:
        data = {"srcip": mip.group(1)}
    if "AH01630" in raw:
        rid = "30305"
    elif "AH01276" in raw:
        rid = "30306"
    elif "PHP Notice" in raw:
        rid = "30318"
    elif re.search(r"\[[^\]]*warn\]", raw):
        rid = "30302"
    elif re.search(r"\[[^\]]*error\]", raw):
        rid = "30301"
    elif BAD_WORDS.search(raw):
        rid = "1002"
    else:
        rid = "30100"
    return {"name": "apache-errorlog"}, rid, data


def build_audit(raw: str):
    audit = {}
    mt = RE_AUDIT_TYPE.match(raw)
    if mt:
        audit["type"] = mt.group(1)
    mid = RE_AUDIT_ID.search(raw)
    if mid:
        audit["id"] = mid.group(1)
    for key in ("pid", "uid", "auid", "ses", "res", "terminal", "exe", "acct", "op"):
        m = re.search(rf'\b{key}=(?:"([^"]*)"|(\S+?))(?:\s|\')', raw)
        if m:
            audit[key] = m.group(1) if m.group(1) is not None else m.group(2)
    return {"name": "auditd"}, "80700", ({"audit": audit} if audit else None)


def build_suricata_fast(raw: str):
    m = RE_SNORT.search(raw)
    data = ({"srcip": m.group("src"), "dstip": m.group("dst"), "id": m.group("sid")}
            if m else None)
    return {"parent": "snort", "name": "snort"}, "20101", data


def generic_rule_id(raw: str) -> str:
    return "1002" if BAD_WORDS.search(raw) else "1"


def reconstruct(raw: str, location: str):
    """Return (predecoder|None, decoder|None, rule_id, data|None) for a raw log line."""
    base = os.path.basename(location)

    if base.endswith("access.log") or "access-access" in base:
        decoder, rid, data = build_web_access(raw, location)
        return None, decoder, rid, data

    if "error" in base and base.endswith(".log"):
        decoder, rid, data = build_apache_error(raw)
        return None, decoder, rid, data

    if location.endswith("/suricata/fast.log"):
        _, pre_ts = parse_event_time(raw, location, 0)
        decoder, rid, data = build_suricata_fast(raw)
        return ({"timestamp": pre_ts} if pre_ts else None), decoder, rid, data

    if location.endswith("/audit/audit.log") or raw.startswith("type="):
        decoder, rid, data = build_audit(raw)
        return None, decoder, rid, data

    if raw.startswith("{"):
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            data = None
        return None, {"name": "json"}, generic_rule_id(raw), data

    if location.endswith("/exim4/mainlog"):
        return None, {"name": "windows-date-format"}, generic_rule_id(raw), None

    if location.endswith("/openvpn.log"):
        if "Peer Connection Initiated with" in raw:
            rid = "81801"
        elif "TLS Error" in raw or "TLS Auth Error" in raw:
            rid = "81803"
        else:
            rid = "1002" if BAD_WORDS.search(raw) else "81800"
        return None, {"name": "openvpn"}, rid, None

    host, prog = parse_syslog_header(raw)
    predecoder = None
    if host or prog:
        _, pre_ts = parse_event_time(raw, location, 0)
        predecoder = {}
        if host:
            predecoder["hostname"] = host
        if prog:
            predecoder["program_name"] = prog
        if pre_ts:
            predecoder["timestamp"] = pre_ts

    if prog == "freshclam":
        if "update process started" in raw:
            rid = "52507"
        elif "Database updated" in raw:
            rid = "52508"
        else:
            rid = "52501"
        return predecoder, {"name": "freshclam"}, rid, None

    if "pam_unix" in raw:
        if "session opened for user" in raw:
            rid = "5501"
        elif "session closed for user" in raw:
            rid = "5502"
        else:
            rid = "5500"
        return predecoder, {"name": "pam"}, rid, None

    if prog == "dovecot" or location.endswith(("/mail.log", "/mail.info")):
        rid = "9701" if "Login: " in raw else "9700"
        return predecoder, {"name": "dovecot"}, rid, None

    if prog == "HORDE" or "HORDE:" in raw:
        if "Login success for" in raw:
            rid = "9305"
        elif "FAILED LOGIN" in raw:
            rid = "9306"
        else:
            rid = "1002" if BAD_WORDS.search(raw) else "9300"
        return predecoder, {"name": "horde_imp"}, rid, None

    if prog and prog.startswith("kernel"):
        return predecoder, {"name": "kernel"}, "5100", None

    decoder = {"name": prog} if prog else {"name": "syslog"}
    return predecoder, decoder, generic_rule_id(raw), None


# --------------------------------------------------------------------------- #
# Streaming document producers.                                               #
# --------------------------------------------------------------------------- #
def iter_wazuh_docs(wazuh_path: str, stats: dict):
    """Yield wrapped OpenSearch docs for each native Wazuh alert line."""
    with open(wazuh_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            source = json.loads(line)
            stats["wazuh"] += 1
            yield wrap(source)


def iter_aminer_docs(aminer_path: str, resolver: AgentResolver, labels_fh, stats: dict):
    """Convert each AMiner event to a native Wazuh alert; write its ground-truth
    label; yield the wrapped OpenSearch doc."""
    firedtimes = collections.Counter()
    with open(aminer_path, "r", encoding="utf-8") as f:
        for i, line in enumerate(f):
            line = line.strip()
            if not line:
                continue
            ev = json.loads(line)
            ld = ev.get("LogData", {})
            ac = ev.get("AnalysisComponent", {})

            raw = (ld.get("RawLogData") or [""])[0]
            location = (ld.get("LogResources") or ["/var/log/syslog"])[0]
            ts_list = ld.get("Timestamps") or ld.get("DetectionTimestamp") or [0]
            fallback_epoch = float(ts_list[0]) if ts_list else 0.0
            host_ip = ev.get("AMiner", {}).get("ID", "0.0.0.0")

            dt, _ = parse_event_time(raw, location, fallback_epoch)
            predecoder, decoder, rule_id, data = reconstruct(raw, location)
            firedtimes[rule_id] += 1

            source = {}
            if predecoder:
                source["predecoder"] = predecoder
            source["agent"] = resolver.resolve(host_ip)
            source["manager"] = {"name": "wazuh.manager"}
            if data is not None:
                source["data"] = data
            source["rule"] = make_rule(rule_id, firedtimes[rule_id])
            if decoder is not None:
                source["decoder"] = decoder
            # JSON-decoded events (Suricata eve.json, metricbeat, ...) carry the
            # parsed body in `data` and have no `full_log` in native Wazuh; text
            # decoders carry the raw line in `full_log`. Mirror that here.
            if not (decoder and decoder.get("name") == "json"):
                source["full_log"] = raw
            source["input"] = {"type": "log"}
            source["@timestamp"] = iso_z(dt)
            source["location"] = location
            source["id"] = f"{ALERT_ID_EPOCH}.{ALERT_ID_SEQ_START + i}"

            label = {
                "id": source["id"], "anomalous": True,
                "detector_type": ac.get("AnalysisComponentType"),
                "detector_id": ac.get("AnalysisComponentIdentifier"),
                "detector_name": ac.get("AnalysisComponentName"),
                "message": ac.get("Message"),
                "training_mode": ac.get("TrainingMode"),
                "affected_paths": ac.get("AffectedLogAtomPaths"),
                "affected_values": ac.get("AffectedLogAtomValues"),
            }
            for opt in ("CriticalValue", "ProbabilityThreshold", "Range"):
                if opt in ac:
                    label[opt.lower()] = ac[opt]
            labels_fh.write(json.dumps(label) + "\n")
            stats["aminer"] += 1
            yield wrap(source)


def _ts_key(doc: dict) -> str:
    return doc["_source"].get("@timestamp", "")


def process_prefix(prefix: str, wazuh_path: str, aminer_path: str) -> dict:
    out_path = os.path.join(OUTPUT_DIR, f"{prefix}_wazuh.json")
    labels_path = os.path.join(OUTPUT_DIR, f"{prefix}_aminer.labels.json")
    stats = {"wazuh": 0, "aminer": 0}

    resolver = AgentResolver(build_agent_map(wazuh_path)) if aminer_path else None
    labels_fh = open(labels_path, "w", encoding="utf-8") if aminer_path else None
    try:
        streams = [iter_wazuh_docs(wazuh_path, stats)]
        if aminer_path:
            streams.append(iter_aminer_docs(aminer_path, resolver, labels_fh, stats))
        with open(out_path, "w", encoding="utf-8") as fout:
            # Both streams are time-ordered; heapq.merge interleaves them by
            # @timestamp without ever holding more than one doc per stream in memory.
            for doc in heapq.merge(*streams, key=_ts_key):
                fout.write(json.dumps(doc) + "\n")
    finally:
        if labels_fh:
            labels_fh.close()
    stats["out_path"] = out_path
    stats["labels_path"] = labels_path if aminer_path else None
    return stats


def main() -> None:
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    wazuh_files = sorted(glob.glob(os.path.join(INPUT_DIR, "*_wazuh.json")))
    if not wazuh_files:
        print(f"No *_wazuh.json files found in {INPUT_DIR!r}")
        return

    for wazuh_path in wazuh_files:
        prefix = os.path.basename(wazuh_path)[:-len("_wazuh.json")]
        aminer_path = os.path.join(INPUT_DIR, f"{prefix}_aminer.json")
        if not os.path.exists(aminer_path):
            aminer_path = None
        print(f"Processing {prefix}: {wazuh_path}"
              + (f" + {aminer_path}" if aminer_path else " (no aminer sibling)"))
        s = process_prefix(prefix, wazuh_path, aminer_path)
        total = s["wazuh"] + s["aminer"]
        print(f"  wrote {total} alerts ({s['wazuh']} wazuh + {s['aminer']} aminer) "
              f"-> {s['out_path']}")
        if s["labels_path"]:
            print(f"  labels -> {s['labels_path']}")


if __name__ == "__main__":
    main()
