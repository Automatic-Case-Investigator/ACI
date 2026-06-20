import re, sys
sys.stdout.reconfigure(encoding='utf-8', errors='replace')

_NEW_LEADS_RE = re.compile(
    r"-\s+title:\s*[\"']?(.+?)[\"']?\s*\n"
    r"(?:[ \t]*\n)*"
    r"\s+pivots:\s*(.+?)\s*\n"
    r"(?:[ \t]*\n)*"
    r"\s+priority:\s*(\d+)",
    re.MULTILINE,
)
_NEW_LEADS_HEADER_RE = re.compile(
    r"(?:^|\n)(?:#{2,3}\s*|(?:\*\*))New Leads(?:\*\*)?\s*\n",
    re.IGNORECASE,
)

samples = [
    ("none placeholder",          "## New Leads\n- None.\n"),
    ("valid lead",                 '## New Leads\n- title: "What is 10.0.2.5?"\n  pivots: IP=10.0.2.5, time=2025-04-20T03:40Z\n  priority: 90\n'),
    ("blank lines between fields", "## New Leads\n- title: Check C2 IP\n\n  pivots: IP=10.0.2.5\n\n  priority: 85\n"),
    ("no quotes on title",         "## New Leads\n- title: Is 10.0.2.5 a known C2?\n  pivots: IP=10.0.2.5\n  priority: 88\n"),
    ("h3 header",                  "### New Leads\n- title: Check lateral movement\n  pivots: host=10.0.2.15\n  priority: 75\n"),
    ("bold header",                "**New Leads**\n- title: Check lateral movement\n  pivots: host=10.0.2.15\n  priority: 75\n"),
    ("two leads",                  "## New Leads\n- title: Investigate C2\n  pivots: IP=10.0.2.5\n  priority: 90\n- title: Check sudo history\n  pivots: user=user, host=10.0.2.15\n  priority: 80\n"),
]

def main():
    all_pass = True
    for name, text in samples:
        m = _NEW_LEADS_HEADER_RE.search(text)
        section = text[m.end():].split("\n##")[0] if m else ""
        leads = _NEW_LEADS_RE.findall(section) if section else []
        expected_none = name == "none placeholder"
        ok = (len(leads) == 0) if expected_none else (len(leads) >= 1)
        if not ok:
            all_pass = False
        status = "PASS" if ok else "FAIL"
        print(f"{status}  {name:30s}  header={bool(m)}  leads={[(t, p) for t,_,p in leads]}")

    print(f"\n{'ALL PASS' if all_pass else 'SOME FAILURES'}")
    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())
