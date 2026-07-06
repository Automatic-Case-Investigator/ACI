# Incident Response Playbook (shared)

This playbook maps each phase of the intrusion lifecycle to the questions an analyst must answer, the SIEM pivots that answer them, and the adjacent phases to trace. A single alert almost always sits in the **middle** of the chain — identify its phase(s), then work outward in both directions.

**How to use it**

- **Triage** — match the case to one or more phases below. Turn each matched phase's **Confirm** questions and **Pivots** into numbered `## Investigation Plan` items, each with an evidence source and a priority (see the priority ladder in your reporting spec). Always include the backward item from **Trace next** when the case involves access, execution, or persistence.
- **Investigation** — when a task confirms activity at a phase, use that phase's **Pivots** to choose your SIEM queries and its **Confirm** questions plus **Trace next** to generate `## New Leads`. **Trace next** is how you satisfy mandatory both-direction coverage: open a lead toward every adjacent phase not yet established.

Pivot fields below are generic; consult the SIEM MCP guidance for exact field names. Common pivot keys: source/destination IP, account, host, process/parent, file path, hash, domain, session/TTY, rule family, time window.

---

## Reconnaissance / Discovery
- **Triggers:** scanning, enumeration commands (`whoami`, `id`, `uname`, `netstat`, `ss`, `arp`, `nmap`), repeated 404/permission-denied, host/service sweeps.
- **Confirm:** What was enumerated (hosts, accounts, services, files)? From which account/host? Single actor or automated? Did recon precede a successful access?
- **Pivots:** discovery/audit-command events for the host; group recon commands by session/TTY/account; correlate the recon source IP against later auth events.
- **Trace next:** forward → initial access attempts from the same source; backward → how the recon actor got on the host (if internal).

## Active / Vulnerability Scanning (automated tooling)
- **Triggers / signatures:** automated scanners leave distinctive, high-volume traces. Common ones (confirm exact IDs against your ruleset):
  - **Port/service scan (nmap):** `ET SCAN Possible Nmap User-Agent Observed` (HTTP), and `sshd: insecure connection attempt (scan)` / "Did not receive identification string" (SSH banner-grab failure). The same `data.srcip` tripping *both* an HTTP UA signature and an SSH banner-grab is the textbook `-sV` version scan.
  - **WordPress scan (WPScan):** web 400/forbidden events whose `full_log` carries a `WPScan v… (wpscan.com)` user-agent; thousands of hits collapse into a "multiple web 4xx from same source ip" correlation rule.
  - **Directory/file brute force (dirb/gobuster/feroxbuster):** a flood of `Apache: Attempt to access forbidden file or directory` / `client denied by server configuration` / 404s for dictionary paths from one `data.srcip` — often hundreds of thousands of events rolling into one correlation rule.
- **Confirm:** Which tool (from the user-agent / pattern)? One `data.srcip` or many? What was probed (services, WP paths, directories)? **Did the scan transition to a hit** — a 200/302 success, a successful login, or a spawned process — after the noise?
- **Pivots — AGGREGATE, do not enumerate.** These steps generate 10k–500k near-identical events; never page through them one by one (it burns the whole budget). Use `get_event_volume` to get the scan's start/end/cadence, and `profile_field` on `rule.groups` **first** (the behavior-class distribution — this is how you find the payload/webshell hiding in the same `web` class under a *different* rule than the scan), then on `data.url` / `http.user_agent` to characterize the scan itself. Do not lead with `rule.id`: the scan's own rule is the noise, and filtering to it excludes the very follow-on you are hunting. Pin the scanner with `correlate_entity` on its `data.srcip` to surface what else it touched. A raw `search` only to grab 1–2 representative events to cite.
- **The finding is in the tail, not the spike.** The scan is setup noise; the exploitation, webshell call, credential access, or privilege escalation almost always sits in the quiet tail minutes-to-hours after the burst ends, not in its densest bucket. Profile the full window, locate where the burst ends and each later cluster, and query those tail windows for what the same `data.srcip`/host did once it stopped scanning.
- **Trace next:** forward (highest priority) → the **same `data.srcip` in success events and in the post-spike tail** — a 200/302 after the 4xx flood, an `authentication_success`, a service-account child process, or any activity from that source after the burst = the scan found its way in; backward → TI/origin of the scanning IP, and whether it also appears as a C2 destination.

## Initial Access — Brute force / password spraying
- **Triggers:** bursts of authentication failures, many accounts from one source, one password across many accounts.
- **Confirm:** Did **any** login from the source succeed (success after failures)? How many accounts targeted? Is the source a known offender (TI)? Which service (SSH/RDP/web/app)?
- **Pivots:** auth-failure rule families filtered by `data.srcip`; then the **same `data.srcip` in success events** to find the breakthrough; count distinct `data.dstuser`; TI-enrich the source IP.
- **Trace next:** forward → the session/commands run after the successful login; backward → source IP origin / TI / does it also appear as a C2 destination.

## Initial Access — Exploitation of a public-facing / remote service
- **Triggers:** web/app errors then anomalous child process, unexpected process spawned by a service account (web server, db), webshell writes.
- **Confirm:** Which service/CVE? What request triggered it? Did it spawn a shell or write a file? Source IP of the request?
- **Pivots:** processes whose parent is a service daemon; file writes under web roots (FIM); web/proxy logs for the source IP and the triggering request; correlate request time to the spawned process.
- **Trace next:** forward → execution/persistence from the spawned process; backward → the external source IP and request.

## Initial Access — Phishing / malicious download (delivery)
- **Triggers:** download from external host followed by execution, office/browser child processes, files written to user temp/download dirs.
- **Confirm:** What was delivered and from where (URL/domain/IP)? Who opened it? Did it execute? Hash/signing status?
- **Pivots:** download origin domain/IP (DNS + connection logs, TI); file hash prevalence; process lineage from the opening application; FIM for the dropped file path.
- **Trace next:** forward → execution and C2 from the dropped file; backward → delivery infrastructure (domain/IP/sender).

## Execution — Suspicious command / script / interpreter
- **Triggers:** shells/interpreters with unusual arguments, encoded/obfuscated commands, `sh -c`, `bash -i`, `powershell -enc`, download-and-run one-liners.
- **Confirm:** Exact command line (decode any encoding)? Parent process and account? What did it do (file, network, child processes)? One-off or repeated?
- **Pivots:** audit/process-execution events by command and account; decode hex/base64 arguments; parent→child lineage; network activity by the executing PID.
- **Trace next:** backward → how the command was launched (access vector, scheduler, parent); forward → C2/persistence/impact it produced.

## Persistence — cron / scheduled task / startup / service / account
- **Triggers:** crontab edits, systemd unit/timer changes, run-key/startup-folder writes, new service, new/modified account or `authorized_keys`.
- **Confirm:** Exact mechanism and **the exact content installed** (the scheduled command, unit ExecStart, key)? Did it execute? Does it call out (C2)? Installed by which account/session?
- **Pivots:** **FIM/syscheck diff of the persistence file** (do not conclude on the editor-execution event alone); scheduler/service rule families; correlate install time to later execution of the installed command; extract IPs/domains/commands embedded in the content and pivot each.
- **Trace next:** backward → who installed it and how they got the access/privilege; forward → execution of the payload and its C2/impact.

## Privilege Escalation
- **Triggers:** `sudo`/`su`/`pkexec` to root, setuid abuse, exploit followed by uid=0 activity, new admin-group membership.
- **Confirm:** How was elevation obtained (legit sudo vs exploit)? Which account → which privilege? What was done as the elevated user? Expected admin or anomalous?
- **Pivots:** privilege-escalation and PAM session-open rule families by account; map elevated session to the commands run within it (session/TTY); compare to the account's baseline.
- **Trace next:** backward → the account's initial access / how credentials were obtained; forward → privileged actions (persistence, defense evasion, collection).

## Defense Evasion — log/audit tampering, security-tool interference, anti-forensics
- **Triggers:** audit ruleset changes (`auditctl`), security-agent stop/restart, log clearing/truncation, history wipe, config edits to monitoring tools.
- **Confirm:** What protection was changed/disabled and when? By which account/session? Does it create a blind spot overlapping other activity? Reversed afterward?
- **Pivots:** config-change and FIM events on monitoring/audit configs; service stop/restart events for security tools; correlate the tampering window against other confirmed activity (what it may hide).
- **Trace next:** backward → the privilege used to tamper; forward → activity inside the created blind spot (assume telemetry gaps there).

## Credential Access
- **Triggers:** access to credential stores (`/etc/shadow`, SAM, LSASS, keyrings, browser stores), dumping tools, suspicious reads of secret files.
- **Confirm:** Which credential store was accessed and by whom? Were credentials exfiltrated or reused? Which accounts are now suspect?
- **Pivots:** file-access/FIM on credential paths; process access to credential memory; then trace any **accounts** read here into subsequent auth/lateral events.
- **Trace next:** forward → lateral movement / new logins using stolen creds; backward → how the actor reached the credential store.

## Lateral Movement
- **Triggers:** internal logins from a compromised host, remote-exec (SSH/SMB/WMI/RDP/psexec), one account authenticating to many hosts.
- **Confirm:** Initial access vector to the next host? Which credentials? Blast radius (how many hosts/accounts)? Pivot host identified?
- **Pivots:** authentication **success** events grouped by `data.srcip`/account across hosts; remote-session rule families; build the host-to-host graph from shared account/source IP.
- **Trace next:** backward → the source host/account and how it was compromised; forward → actions on each newly reached host.

## Command & Control
- **Triggers:** reverse shells (`/dev/tcp/`, `nc -e`, `bash -i`), beaconing, connections to rare/external destinations, DNS tunneling.
- **Confirm:** C2 address/domain and port? Did the callback **connect/succeed**? Is the C2 IP also the initial-access source (same actor)? Beacon cadence?
- **Pivots:** the C2 IP/domain in **both roles** — `data.dstip` (outbound callbacks) **and** `data.srcip` (inbound logins/auth — initial-access match); TI-enrich the address; listener/connection events on the involved hosts.
- **Trace next:** backward → how the C2 mechanism was installed (execution/persistence) and whether C2==initial-access source; forward → commands executed over C2, lateral movement, exfiltration.

## Collection & Exfiltration
- **Triggers:** data staging (archives, large temp files), outbound transfers, cloud-storage/uploads, unusual outbound volume.
- **Confirm:** What data (paths/types)? Staged where? Transferred to which destination? Volume? Succeeded?
- **Pivots:** file-creation of archives/staging dirs (FIM); outbound connections/byte-volume by host and destination; correlate staging time to transfer; TI-enrich the destination.
- **Trace next:** backward → how the actor located/accessed the data (discovery, credential access); forward → impact and cleanup.

## Impact
- **Triggers:** mass file modification/encryption, deletion, ransom notes, service/host disruption, account lockouts.
- **Confirm:** What was affected (files/services/hosts) and how widely? Recoverable? Account/process responsible? Still active?
- **Pivots:** high-rate FIM modify/delete events; service-stop and availability events; identify the responsible process/account and its entry point.
- **Trace next:** backward → the full chain that led here (this is usually the end of the kill chain — reconstruct the whole path); forward → containment scope.
