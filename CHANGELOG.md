# Changelog

All notable changes to this project are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project adheres to [Semantic Versioning](https://semver.org/).

## [2.2.0] - 2026-07-19

### Added
- **Interactive BloodHound-style attack-path graph** in the HTML report: a self-contained,
  dependency-free force-directed SVG graph rendering each `source → technique → … → Tier-0`
  chain as vectors. Nodes coloured by type (user/group/computer/domain), Tier-0 targets ringed
  in gold, directed edges labelled with the abused right. Supports drag, scroll-zoom and pan.
- Attack-graph node/edge model (`graph`) exposed in the `attack_paths()` result.

## [2.1.0] - 2026-07-19

### Added
- **ADCS attack detection** (ESC1, ESC2, ESC3, ESC4, ESC5, ESC6, ESC7, ESC8 style)
  over `certtemplates.json` / `enterprisecas.json`.
- **Offline attack-graph path-finding**: in-memory directed graph (MemberOf, ACEs,
  AdminTo, sessions, RBCD), reverse BFS from the Tier-0 set, shortest paths per
  non-admin principal, and **choke-point ranking** (edges to cut first).
- Domain analysis: `ms-DS-MachineAccountQuota`, legacy functional level, and
  **trusts without SID filtering**.
- New findings: krbtgt stale password (Golden Ticket window), privileged
  Kerberoasting (SPN + admincount), and disabled-but-privileged accounts.
- Attack paths + choke points surfaced in the TXT summary, JSON, and HTML reports.
- **Exploitation command hints** per finding (impacket / Certipy / bloodyAD / netexec /
  Rubeus, with `<placeholder>` values) surfaced in the summary, CSV, Markdown, JSON and HTML.
- **Cleartext credentials in LDAP attributes** detection (`userpassword`, `unixpassword`,
  `unicodepassword`, `sfupassword`) — collected by SharpHound and often plaintext.
- **Privileged-account-delegatable** detection (`admincount` without the "sensitive /
  cannot be delegated" flag).

### Fixed
- **UTF-8 BOM handling**: real SharpHound collections are frequently written with a BOM,
  which broke `json.load`. Files are now read with `utf-8-sig`. (Found by running against a
  real BloodHound CE collection.)
- De-duplicate privileged groups by name (BUILTIN vs domain groups sharing a name).

### Validated
- Tested end-to-end against a real BloodHound CE v5 collection (INLANEFREIGHT.HTB:
  33 users / 68 groups / 7 computers, 1200+ findings, both folder and `.zip` input).

## [2.0.0] - 2026-07-19

### Added
- **BloodHound Community Edition (SharpHound v2)** format support, alongside legacy.
- Direct **`.zip` archive** reading (no manual extraction).
- **ACL / ACE abuse analysis** — 18 dangerous rights, principals resolved SID→name,
  auto-escalation of rights against Tier-0 targets.
- Delegation coverage: unconstrained, constrained, and **RBCD**.
- Hygiene findings: PASSWD_NOTREQD, pwdneverexpires, stale accounts, secrets in the
  `description`/`info` field, SID history, end-of-life OS, missing LAPS.
- **Recursive** effective-member resolution for privileged / Tier-0 groups.
- 0–100 **risk score**.
- Real **CSV**, **HTML** report, and **Neo4j Cypher** hunting-pack exporters
  (previously advertised but unimplemented).
- Synthetic sample dataset, unit-test suite, and a standalone `cypher/queries.cypher`.

### Changed
- Rewrote `parseSharpHound.py` as a modular analyzer + exporter architecture.
- Rewrote the bilingual README.

## [1.0.0]

### Added
- Initial release: legacy SharpHound JSON parsing, basic Kerberoast / ASREPRoast /
  delegation / admincount counting, and TXT / JSON / Markdown export.
