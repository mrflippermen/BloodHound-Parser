```
   ██████╗ ██╗      ██████╗  ██████╗ ██████╗ ██╗  ██╗ ██████╗ ██╗   ██╗███╗   ██╗██████╗ 
   ██╔══██╗██║     ██╔═══██╗██╔═══██╗██╔══██╗██║  ██║██╔═══██╗██║   ██║████╗  ██║██╔══██╗
   ██████╔╝██║     ██║   ██║██║   ██║██║  ██║███████║██║   ██║██║   ██║██╔██╗ ██║██║  ██║
   ██╔══██╗██║     ██║   ██║██║   ██║██║  ██║██╔══██║██║   ██║██║   ██║██║╚██╗██║██║  ██║
   ██████╔╝███████╗╚██████╔╝╚██████╔╝██████╔╝██║  ██║╚██████╔╝╚██████╔╝██║ ╚████║██████╔╝
   ╚═════╝ ╚══════╝ ╚═════╝  ╚═════╝ ╚═════╝ ╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝╚═════╝ 
                        ██████╗  █████╗ ██████╗ ███████╗███████╗██████╗                  
                        ██╔══██╗██╔══██╗██╔══██╗██╔════╝██╔════╝██╔══██╗                 
                        ██████╔╝███████║██████╔╝███████╗█████╗  ██████╔╝                 
                        ██╔═══╝ ██╔══██║██╔══██╗╚════██║██╔══╝  ██╔══██╗                 
                        ██║     ██║  ██║██║  ██║███████║███████╗██║  ██║                 
                        ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝                 
```

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![BloodHound CE](https://img.shields.io/badge/BloodHound-CE%20%2B%20Legacy-red.svg)](https://github.com/SpecterOps/BloodHound)
[![Deps](https://img.shields.io/badge/dependencies-none-brightgreen.svg)](#requirements)
[![CI](https://github.com/mrflippermen/BloodHound-Parser/actions/workflows/ci.yml/badge.svg)](https://github.com/mrflippermen/BloodHound-Parser/actions/workflows/ci.yml)

> **Offline attack-path intelligence from BloodHound / SharpHound JSON — zero dependencies, one file.**

---

## 🇬🇧 English

### What it does

BloodHound gives you the graph. **BloodHound Parser turns a raw collection into a ranked,
report-ready list of what to attack first** — without spinning up Neo4j. Point it at a folder
**or a `.zip`**, and it parses, correlates and scores the whole collection offline.

Supports **both** collection formats automatically:
- **Legacy** SharpHound v1 (`version <= 4`)
- **BloodHound Community Edition** / SharpHound v2 (`version >= 5`, `.zip` archives)

### Features

| Category | Detections |
|---|---|
| **Kerberos** | Kerberoastable (`hasspn`/SPN), ASREPRoastable (`dontreqpreauth`) |
| **Delegation** | Unconstrained (user & computer), Constrained (`allowedToDelegate`), **RBCD** (`AllowedToAct`) |
| **ACL abuse** | GenericAll, GenericWrite, WriteDacl, WriteOwner, Owns, **AddKeyCredentialLink (Shadow Creds)**, ForceChangePassword, AddMember, AllExtendedRights, ReadLAPSPassword, ReadGMSAPassword, DCSync (GetChanges/All) — **principals resolved SID→name** |
| **ADCS** | ESC1, ESC2, ESC3, ESC4, ESC5, ESC6, ESC7, ESC8 (over `certtemplates`/`enterprisecas`), gated on templates actually published by a CA |
| **Domain** | `ms-DS-MachineAccountQuota` > 0, legacy functional level, **trusts without SID filtering** |
| **Hygiene** | PASSWD_NOTREQD, pwdneverexpires, stale accounts, **secrets in `description`/`info`**, **cleartext passwords in LDAP attrs** (`userpassword`/`unixpassword`/`unicodepassword`/`sfupassword`), **privileged-but-delegatable** accounts, SID history, end-of-life OS, missing LAPS, **krbtgt stale password**, **disabled-but-privileged**, **privileged Kerberoasting** (SPN + admincount) |
| **Tiering** | High-value / `admin_tier_0` detection; ACEs against Tier-0 targets are auto-escalated |
| **Membership** | **Recursive** effective-member resolution for privileged / Tier-0 groups |
| **Attack graph** | Offline in-memory graph (MemberOf + ACEs + AdminTo + sessions + RBCD), **reverse-BFS shortest paths to Tier-0**, and **choke-point ranking** (which edges to cut first) — no Neo4j needed |
| **Interactive graph** | The HTML report embeds a **BloodHound-style force-directed graph** of the attack chains (drag / zoom / pan, Tier-0 ringed in gold, edges labelled with the abused right) — self-contained, no external libraries |
| **Exploit hints** | Each finding ships a **ready-to-adapt exploitation command** (impacket, Certipy, bloodyAD, netexec, Rubeus…) in every export |
| **Scoring** | 0–100 risk score weighted by finding severity |

### Exports

`txt` · `json` · **`csv`** · `markdown` · **`html`** (styled report) · **`cypher`** (BloodHound CE hunting pack)

### Install

```bash
git clone https://github.com/mrflippermen/BloodHound-Parser.git
cd BloodHound-Parser
# No pip install needed — pure standard library.
```

### Usage

```bash
# Analyze a folder (all formats)
python src/parseSharpHound.py /path/to/bloodhound/output

# Read a .zip straight from SharpHound CE, write an HTML report
python src/parseSharpHound.py collection.zip -f html -o ./report

# CSV of findings only, custom stale window
python src/parseSharpHound.py ./bh -f csv --stale-days 90

# Just the Cypher hunting pack for BloodHound CE
python src/parseSharpHound.py ./bh -f cypher
```

```
positional arguments:
  source                Directory OR .zip containing SharpHound JSON files

options:
  -o, --output PATH     Output directory (default: alongside input)
  -f, --format FMT      txt | json | csv | markdown | html | cypher | all  (default: all)
  --output-format FMT   Name-list layout: column | comma  (default: column)
  --stale-days N        Inactivity threshold for stale accounts (default: 180)
  -v, --verbose         Debug logging
  -V, --version         Show version
```

### Sample output

```
==============================================================
  BLOODHOUND COLLECTION SUMMARY
  Format: BloodHound CE (v2+)   Risk score: 85/100
==============================================================
...
TOP CRITICAL FINDINGS:
  [CRITICAL] ACL: ForceChangePassword: HELPDESK@CORP.LOCAL -> ADMINISTRATOR@CORP.LOCAL
  [CRITICAL] ACL: GenericAll: HELPDESK@CORP.LOCAL -> WS-LEGACY01.CORP.LOCAL
  [CRITICAL] Unconstrained Delegation: DC01.CORP.LOCAL

PRIVILEGED GROUPS (effective members):
  - DOMAIN ADMINS@CORP.LOCAL: 2 member(s)
```

Try it now against the bundled synthetic dataset:

```bash
python src/parseSharpHound.py examples/sample_data -o /tmp/bh && cat /tmp/bh/resumen.txt
```

### Tests

```bash
python -m unittest discover -s tests -v      # 14 tests, stdlib only
# or: pip install pytest && pytest -q
```

### Project structure

```
BloodHound-Parser/
├── src/
│   ├── parseSharpHound.py     # parser + analyzers + attack graph + exporters
│   └── __init__.py
├── examples/
│   ├── sample_data/           # synthetic CE collection (users/computers/groups/domains/ADCS)
│   └── README.md
├── cypher/queries.cypher      # BloodHound CE hunting pack
├── tests/test_parser.py       # 20 unit tests
├── .github/workflows/ci.yml   # CI: ruff + mypy + tests (Linux/Windows, py3.8–3.12)
├── pyproject.toml             # packaging + `bh-parse` console script + ruff/pytest config
├── CHANGELOG.md · CONTRIBUTING.md · DISCLAIMER.md · LICENSE · README.md
```

### How it compares

| | This tool | PlumHound / GoodHound / AD-Miner |
|---|---|---|
| Needs a running Neo4j/BloodHound DB | **No** | Yes |
| Reads `.zip` directly | **Yes** | — |
| External dependencies | **None** | Several |
| ACL edge SID→name resolution offline | **Yes** | via DB |

It is **not** a graph engine — for full path-finding, load the collection into BloodHound
CE and use the bundled `cypher/queries.cypher`. This tool is the fast triage layer.

---

## 🇪🇸 Español

### Qué hace

BloodHound te da el grafo. **BloodHound Parser convierte una colección en una lista
priorizada y lista para reporte de qué atacar primero** — sin levantar Neo4j. Apúntalo a una
carpeta **o a un `.zip`** y analiza, correlaciona y puntúa toda la colección en local.

Detecta automáticamente **ambos formatos**: SharpHound v1 (legacy) y BloodHound Community
Edition / SharpHound v2 (`.zip`).

### Capacidades

- **Kerberos**: cuentas Kerberoastables y ASREPRoastables
- **Delegación**: sin restricciones, restringida y **RBCD** (delegación basada en recursos)
- **Abuso de ACLs**: GenericAll, WriteDacl, WriteOwner, **AddKeyCredentialLink (Shadow
  Credentials)**, ForceChangePassword, DCSync, ReadLAPSPassword… con **el principal resuelto
  de SID a nombre**
- **Higiene**: PASSWD_NOTREQD, contraseñas que nunca expiran, cuentas obsoletas,
  **secretos en el campo `description`**, historial de SID, SO fuera de soporte, sin LAPS
- **Tiering**: detección de objetivos de alto valor / `admin_tier_0` (los ACEs contra
  Tier-0 suben de severidad automáticamente)
- **Membresías recursivas** de grupos privilegiados
- **Puntuación de riesgo** 0–100
- **Exporta** a: txt, json, csv, markdown, **html** y **cypher** (pack para BloodHound CE)

### Uso rápido

```bash
python src/parseSharpHound.py /ruta/al/output            # carpeta, todos los formatos
python src/parseSharpHound.py coleccion.zip -f html -o ./reporte   # lee .zip -> HTML
python src/parseSharpHound.py ./bh -f csv --stale-days 90
```

---

## Requirements

- Python 3.8+
- **No external dependencies** — pure standard library.

## 🔒 Legal Disclaimer

**FOR AUTHORIZED SECURITY TESTING ONLY.** Use only on networks you own or have written
permission to test. The author assumes no liability for misuse. See [DISCLAIMER.md](DISCLAIMER.md).

## 📜 License

MIT — see [LICENSE](LICENSE).

## 👤 Author

**Esteban Jiménez** — 🏆 Top 1 Hack The Box Ecuador · Red Team Operator · AD Specialist
· [GitHub](https://github.com/mrflippermen)

## 🙏 Acknowledgments

SpecterOps BloodHound/SharpHound team · the AD security research community · MITRE ATT&CK.

---

**⚠️ Use responsibly. Happy hunting!**
