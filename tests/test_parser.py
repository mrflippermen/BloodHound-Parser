"""Unit tests for BloodHound Parser. Run with: python -m pytest -q (or unittest)."""
import sys
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from parseSharpHound import (  # noqa: E402
    SharpHoundParser, OutputExporter, Severity, exploit_hint,
)

SAMPLE = ROOT / "examples" / "sample_data"


class TestSharpHoundParser(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.parser = SharpHoundParser(SAMPLE)
        cls.parser.parse_all()

    def test_counts(self):
        s = self.parser.statistics
        self.assertEqual(s.total_users, 4)
        self.assertEqual(s.total_computers, 3)
        self.assertEqual(s.total_groups, 3)

    def test_format_detected_as_ce(self):
        self.assertIn("CE", self.parser.format_version)

    def test_kerberoastable(self):
        self.assertIn("SQLSERVICE@CORP.LOCAL", self.parser.kerberoastable_users)

    def test_asreproastable(self):
        self.assertIn("LEGACYUSER@CORP.LOCAL", self.parser.asreproastable_users)

    def test_secret_in_description(self):
        cats = [f for f in self.parser.findings if f.category == "Secret in description"]
        self.assertTrue(any("SQLSERVICE" in f.principal for f in cats))

    def test_unconstrained_delegation_computer_is_critical(self):
        f = [x for x in self.parser.findings
             if x.category == "Unconstrained Delegation" and "DC01" in x.principal]
        self.assertTrue(f and f[0].severity == Severity.CRITICAL)

    def test_rbcd_detected(self):
        self.assertTrue(any(f.category == "RBCD configured" for f in self.parser.findings))

    def test_eol_os(self):
        self.assertTrue(any("WS-LEGACY01" in f.principal and f.category == "End-of-life OS"
                            for f in self.parser.findings))

    def test_ace_forcechangepassword_resolves_principal(self):
        f = [x for x in self.parser.findings if x.category == "ACL: ForceChangePassword"]
        self.assertTrue(f)
        # Principal SID 1106 -> HELPDESK, target is Tier-0 Administrator (severity bumped).
        self.assertEqual(f[0].principal, "HELPDESK@CORP.LOCAL")
        self.assertEqual(f[0].severity, Severity.CRITICAL)  # HIGH bumped to CRITICAL for Tier-0

    def test_ace_genericall_on_computer(self):
        f = [x for x in self.parser.findings if x.category == "ACL: GenericAll"]
        self.assertTrue(any("WS-LEGACY01" in x.target for x in f))

    def test_recursive_group_membership(self):
        # DOMAIN ADMINS contains Administrator + (nested) IT-ADMINS -> HELPDESK
        members = self.parser.resolve_group_members("S-1-5-21-1111-2222-3333-512")
        self.assertIn("ADMINISTRATOR@CORP.LOCAL", members)
        self.assertIn("HELPDESK@CORP.LOCAL", members)

    def test_risk_score_positive(self):
        self.assertGreater(self.parser.risk_score(), 0)

    def test_adcs_esc1_detected(self):
        self.assertTrue(any(f.category == "ADCS ESC1" for f in self.parser.findings))

    def test_adcs_esc6_detected(self):
        self.assertTrue(any(f.category == "ADCS ESC6" for f in self.parser.findings))

    def test_machine_account_quota(self):
        self.assertTrue(any(f.category == "MachineAccountQuota > 0" for f in self.parser.findings))

    def test_trust_without_sid_filtering(self):
        self.assertTrue(any(f.category == "Trust w/o SID filtering" for f in self.parser.findings))

    def test_attack_path_to_tier0(self):
        ap = self.parser.attack_paths()
        self.assertGreaterEqual(ap["sources_reaching_tier0"], 1)
        self.assertTrue(ap["paths"])
        # HELPDESK can reach the Tier-0 Administrator.
        self.assertTrue(any("HELPDESK" in p.source for p in ap["paths"]))

    def test_choke_points_present(self):
        ap = self.parser.attack_paths()
        self.assertTrue(ap["choke_points"])

    def test_cleartext_password_attribute(self):
        f = [x for x in self.parser.findings if x.category == "Cleartext password attribute"]
        self.assertTrue(any("LEGACYUSER" in x.principal for x in f))

    def test_privileged_delegatable(self):
        self.assertTrue(any(f.category == "Privileged account delegatable"
                            for f in self.parser.findings))

    def test_bom_is_tolerated(self):
        # A collection written with a UTF-8 BOM must still parse.
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            src = SAMPLE / "20250101_users.json"
            dst = Path(td) / "x_users.json"
            dst.write_bytes(b"\xef\xbb\xbf" + src.read_bytes())
            p = SharpHoundParser(Path(td))
            p.parse_all()
            self.assertEqual(p.statistics.total_users, 4)

    def test_exploit_hints(self):
        # Every finding category should map to (or prefix-match) an exploit command.
        self.assertIn("GetUserSPNs", exploit_hint("Kerberoastable"))
        self.assertIn("GetUserSPNs", exploit_hint("Kerberoastable (privileged!)"))
        self.assertIn("certipy req", exploit_hint("ADCS ESC1"))
        self.assertIn("bloodyAD", exploit_hint("ACL: ForceChangePassword"))
        self.assertIn("secretsdump", exploit_hint("ACL: DCSync"))
        # And the field is exported in each finding dict.
        self.assertTrue(all("exploit" in f.to_dict() for f in self.parser.findings))


class TestZipSupport(unittest.TestCase):
    def test_reads_zip_archive(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            zpath = Path(td) / "collection.zip"
            with zipfile.ZipFile(zpath, "w") as zf:
                for j in SAMPLE.glob("*.json"):
                    zf.write(j, j.name)
            parser = SharpHoundParser(zpath)
            parser.parse_all()
            self.assertEqual(parser.statistics.total_users, 4)


class TestExporters(unittest.TestCase):
    def test_all_exporters_write_files(self):
        import tempfile
        parser = SharpHoundParser(SAMPLE)
        parser.parse_all()
        with tempfile.TemporaryDirectory() as td:
            out = Path(td)
            OutputExporter.export_txt(parser, out)
            OutputExporter.export_summary(parser, out)
            OutputExporter.export_json(parser, out)
            OutputExporter.export_csv(parser, out)
            OutputExporter.export_markdown(parser, out)
            OutputExporter.export_html(parser, out)
            OutputExporter.export_cypher(parser, out)
            for fname in ("resumen.txt", "analysis.json", "findings.csv",
                          "report.md", "report.html", "hunting_queries.cypher"):
                self.assertTrue((out / fname).exists(), f"missing {fname}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
