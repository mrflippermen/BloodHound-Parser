# Examples

`sample_data/` contains a tiny, **synthetic** BloodHound Community Edition (SharpHound v2)
collection used by the test-suite and for a quick demo. It is safe to commit — no real
environment data.

The dataset deliberately contains one of everything the parser detects:

| Object | Planted finding |
|---|---|
| `SQLSERVICE` | Kerberoastable (SPN) + password in `description` |
| `LEGACYUSER` | ASREPRoastable + PASSWD_NOTREQD + stale + pwdneverexpires |
| `HELPDESK` | SID history + `ForceChangePassword` over the Tier-0 Administrator + `GenericAll` over WS-LEGACY01 |
| `ADMINISTRATOR` | Tier-0 high-value target (inbound ACE) |
| `DC01` | Unconstrained delegation (Critical) |
| `WS-LEGACY01` | End-of-life OS (Windows 7) + no LAPS |
| `APP01` | Constrained delegation + RBCD configured |
| `DOMAIN ADMINS` | Nested group → recursive membership resolution |

## Run the demo

```bash
python src/parseSharpHound.py examples/sample_data -o /tmp/bh_report
cat /tmp/bh_report/resumen.txt        # text summary
open /tmp/bh_report/report.html       # visual report
```

Expected: **risk score 85/100**, 3 critical findings, Domain Admins with 2 effective members.
