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
[![BloodHound](https://img.shields.io/badge/BloodHound-Compatible-red.svg)](https://github.com/BloodHoundAD/BloodHound)

> **Advanced Active Directory enumeration analysis tool for BloodHound/SharpHound JSON collections.**

---

## 🇬🇧 English

### Description

**BloodHound Parser** is an enterprise-grade analysis tool for BloodHound/SharpHound JSON collections. It automatically identifies critical Active Directory misconfigurations and attack paths:

- **Kerberoastable accounts** detection (SPN enumeration)
- **ASREProastable users** identification (DONT_REQ_PREAUTH)
- **Delegation analysis** (unconstrained/constrained delegation)
- **High-value target** enumeration
- **Privilege escalation paths** identification
- **Multiple export formats** (JSON, CSV, Markdown, TXT)
- **Risk scoring** and prioritization

### Why This Tool?

BloodHound provides the graph, but **BloodHound Parser extracts actionable intelligence**. Perfect for:
- Quick triage during Active Directory assessments
- Automated reporting generation
- Prioritizing attack paths during time-limited engagements
- Integration with other Red Team tools

### Features

✅ **Kerberoasting Detection**: Automatically finds service accounts with SPNs  
✅ **ASREProast Identification**: Locates accounts without Kerberos pre-authentication  
✅ **Delegation Issues**: Identifies unconstrained/constrained delegation risks  
✅ **Admin Path Mapping**: Finds users with AdminCount attribute  
✅ **Multi-format Export**: JSON, CSV, Markdown, plain text  
✅ **Dataclass Architecture**: Type-safe, modern Python design  

### Installation

```bash
git clone https://github.com/yourusername/BloodHound-Parser.git
cd BloodHound-Parser
pip install -r requirements.txt
```

### Usage

#### Basic Analysis

```bash
# Parse all JSON files in BloodHound directory
python src/parseSharpHound.py /path/to/bloodhound/data
```

#### Generate All Formats

```bash
# Export in all available formats
python src/parseSharpHound.py /path/to/bloodhound -f all
```

#### Export for Integration

```bash
# JSON export for scripting
python src/parseSharpHound.py /path/to/bloodhound -f json -o analysis.json

# Markdown report for documentation
python src/parseSharpHound.py /path/to/bloodhound -f markdown -o report.md
```

#### Custom Output Location

```bash
python src/parseSharpHound.py /path/to/bloodhound -o /custom/output/dir
```

### Command Reference

```
positional arguments:
  directory            Directory containing SharpHound JSON files

optional arguments:
  -o, --output PATH    Output directory (default: same as input)
  -f, --format FORMAT  Export format: txt, json, markdown, all (default: all)
  --output-format FMT  Text file format: column, comma (default: column)
  -v, --verbose        Verbose output
```

### Sample Output

#### Console Output
```
[INFO] Scanning directory: /data/bloodhound
[INFO] Parsed 1234 users from 20241225_users.json
[INFO] Analysis complete: 1234 users, 543 computers, 234 groups
[INFO] Exported 1234 users to user_names_output.txt
```

#### Summary Report (resumen.txt)
```
==========================================================
SHARPHOUND COLLECTION SUMMARY
==========================================================

OBJECT COUNTS:
  Users:      1234
  Groups:     234
  Computers:  543

USER ANALYSIS:
  Enabled:           1100
  Privileged:        45
  Kerberoastable:    12
  ASREProastable:    3
  High Value:        28

KERBEROASTABLE USERS:
  - sqlservice@corp.local
  - webservice@corp.local
  - svc_backup@corp.local

ASREPROASTABLE USERS:
  - testuser@corp.local
  - legacyacct@corp.local
```

### Project Structure

```
BloodHound-Parser/
├── src/
│   ├── parseSharpHound.py    # Main parser
│   └── __init__.py
├── examples/
│   ├── sample_output/
│   └── README.md
├── requirements.txt
├── .gitignore
├── LICENSE
└── README.md
```

---

## 🇪🇸 Español

### Descripción

**BloodHound Parser** es una herramienta de análisis de nivel enterprise para colecciones JSON de BloodHound/SharpHound. Identifica automáticamente configuraciones críticas de Active Directory y rutas de ataque:

- **Detección de cuentas Kerberoastables** (enumeración de SPN)
- **Identificación de usuarios ASREProastables** (DONT_REQ_PREAUTH)
- **Análisis de delegación** (delegación sin restricciones/restringida)
- **Enumeración de objetivos de alto valor**
- **Identificación de rutas de escalación de privilegios**
- **Múltiples formatos de exportación** (JSON, CSV, Markdown, TXT)

### ¿Por qué usar esta herramienta?

BloodHound proporciona el grafo, pero **BloodHound Parser extrae inteligencia accionable**. Perfecto para:
- Triage rápido durante evaluaciones de Active Directory
- Generación automatizada de reportes
- Priorización de rutas de ataque en compromisos con tiempo limitado
- Integración con otras herramientas de Red Team

### Instalación

```bash
git clone https://github.com/yourusername/BloodHound-Parser.git
cd BloodHound-Parser
pip install -r requirements.txt
```

### Uso Básico

```bash
# Análisis completo
python src/parseSharpHound.py /path/to/bloodhound/data

# Exportar solo JSON
python src/parseSharpHound.py /path/to/bloodhound -f json -o analysis.json

# Exportar en todos los formatos
python src/parseSharpHound.py /path/to/bloodhound -f all
```

### Salida de Ejemplo

El análisis identifica:
- Cuentas Kerberoastables (objetivo para roast SPN)
- Usuarios ASREProastables (objetivo para asreproast)
- Cuentas con delegación sin restricciones (objetivo para ataques de delegación)
- Usuarios privilegiados (AdminCount)

---

## 📋 Requirements

- Python 3.8+
- pathlib (standard library)
- dataclasses (standard library)

No external dependencies required! Pure Python implementation.

## 🔒 Legal Disclaimer

**FOR AUTHORIZED SECURITY TESTING ONLY**

This tool is for authorized Active Directory security assessments only. Unauthorized access to computer systems is illegal.

- ✅ Use only on networks you own or have written permission to test
- ✅ Understand your local laws regarding penetration testing
- ❌ The author assumes NO liability for misuse

## 📜 License

MIT License - see [LICENSE](LICENSE) file for details.

## 👤 Author

**Esteban Jiménez**
- 🏆 Top 1 Hack The Box Ecuador
- 🎯 Red Team Operator  
- 💼 Active Directory Specialist
- 🔗 [GitHub](https://github.com/virtualshoot)

## 🙏 Acknowledgments

- BloodHound/SharpHound team for amazing AD analysis tools
- Active Directory security research community
- MITRE ATT&CK framework

---

**⚠️ Use responsibly. Happy hunting!**
