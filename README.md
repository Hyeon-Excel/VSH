# 🛡️ VSH v1.0 – Vibe Secure Helper

**VSH (Vibe Secure Helper)** is a lightweight, layered AppSec scanner for
static code and dependency security.  It combines pattern‑based analysis,
supply‑chain checks, and inline annotations to help developers spot and
fix vulnerabilities quickly.

---

## 🎯 What it does (L1 hot path)

- **Code pattern detection** via Semgrep (SQLi, XSS, command
  injection, etc.), with fallback heuristics when Semgrep is unavailable.
- **Function‑level risk warnings** – only the dangerous methods are flagged
  (e.g. `ET.fromstring()` vs `ET.parse()`, `eval()`, `subprocess.run(shell=True)`,
  `pickle.loads()`, `innerHTML` assignment).
- **Dependency inventory & OSV lookup**: SBOM from `syft`, or requirements/lock
  file parsing.
- **Package hallucination & typosquatting**: checks PyPI/npm registries for
  imported packages and suggests likely typos.
- **Simple reachability**: heuristic proximity of user input to sinks.
- **Optional source‑code annotations**: generate annotated copies with
  vulnerability comments.
- **Markdown reporting**: export a human‑readable summary of findings,
  dependencies, and hallucinations.

> 🔥 L1 is fast (~0.3‑1.0 s) and stateless.  L2/L3 extensions can layer on
> explanations, LLM analysis, PoCs, or external integrations via the
> `AnalysisPipeline` API.

---

## 📁 Repo structure

```
vsh/                 # main package
  core/              # config, models, utilities
  engines/           # detection engines (semgrep, osv, sbom, etc.)
  rules/semgrep/     # Python/JS rules
  demo_targets/      # vulnerable sample code
modules/scanner/     # scanner interface + VSHL1Scanner
pipeline/            # AnalysisPipeline (L1/L2/L3 orchestration)
tests/               # pytest suite
scripts/             # helper utilities
docker/              # Dockerfile + compose
README.md            # you are here
```

---

## 🚀 Quick start

### 1. Install

```bash
pip install -e .                  # install package into venv
./scripts/install_semgrep.sh      # optional, installs Semgrep
```

### 2. CLI scan

```bash
# Python project
vsh /path/to/project --lang python

# JavaScript/TypeScript project
vsh /path/to/project --lang javascript
```

The tool will print a summary, sample inline comments, and write
`vsh_out/VSH_REPORT.md`.

#### Annotated copies

The CLI does **not** modify your source by default.  To generate annotated
copies, use:

```bash
vsh /path/to/project --annotate                # writes to vsh_out/annotated
vsh /path/to/project --annotate --annotated-dir copy_dir
```

(Annotations are **copies**; originals remain untouched.)

---

## 💻 Programmatic API

```python
from pathlib import Path
from vsh.core.config import VSHConfig
from pipeline.analysis_pipeline import AnalysisPipeline
from modules.scanner.vsh_l1_scanner import VSHL1Scanner
from vsh.engines.code_annotator import write_annotated_files

cfg = VSHConfig(project_root=Path("./project"), out_dir=Path("vsh_out"), language="python")
scanner = VSHL1Scanner(cfg)
pipeline = AnalysisPipeline(scanner=scanner)

# simple scan
result = pipeline.run_l1(scan_only=True)

# scan + annotations
result = pipeline.run_l1(scan_only=False, annotate=True)
write_annotated_files(result.annotated_files, Path("annotated"))
```

The `ScanResult` contains `findings`, `vuln_records`, `package_records`, and
(optional) `annotated_files`.

---

## 🛠 CLI options

```bash
vsh <project_path> [OPTIONS]

--out <dir>           # output directory (default: vsh_out)
--lang <lang>         # python|javascript (auto detect if omitted)
--no-syft             # disable SBOM creation via syft
--annotate            # produce annotated copies of source files
--annotated-dir <dir> # where to write annotated copies
```

Example:
```bash
vsh myapp --lang python --annotate --annotated-dir annotated_copy
```

---

## 🧪 Testing & development

```bash
pytest                     # run all tests
pytest tests/test_vsh_l1_scanner.py::test_typosquatting_detection
```

Use `black`, `isort` and `mypy` before committing; see CONTRIBUTING notes
below.

---

## 🌍 Language support

- ✅ **Python** – full support (rules, SBOM, package checks, annotations)
- ✅ **JavaScript/TypeScript** – full support
- 🚧 **Java, Go, C/C++** – partial; add Semgrep rules and registry logic to
  extend.

---

## ⚠️ Feature highlights

### Function‑level warnings (implemented)
Rather than blanket library alerts, VSH warns only when a risky function is
called.  Examples:

```python
import xml.etree.ElementTree as ET
ET.parse("file.xml")          # safe
ET.fromstring(user_input)       # ⚠️ XXE 위험 – use ET.parse()/defusedxml
```

This is driven by metadata on both Semgrep and fallback patterns and passes
through to annotations and normalized results.

### Dependency & supply‑chain checks
- SBOM via `syft` or requirements/lock files
- OSV API lookup for known CVEs
- Typosquatting detection using Levenshtein similarity

### Reachability
Simple heuristic: is user input textually close to a sink in the same file?

---

## 🏗 Extending to L2/L3

`AnalysisPipeline` decouples layers so you can plug in an analyzer (L2) or
reporter (L3) without touching L1.  See code comments in
`pipeline/analysis_pipeline.py` for interface details.

---

## 🤝 Contributing

- Tests must pass (`pytest`).
- Run `black`, `isort`, `mypy`.
- Update README when adding features.
- Keep L1 stateless and focused on detection.

---

## 📄 License

MIT – free to use and modify.

---

*VSH v1.0 – made with ❤️ by Vibe Security Team*

