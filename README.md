# VSH Security Prototype (rasasoe-integration)

## 역할 분리 (핵심)
- **L1 fast path**: pattern/heuristic/typosquatting/SBOM + lightweight reachability + 빠른 normalize.
- **L2 context-aware reasoning**: finding-driven context extraction 후 "실제 취약 가능성" verdict 생성.
- **L3 deep validation**: PoC/long-running/offline validation/report cold path.

## 실제 사용 가능 기능
- CLI
  - `python VSH_Project_MVP/scripts/vsh_cli.py scan-file <file> --format json|markdown|summary`
  - `python VSH_Project_MVP/scripts/vsh_cli.py scan-project <dir> --format json|markdown|summary`
  - `python VSH_Project_MVP/scripts/vsh_cli.py diagnostics <file_or_dir>`
  - `python VSH_Project_MVP/scripts/vsh_cli.py watch <dir>`
- Watcher
  - `python VSH_Project_MVP/scripts/watch_and_scan.py --path ./target_project`
- MCP tools
  - `analyze_file`, `analyze_project`, `get_diagnostics`, `watch_project`

## 출력물
- JSON: vuln_records/package_records/l2_reasoning_results/l3_validation_results/diagnostics/aggregate_summary
- Markdown preview + inline preview + diagnostics JSON preview (non-destructive 기본)

## 모드 구분
- Default: mock/offline-safe (OSV/registry/reasoning)
- Online: provider opt-in 확장 포인트

## 문서
- `ARCHITECTURE.md`
- `docs/integration/ide_workflow.md`
- `LIMITATIONS.md`
- `HANDOFF.md`
