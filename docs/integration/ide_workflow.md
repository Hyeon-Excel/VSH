# IDE Workflow Integration (Current)

## 실제 구현됨
- File watcher: `python VSH_Project_MVP/scripts/watch_and_scan.py --path ./target_project`
- CLI:
  - `python VSH_Project_MVP/scripts/vsh_cli.py scan-file <file> --format json|markdown|summary`
  - `python VSH_Project_MVP/scripts/vsh_cli.py scan-project <dir> --format json|markdown|summary`
  - `python VSH_Project_MVP/scripts/vsh_cli.py diagnostics <file_or_dir>`
  - `python VSH_Project_MVP/scripts/vsh_cli.py watch <dir>`
- MCP tools:
  - `analyze_file(file_path)`
  - `analyze_project(project_path)`
  - `get_diagnostics(target_path)`
  - `watch_project(project_path)`
- 공통 diagnostics JSON 구조:
  - file, line, column, severity, source, rule_id, message, suggestion, linked_vuln_id

## Non-destructive preview
기본 동작은 read-only입니다.
- diagnostics JSON preview
- inline-like text preview
- markdown preview

## Future Work
- VS Code/Cursor extension UI
- LSP server
- watch event의 push 기반 transport 개선
