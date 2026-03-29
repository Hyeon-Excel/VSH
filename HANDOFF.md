# HANDOFF

## 핵심 폴더
- `VSH_Project_MVP/vsh_runtime`: runtime engine/diagnostics/watcher/risk/sca usage
- `VSH_Project_MVP/layer1`: fast scanner
- `VSH_Project_MVP/layer2/reasoning`: context-aware reasoning pipeline/providers
- `VSH_Project_MVP/interfaces/mcp/server.py`: MCP tool entry

## 실행
- scan-file: `python VSH_Project_MVP/scripts/vsh_cli.py scan-file <file> --format json`
- diagnostics: `python VSH_Project_MVP/scripts/vsh_cli.py diagnostics <target>`
- watch: `python VSH_Project_MVP/scripts/watch_and_scan.py --path <dir>`

## Provider 교체
- reasoning: `layer2/reasoning/providers/*`
- registry/osv: `layer2/verifier/providers/*`

## 비고
- 기본은 mock/offline.
- online provider는 opt-in으로만 활성화.
