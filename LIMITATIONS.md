# LIMITATIONS

- L1은 fast heuristic 중심이며 완전한 taint/call graph 분석이 아님.
- L2는 context-aware reasoning이지만 runtime proof가 아님.
- L3만 deep validation 담당(현재는 slot/queue 중심).
- SCA usage 분석은 exploitability-aware heuristic이며 완전한 interprocedural 분석이 아님.
- IDE 연동은 watcher/MCP/diagnostics까지 구현, VSCode extension/LSP는 future work.
