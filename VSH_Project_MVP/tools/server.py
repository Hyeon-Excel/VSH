# hyeonexcel 수정: MCP 서버 실제 구현은 interfaces/mcp로 이동했고,
# 기존 tools/server.py 경로는 실행 및 import 호환을 위해 wrapper로 유지한다.
from interfaces.mcp.server import *  # noqa: F401,F403
