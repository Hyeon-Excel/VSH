from l3.llm import LLMAdapter, ClaudeAdapter, GeminiAdapter

print("import OK")
print("ClaudeAdapter는 LLMAdapter 서브클래스:",
      issubclass(ClaudeAdapter, LLMAdapter))
print("GeminiAdapter는 LLMAdapter 서브클래스:",
      issubclass(GeminiAdapter, LLMAdapter))
claude = ClaudeAdapter()
gemini = GeminiAdapter()
print("ClaudeAdapter 인스턴스 생성: OK")
print("GeminiAdapter 인스턴스 생성: OK")
print("classify_cwe 메서드 존재 (Claude):",
      hasattr(claude, "classify_cwe"))
print("classify_cwe 메서드 존재 (Gemini):",
      hasattr(gemini, "classify_cwe"))
