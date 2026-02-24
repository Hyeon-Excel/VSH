"""
L2 Warm Path — LLM 기반 취약점 심층 분석 (구현 예정)

계획:
- Claude claude-sonnet-4-6 API 연동 (anthropic SDK)
- LangChain 기반 체인 구성
- L1 Finding → 상세 취약점 설명 + Diff 형태의 수정 코드 생성
- KISA RAG (kisa_mapper.py) 결과와 결합하여 법적 근거 강화
- Human-in-the-Loop: Accept / Dismiss 인터페이스 지원

TODO: L2 구현 시 아래 의존성 추가
  pip install anthropic langchain langchain-anthropic
"""
