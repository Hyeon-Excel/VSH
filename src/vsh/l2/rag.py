"""
L2 Warm Path — RAG 지식 베이스 (구현 예정)

계획:
- ChromaDB 벡터 스토어 구축
- 임베딩 대상 데이터셋:
    * KISA 시큐어코딩 가이드 (전체 49개 항목)
    * 금융보안원 소프트웨어 개발보안 체크리스트
    * OWASP Top 10 (2021)
    * NVD/CVE 취약점 설명 데이터
- 쿼리: CWE ID + 코드 스니펫 → 관련 가이드 항목 Semantic Search
- 출력: KISA 조항 번호, 위반 사유, 모범 예시 코드

TODO: L2 구현 시 아래 의존성 추가
  pip install chromadb langchain-anthropic
"""
