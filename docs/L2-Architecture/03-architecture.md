# L2 Architecture

## 1. 현재 목표 아키텍처

```text
L1 findings
  -> AnalysisPipeline
      -> EvidenceRetriever
      -> RegistryVerifier
      -> OsvVerifier
      -> Analyzer (Mock / Gemini / Claude)
      -> PatchBuilder
      -> FixSuggestion / Log / MCP / Dashboard
```

## 2. 세부 컴포넌트 책임

### `AnalysisPipeline`

현재 L2 전체 오케스트레이션 담당.

- request 수신
- finding 분류
- enrichment 실행
- verification 실행
- patch 생성 호출
- log 저장
- response 조립
- 오류 수집 및 반환

### `EvidenceRetriever`

정책, 보안 기준, 내부 규칙 근거 조회 담당.

조회 우선순위:

1. `kisa_key`
2. `fsec_key`
3. `cwe`
4. `owasp`
5. 언어 및 프레임워크 힌트

반환 데이터:

- 참조 목록
- 설명
- remediation 요약

### `RegistryVerifier`

패키지 존재 여부 및 레지스트리 메타데이터 확인 담당.

출력:

- 검증 대상
- 상태
- 세부 메시지

### `OsvVerifier`

OSV 기반 취약 버전 검증 담당.

출력:

- 검증 대상
- advisory 발견 여부
- 버전 또는 세부 설명

### `PatchBuilder`

최종 수정 patch 또는 diff 생성 담당.

처리 전략:

- 코드 취약점:
  - patch 또는 diff 생성
- 공급망 취약점:
  - 버전 상향 patch 또는 recommendation 생성

## 3. 내부 처리 흐름

### Code Finding 처리 흐름

1. finding 입력
2. 식별자 추출
3. evidence retrieval 수행
4. rationale와 recommendation 생성
5. patch 후보 생성
6. enriched finding 반환

### Supply Chain Finding 처리 흐름

1. package candidate 추출
2. registry verification 수행
3. osv verification 수행
4. verification 결과 정규화
5. recommendation 작성
6. 가능하면 version patch 생성

### 오류 처리 흐름

L2는 fail-soft 원칙을 따른다.

- retrieval 실패 -> error 기록 후 계속 진행
- registry 실패 -> `UNKNOWN` 또는 `ERROR`
- osv 실패 -> `UNKNOWN` 또는 `ERROR`
- patch 생성 실패 -> `fix_patch=""`

하위 컴포넌트가 실패해도 response는 가능한 한 반환해야 한다.

## 4. 현재 파일 구조 기준

```text
VSH_Project_MVP/
  layer2/
    __init__.py
    common/
      __init__.py
      requirement_parser.py
    analyzer/
      __init__.py
      analyzer_factory.py
      mock_analyzer.py
      gemini_analyzer.py
      claude_analyzer.py
      confidence_support.py
    patch_builder.py
    retriever/
      __init__.py
      evidence_retriever.py
      chroma_retriever.py
    verifier/
      __init__.py
      registry_verifier.py
      osv_verifier.py
  pipeline/
    analysis_pipeline.py
    pipeline_factory.py
  models/
    fix_suggestion.py
  tests/
  test_l2_retriever.py
  test_l2_verifiers.py
  test_l2_patch_builder.py
  test_mock_analyzer.py
  test_e2e.py
```

향후 `L2Service` 같은 별도 오케스트레이션 클래스로 재분리할 수는 있지만,
현재 구현과 테스트 기준선은 위 구조를 따른다.
