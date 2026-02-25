# Process Flows

## Domain Model Flow

Domain Model은 레이어 간 데이터 전달의 핵심이며, 모든 레이어는 이 모델을 기준으로 통신합니다.

### Data Flow Diagram

1. **Scanner (L1)**: 소스 파일을 읽고 취약점을 탐지하여 `ScanResult` 객체를 생성합니다.
   - `ScanResult(findings=[Vulnerability(...)])`

2. **Pipeline**: `ScanResult.is_clean()` 메서드로 취약점 유무를 판단합니다.
   - **Clean**: 추가 처리 없이 종료.
   - **Vulnerable**: `ScanResult` 객체를 Analyzer(L2)로 전달합니다.

3. **Analyzer (L2)**: 취약점 분석 후 수정 제안을 담은 `FixSuggestion` 객체를 생성합니다.
   - `FixSuggestion(issue_id, original_code, fixed_code, description)`

4. **Repository**: `FixSuggestion` 및 `ScanResult` 정보를 DB에 저장합니다.

---

### Layer Dependency

`Pipeline` -> `models`
`Scanner` -> `models`
`Analyzer` -> `models`
`Repository` -> `models`

모든 레이어는 `models` 패키지에 정의된 클래스에 의존하며, 레이어 간에는 객체 인스턴스로 데이터를 주고받습니다.

---

## Repository Layer Flow

Repository 레이어는 상위 레이어가 데이터의 물리적 저장소에 관계없이 동일한 인터페이스로 데이터를 다룰 수 있게 합니다.

### Inheritance Structure
- **BaseReadRepository (Abstract)**
  - `MockKnowledgeRepo`: `knowledge.json` 보안 지식 읽기 전용
  - `MockFixRepo`: `kisa_fix.json` 수정 가이드 읽기 전용
- **BaseWriteRepository (Abstract, extends BaseReadRepository)**
  - `MockLogRepo`: `log.json` 분석 결과 로그 읽기/쓰기/상태 업데이트

### Mock to Real DB Migration
나중에 실제 Vector DB(ChromaDB 등)나 RDBMS로 교체할 때:
1. `BaseRepository` 인터페이스를 상속받는 새로운 클래스(예: `ChromaRepo`)를 구현합니다.
2. `PipelineFactory` 등 객체를 조립하는 부분에서 `MockRepo` 대신 `ChromaRepo`를 주입하도록 설정만 변경합니다.
3. 상위 레이어(`Pipeline`, `Tools`)의 비즈니스 로직 코드는 일절 수정하지 않아도 동작이 유지됩니다.

---

## L1 Detection Flow (Step 3)

보안 스캔은 세 가지 서로 다른 계층에서 동시에 진행됩니다.

1. **입력**: 소스 파일 경로 (`.py`)
2. **실행**:
   - **SemgrepScanner**: 파일 라인별 문자열 패턴 매칭 → `ScanResult`
   - **TreeSitterScanner**: AST 파싱 후 함수 호출 노드 정규식 매칭 → `ScanResult`
   - **SBOMScanner**: 루트의 `requirements.txt` 내 취약 패키지 대조 → `ScanResult`
3. **통합**: 각 스캐너는 독립적인 `ScanResult` 객체를 반환하며, 이는 나중에 `Pipeline` 레이어에서 하나로 통합(merge)됩니다 (Step 5 구현 예정).

### Real Semgrep 교체 전략 (Migration)
나중에 Windows 환경이 아닌 곳에서 실제 Semgrep을 사용할 경우:
- `modules/scanner/semgrep_scanner.py` 구현 (CLI 호출 방식).
- `modules/__init__.py` 수정:
  ```python
  # 기존
  from .scanner.mock_semgrep_scanner import MockSemgrepScanner as SemgrepScanner
  # 변경
  from .scanner.semgrep_scanner import SemgrepScanner
  ```
- 이 변경만으로 나머지 모든 시스템(`Pipeline`, `Tools`)은 수정 없이 실제 Semgrep을 사용하게 됩니다.
