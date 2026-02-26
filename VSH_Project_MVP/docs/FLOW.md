# Process Flows

## Dashboard Interface Flow (Step 7)

대시보드는 개발자가 분석 결과를 최종적으로 검토하고 조치하는 사용자 인터페이스입니다.

### 서버 초기화 순서 (dashboard/app.py)
1. **`load_dotenv()`**: 환경변수를 로드합니다.
2. **`MockLogRepo()` 직접 생성**: 파이프라인 생성 없이 로그 저장소만 단독으로 초기화합니다.
3. **FastAPI 인스턴스 생성**: API 엔드포인트 서비스를 시작합니다.

### 대시보드 액션 흐름
1. **리스트 조회**: 브라우저 접속 -> `GET /api/logs` 호출 -> `LogRepo`에서 전체 기록 로드 -> 화면에 카드 형태로 렌더링.
2. **Accept (수정 승인)**:
   - 개발자가 버튼 클릭 -> `POST /api/logs/{id}/accept` 호출.
   - 서버: DB 상태를 `accepted`로 업데이트 후 제안된 `fixed_code` 반환.
   - 브라우저: 수신된 코드를 클립보드에 자동 복사 -> UI 상태(색상, 텍스트) 변경.
3. **Dismiss (무시)**:
   - 개발자가 버튼 클릭 -> `POST /api/logs/{id}/dismiss` 호출.
   - 서버: DB 상태를 `dismissed`로 업데이트.
   - 브라우저: UI에서 해당 카드를 무시 처리(반투명/회색) 및 버튼 비활성화.

---

## Multiple Servers & Data Sync

VSH 프로젝트는 AI 에이전트용 인터페이스(MCP)와 인간 개발자용 인터페이스(Dashboard)를 분리하여 운영합니다.

### 데이터 공유 흐름 (Shared log.json)
1. **Write (MCP)**: Claude가 파일을 수정하거나 분석할 때 `scan_file` 툴을 호출하면, MCP 서버 내부의 `Pipeline`이 실행되고 그 결과를 `log.json`에 씁니다.
2. **Read (Dashboard)**: 개발자가 브라우저를 새로고침하면 Dashboard 서버는 동일한 `log.json` 파일을 읽어와 에이전트가 탐지한 내용을 실시간으로 보여줍니다.
3. **Update (Dashboard)**: 개발자가 대시보드에서 `Accept`를 누르면 `log.json` 파일의 상태값이 업데이트됩니다.

`MockLogRepo`가 파일 기반(Persistence)으로 동작하기 때문에 별도의 서버 간 통신이나 데이터 동기화 로직 없이도 완벽한 일관성이 유지됩니다.
