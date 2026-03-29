from l3.schema import VulnRecord, PackageRecord
from l3.providers.base import AbstractSharedDB

class L3Normalizer:
    """M4: 스키마 검증 및 Shared DB 저장을 담당하는 Normalizer"""

    def __init__(self, db: AbstractSharedDB):
        """AbstractSharedDB를 의존성 주입(DI)으로 받는다."""
        self.db = db

    async def save(self, record: VulnRecord | PackageRecord) -> None:
        """레코드를 DB에 저장하며, 실패 시 scan_error 상태로 재시도한다."""
        try:
            # 1단계: 1차 저장 시도
            await self.db.write(record)
            # 5단계: 정상 저장 시 로그 출력
            print(f"[L3 Normalizer] 저장 완료: {type(record).__name__}")
        except Exception:
            # 2단계: 1차 실패 시 status 속성 확인 및 변경
            if hasattr(record, "status"):
                record.status = "scan_error"
                
            try:
                # 3단계: 상태 변경 후 2차 저장 시도
                await self.db.write(record)
                print(f"[L3 Normalizer] 재시도 저장 완료: {type(record).__name__}")
            except Exception as e:
                # 4단계: 최종 실패 시 파이프라인 중단 없이 에러 로깅만 수행
                print(f"[L3 Normalizer] 저장 최종 실패: {e}")
                return
