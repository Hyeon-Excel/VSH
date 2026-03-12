# 주의: pipeline.py에서 이 구체 클래스를 직접 import 하지 마세요 (DI 패턴 위반). mcp_server.py에서 주입해야 합니다.

from l3.providers.base import AbstractPoCProvider
from l3.schema import VulnRecord

class MockPoCProvider(AbstractPoCProvider):
    """테스트 및 초기 개발을 위한 PoC(공격 가능성 증명) Mock Provider"""

    async def verify(self, record: VulnRecord) -> VulnRecord:
        """실제 PoC 실행 없이 입력받은 레코드의 상태를 poc_verified로 변경하여 반환한다."""
        print(f"[L3 PoC Mock] PoC 실행: {record.vuln_id}")
        
        # 상태 업데이트 (성공 가정)
        record.status = "poc_verified"
        
        print(f"[L3 PoC Mock] 결과: poc_verified")
        return record
