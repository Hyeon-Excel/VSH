# hyeonexcel 수정: 공통 계약 구현은 shared/contracts.py로 이동했고,
# 기존 modules.base_module import 경로는 하위 호환을 위해 얇은 wrapper만 유지한다.
from shared.contracts import BaseAnalyzer, BaseScanner

__all__ = [
    "BaseAnalyzer",
    "BaseScanner",
]
