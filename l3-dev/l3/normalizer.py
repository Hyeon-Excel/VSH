from l3.schema import VulnRecord, PackageRecord
from l3.providers.base import AbstractSharedDB

CWE_META = {
    "CWE-89":  {"owasp": "A03:2021 - Injection",                    "cvss": 9.8},
    "CWE-78":  {"owasp": "A03:2021 - Injection",                    "cvss": 9.8},
    "CWE-79":  {"owasp": "A03:2021 - Injection",                    "cvss": 6.1},
    "CWE-829": {"owasp": "A06:2021 - Vulnerable and Outdated Components", "cvss": 7.5},
    "CWE-798": {"owasp": "A07:2021 - Identification and Authentication Failures", "cvss": 7.5},
    "CWE-22":  {"owasp": "A01:2021 - Broken Access Control",         "cvss": 7.5},
    "CWE-502": {"owasp": "A08:2021 - Software and Data Integrity",   "cvss": 9.8},
}

def _get_kisa_ref(cwe_id: str) -> str:
    try:
        import sys, os
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../VSH-l1-l2-integration/VSH_Project_MVP"))
        from layer2.retriever.chroma_retriever import ChromaRetriever
        retriever = ChromaRetriever()
        if retriever.ready:
            docs = retriever.query_by_source(cwe_id, source="KISA", n_results=1)
            if docs:
                return docs[0].get("kisa_article", "") or ""
    except Exception:
        pass
    return ""

def apply_cwe_meta(record):
    if not hasattr(record, "cwe_id"):
        return record
    meta = CWE_META.get(record.cwe_id, {})
    if meta:
        if not record.owasp_ref or record.owasp_ref == "N/A":
            record.owasp_ref = meta.get("owasp", record.owasp_ref)
        if record.cvss_score is None:
            record.cvss_score = meta.get("cvss", record.cvss_score)
    if not record.kisa_ref or record.kisa_ref in ("N/A", "") or "가이드 참조" in (record.kisa_ref or ""):
        kisa = _get_kisa_ref(record.cwe_id)
        if kisa:
            record.kisa_ref = kisa
    return record

class L3Normalizer:
    """M4: 스키마 검증 및 Shared DB 저장을 담당하는 Normalizer"""

    def __init__(self, db: AbstractSharedDB):
        """AbstractSharedDB를 의존성 주입(DI)으로 받는다."""
        self.db = db

    async def save(self, record: VulnRecord | PackageRecord) -> None:
        """레코드를 DB에 저장하며, 실패 시 scan_error 상태로 재시도한다."""
        try:
            # 1단계: 1차 저장 시도
            record = apply_cwe_meta(record)
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
