from models.scan_result import ScanResult
from models.vulnerability import Vulnerability
from layer2.retriever.chroma_retriever import ChromaRetriever
from layer2.retriever.evidence_retriever import EvidenceRetriever
from repository.fix_repo import MockFixRepo
from repository.knowledge_repo import MockKnowledgeRepo


class FakeChromaRetriever:
    ready = True
    status = "READY"
    status_summary = "Chroma collection `vsh_kisa_guide` 연결이 활성화되었습니다."

    def query(self, cwe_id: str, code_snippet: str = "", n_results: int = 4):
        return [
            {
                "source": "KISA",
                "kisa_article": "KISA 시큐어코딩 DB-RAG-01",
                "title": "SQL Injection 가이드",
                "text": "사용자 입력이 SQL 문에 직접 연결되면 파라미터 바인딩으로 수정해야 합니다.",
                "cvss_score": "",
            },
            {
                "source": "OWASP",
                "owasp_id": "A03:2021",
                "title": "Injection",
                "text": "Injection 계열 공격은 입력값 검증과 바인딩으로 완화합니다.",
                "cvss_score": "",
            },
        ]

    def query_related(self, cwe_id: str, code_snippet: str = "", n_results: int = 4):
        return self.query(cwe_id, code_snippet, n_results=n_results)


class DisabledChromaRetriever:
    ready = False
    status = "MISSING_DEPENDENCY"
    status_summary = "chromadb 패키지가 설치되지 않아 Chroma RAG가 비활성화되었습니다."

    def query(self, cwe_id: str, code_snippet: str = "", n_results: int = 4):
        return []


class FallbackChromaRetriever:
    ready = True
    status = "READY"
    status_summary = "Chroma collection `vsh_kisa_guide` 연결이 활성화되었습니다."

    def query_related(self, cwe_id: str, code_snippet: str = "", n_results: int = 4):
        return [
            {
                "source": "KISA",
                "cwe": cwe_id,
                "kisa_article": "입력데이터 검증 및 표현 1항",
                "title": "SQL 삽입",
                "text": "파라미터 바인딩을 사용해 SQL Injection을 방지합니다.",
                "cvss_score": "",
            },
            {
                "source": "FSI",
                "cwe": "",
                "source_id": "WEB-FIN-001",
                "title": "SQL Injection",
                "text": "금융보안원 체크리스트 기준으로 URL 파라미터 및 XML 입력값에 대한 비정상 SQL 질의 여부를 점검합니다.",
                "cvss_score": "",
            },
        ]

    def query(self, cwe_id: str, code_snippet: str = "", n_results: int = 4):
        raise AssertionError("query_related should be used before query")


def test_evidence_retriever_builds_code_finding_context():
    retriever = EvidenceRetriever()
    scan_result = ScanResult(
        file_path="tests/e2e_target.py",
        language="python",
        findings=[
            Vulnerability(
                file_path="tests/e2e_target.py",
                cwe_id="CWE-89",
                severity="HIGH",
                line_number=5,
                code_snippet="cursor.execute('SELECT * FROM users WHERE id = %s' % user_input)",
            )
        ],
    )

    evidence_map = retriever.retrieve(
        scan_result,
        MockKnowledgeRepo().find_all(),
        MockFixRepo().find_all(),
    )

    context = evidence_map["tests/e2e_target.py_CWE-89_5"]
    assert "KISA 시큐어코딩 DB-01" in context["evidence_refs"]
    assert context["primary_reference"] == "KISA 시큐어코딩 DB-01"
    assert "SQL Injection" not in (context["evidence_summary"] or "")
    assert "사용자 입력이 SQL 쿼리에 직접 삽입됨" in (context["evidence_summary"] or "")


def test_evidence_retriever_builds_supply_chain_context():
    retriever = EvidenceRetriever()
    scan_result = ScanResult(
        file_path="tests/e2e_target.py",
        language="python",
        findings=[
            Vulnerability(
                file_path="requirements.txt",
                cwe_id="CWE-829",
                severity="HIGH",
                line_number=1,
                code_snippet="requests==2.9.0",
            )
        ],
    )

    evidence_map = retriever.retrieve(scan_result, knowledge=[], fix_hints=[])

    context = evidence_map["requirements.txt_CWE-829_1"]
    assert "Package: requests" in context["evidence_refs"]
    assert "Safe floor: 2.20.0" in context["evidence_refs"]
    assert "CVE-2018-18074" in context["evidence_refs"]
    assert context["recommended_fix"] == "requests>=2.20.0"
    assert "2.20.0" in (context["evidence_summary"] or "")


def test_evidence_retriever_includes_chroma_context_when_available():
    retriever = EvidenceRetriever(chroma_retriever=FakeChromaRetriever())
    scan_result = ScanResult(
        file_path="tests/e2e_target.py",
        language="python",
        findings=[
            Vulnerability(
                file_path="tests/e2e_target.py",
                cwe_id="CWE-89",
                severity="HIGH",
                line_number=5,
                code_snippet="cursor.execute('SELECT * FROM users WHERE id = %s' % user_input)",
            )
        ],
    )

    evidence_map = retriever.retrieve(
        scan_result,
        knowledge=[],
        fix_hints=[],
    )

    context = evidence_map["tests/e2e_target.py_CWE-89_5"]
    assert context["retrieval_backend"] == "chroma_only"
    assert context["chroma_status"] == "READY"
    assert context["chroma_hits"] == 2
    assert context["primary_reference"] == "KISA: KISA 시큐어코딩 DB-RAG-01"
    assert "KISA: KISA 시큐어코딩 DB-RAG-01" in context["evidence_refs"]
    assert "OWASP: A03:2021" in context["evidence_refs"]
    assert "DB-RAG-01" in (context["evidence_summary"] or "")


def test_evidence_retriever_reports_chroma_runtime_status_when_disabled():
    retriever = EvidenceRetriever(chroma_retriever=DisabledChromaRetriever())
    scan_result = ScanResult(
        file_path="tests/e2e_target.py",
        language="python",
        findings=[
            Vulnerability(
                file_path="tests/e2e_target.py",
                cwe_id="CWE-89",
                severity="HIGH",
                line_number=5,
                code_snippet="cursor.execute('SELECT * FROM users WHERE id = %s' % user_input)",
            )
        ],
    )

    evidence_map = retriever.retrieve(
        scan_result,
        knowledge=[],
        fix_hints=[],
    )

    context = evidence_map["tests/e2e_target.py_CWE-89_5"]
    assert context["retrieval_backend"] == "empty"
    assert context["chroma_status"] == "MISSING_DEPENDENCY"
    assert "비활성화" in (context["chroma_summary"] or "")
    assert context["chroma_hits"] == 0


def test_evidence_retriever_uses_query_related_fallback_for_fsi_docs():
    retriever = EvidenceRetriever(chroma_retriever=FallbackChromaRetriever())
    scan_result = ScanResult(
        file_path="tests/e2e_target.py",
        language="python",
        findings=[
            Vulnerability(
                file_path="tests/e2e_target.py",
                cwe_id="CWE-89",
                severity="HIGH",
                line_number=5,
                code_snippet="cursor.execute(query % user_input)",
            )
        ],
    )

    evidence_map = retriever.retrieve(
        scan_result,
        knowledge=[],
        fix_hints=[],
    )

    context = evidence_map["tests/e2e_target.py_CWE-89_5"]
    assert context["retrieval_backend"] == "chroma_only"
    assert context["chroma_hits"] == 2
    assert "FSI: WEB-FIN-001" in context["evidence_refs"]
    assert context["primary_reference"] == "KISA: 입력데이터 검증 및 표현 1항"
    assert "금융보안원 체크리스트" in (context["evidence_summary"] or "") or "SQL 삽입" in (context["evidence_summary"] or "")


def test_chroma_retriever_ranks_exact_and_kisa_sources_first():
    exact_docs = [
        {
            "source": "NVD",
            "cwe": "CWE-89",
            "cve_id": "CVE-2024-0001",
            "text": "NVD advisory",
        }
    ]
    broad_docs = [
        {
            "source": "FSI",
            "cwe": "",
            "source_id": "WEB-FIN-001",
            "title": "SQL Injection",
            "text": "금융보안원 체크리스트",
        },
        {
            "source": "KISA",
            "cwe": "CWE-89",
            "kisa_article": "입력데이터 검증 및 표현 1항",
            "title": "SQL 삽입",
            "text": "KISA guide",
        },
    ]

    merged = ChromaRetriever._merge_ranked_results(exact_docs, broad_docs, "CWE-89", 3)

    assert merged[0]["source"] == "KISA"
    assert merged[1]["source"] == "FSI"
    assert merged[2]["source"] == "NVD"


def test_chroma_retriever_prioritizes_nvd_for_supply_chain():
    merged = ChromaRetriever._merge_ranked_results(
        exact_docs=[
            {
                "source": "NVD",
                "cwe": "CWE-829",
                "cve_id": "CVE-2018-18074",
                "text": "NVD advisory",
            }
        ],
        broad_docs=[
            {
                "source": "KISA",
                "cwe": "CWE-829",
                "kisa_article": "보안 기능 1항",
                "title": "취약 라이브러리 점검",
                "text": "KISA guide",
            }
        ],
        cwe_id="CWE-829",
        n_results=2,
    )

    assert merged[0]["source"] == "NVD"
    assert merged[1]["source"] == "KISA"


def test_chroma_retriever_uses_exact_metadata_before_query_embeddings():
    class QueryFailCollection:
        def count(self):
            return 2

        def get(self, where=None, limit=10, include=None):
            if where:
                return {
                    "documents": [
                        "파라미터 바인딩으로 SQL Injection을 방지합니다.",
                        "Injection 취약점은 입력값 검증이 필요합니다.",
                    ],
                    "metadatas": [
                        {
                            "source": "KISA",
                            "cwe": "CWE-89",
                            "kisa_article": "입력데이터 검증 및 표현 1항",
                            "title": "SQL 삽입",
                        },
                        {
                            "source": "OWASP",
                            "cwe": "CWE-89",
                            "owasp_id": "A03:2021",
                            "title": "Injection",
                        },
                    ],
                }
            return {"documents": [], "metadatas": []}

        def query(self, *args, **kwargs):
            raise AssertionError("exact metadata match should bypass semantic query")

    retriever = ChromaRetriever.__new__(ChromaRetriever)
    retriever._ready = True
    retriever._collection = QueryFailCollection()

    docs = retriever.query_related("CWE-89", "cursor.execute(query % user_input)", n_results=2)

    assert len(docs) == 2
    assert docs[0]["source"] == "KISA"
    assert docs[1]["source"] == "OWASP"
