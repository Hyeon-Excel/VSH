from models.scan_result import ScanResult
from models.vulnerability import Vulnerability
from layer2.retriever.evidence_retriever import EvidenceRetriever
from repository.fix_repo import MockFixRepo
from repository.knowledge_repo import MockKnowledgeRepo


class FakeChromaRetriever:
    ready = True

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
    assert context["primary_reference"] == "KISA: KISA 시큐어코딩 DB-RAG-01"
    assert "KISA: KISA 시큐어코딩 DB-RAG-01" in context["evidence_refs"]
    assert "OWASP: A03:2021" in context["evidence_refs"]
    assert "DB-RAG-01" in (context["evidence_summary"] or "")
