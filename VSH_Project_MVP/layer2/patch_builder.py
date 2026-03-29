from difflib import unified_diff

from models.fix_suggestion import FixSuggestion
from models.vulnerability import Vulnerability


class PatchBuilder:
    """
    FixSuggestion의 original/fixed 코드를 기반으로 deterministic patch preview를 생성한다.
    """

    def build(self, finding: Vulnerability, suggestion: FixSuggestion) -> dict:
        file_path = suggestion.file_path or finding.file_path or "unknown-file"
        original_code = (suggestion.original_code or finding.code_snippet or "").rstrip("\n")
        fixed_code = (suggestion.fixed_code or "").rstrip("\n")

        if not fixed_code:
            return {
                "patch_status": "NOT_GENERATED",
                "patch_summary": "수정 코드가 없어 patch preview를 생성하지 못했습니다.",
                "patch_diff": None,
            }

        if original_code == fixed_code:
            return {
                "patch_status": "NOT_GENERATED",
                "patch_summary": "원본과 수정 코드가 동일하여 patch preview를 생성하지 않았습니다.",
                "patch_diff": None,
            }

        diff_lines = list(
            unified_diff(
                original_code.splitlines(),
                fixed_code.splitlines(),
                fromfile=f"a/{file_path}",
                tofile=f"b/{file_path}",
                lineterm="",
            )
        )

        if not diff_lines:
            return {
                "patch_status": "NOT_GENERATED",
                "patch_summary": "변경 diff를 계산하지 못했습니다.",
                "patch_diff": None,
            }

        return {
            "patch_status": "GENERATED",
            "patch_summary": self._build_patch_summary(file_path, finding),
            "patch_diff": "\n".join(diff_lines),
        }

    @staticmethod
    def _build_patch_summary(file_path: str, finding: Vulnerability) -> str:
        if finding.cwe_id == "CWE-829":
            return f"{file_path} 의존성 선언에 대한 버전 상향 patch preview를 생성했습니다."
        return f"{file_path}:{finding.line_number} 기준 코드 스니펫 patch preview를 생성했습니다."
