"""
PDF Report Generator — Markdown → PDF (NotoSansKR, reportlab)

weasyprint requires GTK3 native DLLs unavailable on Windows;
reportlab is used instead with the same NotoSansKR font.
"""
import re
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    HRFlowable,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
)

FONT_PATH = "C:/Windows/Fonts/NotoSansKR-VF.ttf"

_EMOJI_RE = re.compile(
    "["
    "\U0001F600-\U0001F64F"
    "\U0001F300-\U0001F5FF"
    "\U0001F680-\U0001F6FF"
    "\U0001F900-\U0001F9FF"
    "\U0001FA00-\U0001FA6F"
    "\U0001FA70-\U0001FAFF"
    "\u2705\u274C\u26A0\u2714\u2716\u2753\u2754\u2755"
    "\u2640-\u2642\u2600-\u26FF"
    "]",
    flags=re.UNICODE,
)

_SEVERITY_COLORS = {
    "CRITICAL": colors.HexColor("#c62828"),
    "HIGH":     colors.HexColor("#e65100"),
    "MEDIUM":   colors.HexColor("#f9a825"),
    "LOW":      colors.HexColor("#2e7d32"),
}

_SECTION_KEYWORDS = (
    "VSH ", "보안 점수", "종합 보안", "취약점 상세",
    "SBOM", "개발자 조치", "진단일시", "진단엔진", "적용기준",
)


def _strip_emoji(text: str) -> str:
    return _EMOJI_RE.sub("", text)


def _xml_escape(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _is_rule_line(text: str) -> bool:
    stripped = text.strip()
    return bool(stripped) and set(stripped) <= {"=", "-", "─"} and len(stripped) >= 4


class PDFReportGenerator:
    """Markdown 보안 리포트를 PDF로 변환한다."""

    def generate(self, md_path: str) -> str:
        """md_path의 .md 파일을 읽어 동일 경로에 .pdf를 생성하고 경로를 반환한다."""
        pdf_path = str(Path(md_path).with_suffix(".pdf"))

        # 폰트 등록
        try:
            pdfmetrics.registerFont(TTFont("NotoSansKR", FONT_PATH))
            font = "NotoSansKR"
        except Exception:
            font = "Helvetica"

        styles = self._make_styles(font)

        doc = SimpleDocTemplate(
            pdf_path,
            pagesize=A4,
            leftMargin=20 * mm,
            rightMargin=20 * mm,
            topMargin=20 * mm,
            bottomMargin=20 * mm,
        )

        with open(md_path, "r", encoding="utf-8") as f:
            lines = f.readlines()

        story = self._build_story(lines, styles)
        doc.build(story)
        return pdf_path

    # ── 내부 메서드 ────────────────────────────────────────────────────

    def _make_styles(self, font: str) -> dict:
        base = dict(fontName=font, wordWrap="CJK")
        return {
            "normal": ParagraphStyle("n", **base, fontSize=9, leading=14),
            "section": ParagraphStyle(
                "s", **base, fontSize=12, leading=18,
                spaceBefore=8, spaceAfter=3,
                textColor=colors.HexColor("#1565c0"),
            ),
            "score": ParagraphStyle(
                "sc", **base, fontSize=10, leading=15,
                textColor=colors.HexColor("#37474f"),
            ),
            "detail": ParagraphStyle(
                "d", **base, fontSize=8, leading=12,
                leftIndent=10,
                textColor=colors.HexColor("#546e7a"),
            ),
            "footer": ParagraphStyle(
                "f", **base, fontSize=8, leading=12,
                textColor=colors.HexColor("#9e9e9e"),
            ),
            **{
                sev: ParagraphStyle(
                    f"sev_{sev}", **base,
                    fontSize=9, leading=14,
                    textColor=col,
                )
                for sev, col in _SEVERITY_COLORS.items()
            },
        }

    def _build_story(self, lines: list[str], styles: dict) -> list:
        story: list = []

        for raw_line in lines:
            line = raw_line.rstrip("\n")
            clean = _strip_emoji(line).rstrip()

            # 빈 줄
            if not clean.strip():
                story.append(Spacer(1, 2 * mm))
                continue

            # 구분선
            if _is_rule_line(clean):
                story.append(
                    HRFlowable(
                        width="100%", thickness=0.5,
                        color=colors.HexColor("#b0bec5"),
                        spaceAfter=2,
                    )
                )
                continue

            # [SEVERITY] 태그로 시작하는 취약점 라인
            sev_match = re.match(r"^\[(CRITICAL|HIGH|MEDIUM|LOW)\]", clean)
            if sev_match:
                sev = sev_match.group(1)
                story.append(
                    Paragraph(_xml_escape(clean), styles[sev])
                )
                continue

            # 섹션 헤더
            if any(kw in clean for kw in _SECTION_KEYWORDS):
                story.append(
                    Paragraph(_xml_escape(clean), styles["section"])
                )
                continue

            # 점수/통계 라인 (항목 + 숫자 패턴)
            if re.search(r"\d+\s*/\s*\d+|\d+건|\d+개|\d+%", clean):
                story.append(
                    Paragraph(_xml_escape(clean), styles["score"])
                )
                continue

            # 들여쓰기 상세 라인 (2+spaces or *)
            if clean.startswith("  ") or clean.startswith("* "):
                story.append(
                    Paragraph(_xml_escape(clean), styles["detail"])
                )
                continue

            # 푸터 라인 (본 리포트는...)
            if "본 리포트" in clean or "최종 보안" in clean:
                story.append(
                    Paragraph(_xml_escape(clean), styles["footer"])
                )
                continue

            # 기본 라인
            story.append(
                Paragraph(_xml_escape(clean), styles["normal"])
            )

        return story
