# 🛡️ VSH 보안 진단 리포트

**프로젝트명** : demo_targets
**진단일시**   : 2026-02-20 18:35:45
**진단엔진**   : VSH v1.0 (Semgrep + SBOM + OSV + Registry Check)

## 📊 종합 보안 점수 : 85 / 100

## 🚨 코드 취약점
### [HIGH] XSS 가능성: 사용자 입력이 innerHTML로 직접 삽입됩니다. — `js_xss.js:2`
- **ID**           : VSH-JS-XSS-001
- **CWE**          : CWE-79
- **CVE**          : CVE-2022-25858
- **CVSS**         : 8.2
- **Reachability** : NO
- **메시지**       : XSS 가능성: 사용자 입력이 innerHTML로 직접 삽입됩니다.
- **조치**         : document.getElementById("output").textContent = userInput;
- **참고**         : KISA 시큐어코딩 가이드 - 입력데이터 검증 및 표현, OWASP Top 10 - XSS

## 📦 공급망 / 라이브러리 취약점 (OSV)
- 탐지된 라이브러리 취약점 없음(또는 조회 실패)

## 🧨 패키지 환각 / 존재성 이상
- 의심 패키지 없음