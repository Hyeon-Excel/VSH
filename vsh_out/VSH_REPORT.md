# 🛡️ VSH 보안 진단 리포트

**프로젝트명** : demo_targets
**진단일시**   : 2026-02-20 18:35:36
**진단엔진**   : VSH v1.0 (Semgrep + SBOM + OSV + Registry Check)

## 📊 종합 보안 점수 : 65 / 100

## 🚨 코드 취약점
### [CRITICAL] SQL Injection 가능성: 사용자 입력이 쿼리에 직접 결합됩니다. — `python_sqli.py:5`
- **ID**           : VSH-PY-SQLI-001
- **CWE**          : CWE-89
- **CVE**          : CVE-2023-32315
- **CVSS**         : 9.8
- **Reachability** : YES
- **메시지**       : SQL Injection 가능성: 사용자 입력이 쿼리에 직접 결합됩니다.
- **조치**         : query = "SELECT * FROM users WHERE id = %s"; cursor.execute(query, (user_input,))
- **참고**         : KISA 시큐어코딩 가이드 - 입력데이터 검증 및 표현

## 📦 공급망 / 라이브러리 취약점 (OSV)
- 탐지된 라이브러리 취약점 없음(또는 조회 실패)

## 🧨 패키지 환각 / 존재성 이상
- ❌ 레지스트리 미존재 의심: `reqeusts`