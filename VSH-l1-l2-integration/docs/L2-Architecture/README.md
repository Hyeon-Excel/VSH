# VSH Layer 2 Documentation

이 폴더는 VSH 프로젝트의 Layer 2 설계와 실행 계획을 섹션별로 정리한 문서 모음이다.

읽는 순서는 아래를 권장한다.

1. [01-context-and-role.md](/Users/hyeonexcel/Documents/Workspace/VSH/docs/L2-Architecture/01-context-and-role.md)
2. [02-goals-scope-and-contracts.md](/Users/hyeonexcel/Documents/Workspace/VSH/docs/L2-Architecture/02-goals-scope-and-contracts.md)
3. [03-architecture.md](/Users/hyeonexcel/Documents/Workspace/VSH/docs/L2-Architecture/03-architecture.md)
4. [04-branch-strategy.md](/Users/hyeonexcel/Documents/Workspace/VSH/docs/L2-Architecture/04-branch-strategy.md)
5. [05-roadmap-and-milestones.md](/Users/hyeonexcel/Documents/Workspace/VSH/docs/L2-Architecture/05-roadmap-and-milestones.md)
6. [06-testing-and-risks.md](/Users/hyeonexcel/Documents/Workspace/VSH/docs/L2-Architecture/06-testing-and-risks.md)
7. [07-next-actions.md](/Users/hyeonexcel/Documents/Workspace/VSH/docs/L2-Architecture/07-next-actions.md)

문서 구성 원칙은 다음과 같다.

- 현재 실제 L2 구현 기준선은 `VSH_Project_MVP/layer2`와 `VSH_Project_MVP/orchestration`이다
- `src/vsh`는 과거 검토 흔적으로만 남아 있으며 현재 구현 기준선이 아니다
- `layer2` 브랜치를 L2 통합 브랜치로 운영한다
- 구현 전 계약과 구조를 먼저 고정한다
