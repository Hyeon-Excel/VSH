from __future__ import annotations

from abc import ABC, abstractmethod
import re

class RegistryProvider(ABC):
    @abstractmethod
    def verify_package(self, ecosystem: str, package_name: str, version: str | None) -> dict[str, str | None]:
        raise NotImplementedError


class OfflineRegistryProvider(RegistryProvider):
    def verify_package(self, ecosystem: str, package_name: str, version: str | None) -> dict[str, str | None]:
        if not re.match(r"^[a-zA-Z0-9_\-.@/]+$", package_name):
            return {"registry_status": "INVALID", "registry_summary": "패키지명에 허용되지 않는 문자가 포함되어 있습니다."}
        if version and not re.match(r"^[a-zA-Z0-9_\-.+]+$", version):
            return {"registry_status": "INVALID", "registry_summary": "버전 문자열 형식이 비정상입니다."}
        detail = f"offline heuristic 검증: {ecosystem}:{package_name}" + (f"=={version}" if version else " (version missing)")
        return {"registry_status": "FOUND", "registry_summary": detail}


class OnlineRegistryProvider(RegistryProvider):
    def verify_package(self, ecosystem: str, package_name: str, version: str | None) -> dict[str, str | None]:
        return {
            "registry_status": "UNIMPLEMENTED",
            "registry_summary": "online registry 조회 provider 확장 포인트(기본 비활성).",
        }
