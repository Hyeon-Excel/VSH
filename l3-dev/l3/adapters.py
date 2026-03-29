import dataclasses
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../VSH-l1-l2-integration/VSH_Project_MVP"))

from models.common_schema import VulnRecord as PydanticVulnRecord
from models.common_schema import PackageRecord as PydanticPackageRecord
from l3.models.vuln_record import VulnRecord as L3VulnRecord
from l3.models.package_record import PackageRecord as L3PackageRecord


def l3_vuln_to_pydantic(record: L3VulnRecord) -> PydanticVulnRecord:
    d = dataclasses.asdict(record)
    d["evidence"] = d.pop("code_snippet")
    for f in ("line_number", "end_line_number", "column_number", "end_column_number"):
        if d[f] < 1:
            d[f] = 1
    return PydanticVulnRecord(**d)


def l3_package_to_pydantic(record: L3PackageRecord) -> PydanticPackageRecord:
    d = dataclasses.asdict(record)
    d["evidence"] = d.pop("code_snippet")
    return PydanticPackageRecord(**d)
