def check_xss(payload: str) -> bool:
    try:
        template = f"<div>{payload}</div>"
        lower_template = template.lower()

        patterns = [
            "<script",
            "javascript:",
            "onerror=",
            "onload="
        ]

        for pattern in patterns:
            if pattern in lower_template:
                return True
        return False
    except Exception:
        return False
