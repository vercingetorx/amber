from __future__ import annotations

def norm_path(p: str) -> str:
    """Normalize archive paths to a canonical forward-slash form.

    Rules:
    - Convert backslashes to slashes
    - Strip leading/trailing slashes
    - Remove empty and '.' segments
    - Reject '..' segments
    """
    p = p.replace("\\", "/").strip("/")
    parts = [q for q in p.split("/") if q not in ("", ".")]
    for q in parts:
        if q == "..":
            raise ValueError("Path may not contain '..'")
    return "/".join(parts)

