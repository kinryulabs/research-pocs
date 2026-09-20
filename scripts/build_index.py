#!/usr/bin/env python3
"""Regenerate root README.md from every metadata.yaml in the repo."""
import pathlib
import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
TAXONOMY = ROOT / "TAXONOMY.md"


def load_valid_tags() -> set[str]:
    if not TAXONOMY.exists():
        return set()
    tags = set()
    for line in TAXONOMY.read_text().splitlines():
        line = line.strip()
        if line.startswith("- `") and line.endswith("`"):
            tags.add(line[3:-1])
    return tags


def collect() -> list[dict]:
    entries = []
    for meta in ROOT.glob("20*/*/*/metadata.yaml"):
        data = yaml.safe_load(meta.read_text())
        data["_path"] = meta.parent.relative_to(ROOT).as_posix()
        entries.append(data)
    return sorted(entries, key=lambda d: str(d.get("date", "")), reverse=True)


def validate(entries: list[dict], valid_tags: set[str]) -> None:
    if not valid_tags:
        return
    errors = []
    for e in entries:
        for t in e.get("classification", {}).get("tags", []):
            if t not in valid_tags:
                errors.append(f"{e['_path']}: unknown tag '{t}'")
    if errors:
        raise SystemExit("Tag validation failed:\n" + "\n".join(errors))


def render(entries: list[dict]) -> str:
    lines = [
        "# Research PoCs",
        "",
        f"{len(entries)} entries. This index is auto-generated — do not edit by hand.",
        "",
        "| Date | Title | Target | Tags | IDs | Status |",
        "|---|---|---|---|---|---|",
    ]
    for e in entries:
        cls = e.get("classification", {})
        tgt = e.get("target", {})
        ids = e.get("identifiers", {})
        id_str = " ".join(
            str(v) for v in (ids.get("cve"), ids.get("ghsa"), ids.get("internal")) if v
        ) or "—"
        tags = ", ".join(f"`{t}`" for t in cls.get("tags", [])) or "—"
        title = f"[{e.get('title', '?')}]({e['_path']}/)"
        lines.append(
            f"| {e.get('date', '?')} | {title} | {tgt.get('product', '—')} "
            f"| {tags} | {id_str} | {e.get('status', '—')} |"
        )
    return "\n".join(lines) + "\n"


def main() -> None:
    valid = load_valid_tags()
    entries = collect()
    validate(entries, valid)
    (ROOT / "README.md").write_text(render(entries))
    print(f"Wrote index with {len(entries)} entries.")


if __name__ == "__main__":
    main()
