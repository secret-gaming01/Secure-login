"""Répare l'encodage mojibake (UTF-8 -> CP1252 -> réécrit) ligne par ligne."""
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]


def unmojibake_line(line: str) -> str:
    best = line
    cur = line
    for _ in range(2):  # gère simple et double encodage
        try:
            raw = bytearray()
            for ch in cur:
                try:
                    raw += ch.encode("cp1252")
                except UnicodeEncodeError:
                    raw += ch.encode("utf-8")
            cur = raw.decode("utf-8")
        except (UnicodeEncodeError, UnicodeDecodeError):
            break
        best = cur
    return best


def fix_text(text: str) -> str:
    return "\n".join(unmojibake_line(l) for l in text.split("\n"))


changed = []
for pat in ("**/*.rs", "**/*.md", "**/*.yml", "**/*.toml", ".env.example"):
    for p in ROOT.glob(pat):
        parts_lower = {part.lower() for part in p.parts}
        if ".git" in parts_lower or "target" in parts_lower:
            continue
        raw = p.read_text(encoding="utf-8")
        new = fix_text(raw)
        if new != raw:
            p.write_text(new, encoding="utf-8", newline="\n")
            changed.append(str(p.relative_to(ROOT)))

print(f"{len(changed)} fichier(s) réparé(s)")
for c in changed:
    print(" -", c)
sys.exit(0)
