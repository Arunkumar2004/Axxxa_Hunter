import re
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "agents"
DST = ROOT / ".opencode" / "agents"

DST.mkdir(parents=True, exist_ok=True)

for path in sorted(SRC.glob("*.md")):
    text = path.read_text(encoding="utf-8")
    if not text.startswith("---\n"):
        shutil.copy2(path, DST / path.name)
        continue
    lines = text.splitlines(keepends=True)
    fm_end = lines.index("---\n", 1)
    fm = lines[1:fm_end]
    body = "".join(lines[fm_end + 1:])

    description = ""
    keep = []
    for line in fm:
        if line.startswith("description:"):
            description = line[len("description:"):].strip()
        elif line.startswith("model:"):
            continue
        elif line.startswith("tools:"):
            continue
        elif re.match(r"^\s+[a-z_]+:\s*(true|false)\s*$", line):
            continue
        else:
            keep.append(line)

    out = ["---\n"]
    out.append(f"description: {description}\n")
    out.append("mode: subagent\n")
    out.extend(keep)
    out.append("---\n")
    out.append(body)

    (DST / path.name).write_text("".join(out), encoding="utf-8")
    print(f"converted {path.name}")

# Prune stale generated agents: .opencode/agents is fully derived from agents/,
# so remove any file there without a root source (root = single source of truth).
_src_agents = {p.name for p in SRC.glob("*.md")}
for gen in DST.glob("*.md"):
    if gen.name not in _src_agents:
        gen.unlink()
        print(f"pruned stale agent {gen.name}")

CMD_SRC = ROOT / "commands"
CMD_DST = ROOT / ".opencode" / "commands"
CMD_DST.mkdir(parents=True, exist_ok=True)
for path in sorted(CMD_SRC.glob("*.md")):
    shutil.copy2(path, CMD_DST / path.name)
_src_cmds = {p.name for p in CMD_SRC.glob("*.md")}
for gen in CMD_DST.glob("*.md"):
    if gen.name not in _src_cmds:
        gen.unlink()
        print(f"pruned stale command {gen.name}")
print(f"copied {len(list(CMD_SRC.glob('*.md')))} commands")
