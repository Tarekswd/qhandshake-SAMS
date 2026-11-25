"""Variable-latency scan (NOVELTY_PLAN.md Q-6): divide instructions and divide libcalls reachable from each
ct_* entry point of the nostd staticlib, on any target llvm-objdump understands (incl. thumbv6m, which Valgrind
cannot run).

    python3 scan_asm.py <libct_nostd.a> [objdump]

Edges come from relocations (`objdump -dr`): in an unlinked archive every cross-function call is a relocation.
Self-check: ct_control_div (a u64 division) must be flagged, otherwise exit 1.
Output: one line per entry: reachable function count, then each flagged site "function: instruction".
Flags are candidates, not leaks: the operand may be public (e.g. a loop bound). Triage by reading the source.
"""
import re
import subprocess
import sys
from collections import defaultdict

FUNC = re.compile(r"^[0-9a-f]+ <(.+)>:$")
MEMBER = re.compile(r"^(.+\.o)\)?:\s+file format")
LOCAL = re.compile(r"^OUTLINED_FUNCTION_\d+$")  # machine-outliner names repeat in every object file
RELOC = re.compile(r"\sR_\S+\s+(.+?)(?:[+-]0x[0-9a-f]+)?$")
DIV_INSN = re.compile(r"^\s*[0-9a-f]+:\s+(i?div[bwlq]?|[us]div)\b", re.I)
DIV_CALL = re.compile(r"__aeabi_[a-z]*div|__(u)?(div|mod)[sdt]i3|__[a-z]*divmod|::(u|i)?div", re.I)


def parse(lines):
    calls, flags, cur, obj = defaultdict(set), defaultdict(list), None, ""

    def name(sym):
        return f"{sym}@{obj}" if LOCAL.match(sym) else sym

    for line in lines:
        m = MEMBER.match(line)
        if m:
            obj, cur = m.group(1), None
            continue
        m = FUNC.match(line)
        if m:
            cur = name(m.group(1))
            calls[cur]  # register leaf functions too (a lone `div` has no relocation)
            continue
        if cur is None:
            continue
        m = DIV_INSN.match(line)
        if m:
            flags[cur].append(line.split(":", 1)[1].strip())
        m = RELOC.search(line)
        if m:
            tgt = name(m.group(1).strip())
            calls[cur].add(tgt)
            if DIV_CALL.search(tgt):
                flags[cur].append("call " + tgt)
    return calls, flags


def reachable(calls, root):
    seen, todo = set(), [root]
    while todo:
        f = todo.pop()
        if f not in seen:
            seen.add(f)
            todo.extend(calls.get(f, ()))
    return seen


def main(lib, objdump="llvm-objdump-18"):
    out = subprocess.run([objdump, "-dr", "-C", "--no-show-raw-insn", lib], capture_output=True, text=True, check=True)
    calls, flags = parse(out.stdout.splitlines())
    entries = sorted(f for f in calls if f.startswith("ct_"))
    ok = True
    for e in entries:
        fs = reachable(calls, e)
        sites = [f"{f}: {i}" for f in sorted(fs) for i in flags.get(f, [])]
        print(f"{e}\treachable={len(fs)}\tflags={len(sites)}")
        for s in sites:
            print(f"    {s}")
        if e == "ct_control_div" and not sites:
            ok = False
    if "ct_control_div" not in entries:
        ok = False
    if not ok:
        sys.exit("SELF-CHECK FAILED: control division not detected")


if __name__ == "__main__":
    if len(sys.argv) not in (2, 3):
        sys.exit(__doc__)
    main(*sys.argv[1:])
