import gzip
import os
import re
import sys

SRC = os.path.join("Antihunter", "full", "src", "web_index_html.h")


def page_text(header, sentinel):
    out, stack = [], []
    for line in header.splitlines(keepends=True):
        s = line.strip()
        if s == "#if AH_SENTINEL":
            stack.append(sentinel)
            continue
        if s == "#else":
            stack[-1] = not stack[-1]
            continue
        if s == "#endif" and stack:
            stack.pop()
            continue
        if s.startswith("#if") or s.startswith("#elif"):
            if s not in ("#ifndef AH_SENTINEL",):
                raise SystemExit("[gzip_html] unsupported directive: " + s)
        if all(stack):
            out.append(line)
    body = "".join(out)
    parts = re.findall(r'R"HTML\((.*?)\)HTML"', body, re.S)
    if not parts:
        raise SystemExit("[gzip_html] no R\"HTML( literals found")
    return "".join(parts).encode()


def emit(data, path):
    gz = gzip.compress(data, 9, mtime=0)
    rows = ",".join(str(b) for b in gz)
    text = ("#pragma once\n#include <pgmspace.h>\n#include <stddef.h>\n#include <stdint.h>\n"
            "static const uint8_t INDEX_HTML_GZ[] PROGMEM = {" + rows + "};\n"
            "static const size_t INDEX_HTML_GZ_LEN = sizeof(INDEX_HTML_GZ);\n"
            "static const size_t INDEX_HTML_RAW_LEN = " + str(len(data)) + ";\n")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if not os.path.exists(path) or open(path).read() != text:
        with open(path, "w") as f:
            f.write(text)
    return len(gz)


def sentinel_of(defines):
    for d in defines:
        if isinstance(d, (list, tuple)) and d and d[0] == "AH_SENTINEL":
            return str(d[1]) not in ("0", "")
        if isinstance(d, str) and d.split("=")[0] == "AH_SENTINEL":
            return d.split("=", 1)[1:] not in (["0"], [""])
    return True


if __name__ == "__main__":
    header = open(sys.argv[1]).read()
    sys.stdout.buffer.write(page_text(header, sys.argv[2] == "1"))
else:
    Import("env")
    proj = env.subst("$PROJECT_DIR")
    flags = env.ParseFlags(env.subst(env.get("BUILD_FLAGS", [])))
    sen = sentinel_of(list(env.get("CPPDEFINES", [])) + list(flags.get("CPPDEFINES", [])))
    raw = page_text(open(os.path.join(proj, SRC)).read(), sen)
    out = os.path.join(env.subst("$BUILD_DIR"), "gen", "web_index_html_gz.h")
    n = emit(raw, out)
    env.Append(CPPPATH=[os.path.dirname(out)])
    print("[gzip_html] AH_SENTINEL=%d raw=%d gzip=%d -> %s" % (sen, len(raw), n, out))
