#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Alok Kumar Mishra <alok16022006@gmail.com>
# SPDX-License-Identifier: LGPL-3.0-only

"""Embed the rz-frida agent script as a C string for the backend.

Reads the agent JavaScript and writes a header that defines a NUL terminated
byte array the backend loads into the target. Meson runs this during the build
when Python is available. The checked-in header is the fallback.

    python3 agent/embed_agent.py agent/rzfrida_agent.js src/rzfrida_agent.h
"""

import sys

BYTES_PER_ROW = 12


def render(data):
    lines = [
        "// SPDX-FileCopyrightText: 2026 Alok Kumar Mishra <alok16022006@gmail.com>",
        "// SPDX-License-Identifier: LGPL-3.0-only",
        "",
        "// Generated from agent/rzfrida_agent.js by agent/embed_agent.py.",
        "// Do not edit by hand, regenerate it after changing the agent.",
        "",
        "#ifndef RZ_FRIDA_AGENT_SOURCE_H",
        "#define RZ_FRIDA_AGENT_SOURCE_H",
        "",
        "static const char rz_frida_agent_source[] = {",
    ]
    values = ["0x%02x," % b for b in data]
    values.append("0x00")
    for start in range(0, len(values), BYTES_PER_ROW):
        lines.append("\t" + " ".join(values[start:start + BYTES_PER_ROW]))
    lines.append("};")
    lines.append("")
    lines.append("#endif")
    lines.append("")
    return "\n".join(lines)


def main(argv):
    if len(argv) != 3:
        sys.stderr.write("usage: embed_agent.py <input.js> <output.h>\n")
        return 1
    with open(argv[1], "rb") as src:
        data = src.read()
    with open(argv[2], "w", newline="\n") as out:
        out.write(render(data))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
