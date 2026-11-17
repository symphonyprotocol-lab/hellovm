#!/usr/bin/env python3
"""Condenses a HELLOVM_SECCOMP_LEARN file (see kernel/sandbox/src/learn.rs).

usage: learn-summary.py LEARN_FILE [UNISTD_HEADER]

Prints, per syscall, how often the kernel process made it and the distinct
values of each argument (up to 8; '*' when there were more). The header
(default: the asm unistd header of this machine) names the numbers.
"""
import collections
import glob
import re
import sys


def names(header_paths):
    table = {}
    for path in header_paths:
        try:
            text = open(path).read()
        except OSError:
            continue
        for name, nr in re.findall(r"#define __NR(?:3264)?_(\w+)\s+(\d+)\b", text):
            table.setdefault(int(nr), name)
    return table


def main():
    learn = sys.argv[1]
    headers = sys.argv[2:] or (
        glob.glob("/usr/include/asm-generic/unistd.h")
        + glob.glob("/usr/include/*/asm/unistd_64.h")
        + glob.glob("/usr/include/asm/unistd_64.h")
    )
    import platform
    if platform.machine() == "x86_64":
        headers = [h for h in headers if "asm-generic" not in h] or headers
    table = names(headers)
    count = collections.Counter()
    values = collections.defaultdict(lambda: [set() for _ in range(6)])
    for line in open(learn):
        fields = line.split()
        if len(fields) != 7:
            continue
        nr = int(fields[0], 16)
        count[nr] += 1
        for i, arg in enumerate(fields[1:]):
            values[nr][i].add(int(arg, 16))
    for nr, n in sorted(count.items()):
        args = []
        for seen in values[nr]:
            if len(seen) > 8:
                args.append("*")
            else:
                args.append("{" + ",".join(hex(v) for v in sorted(seen)) + "}")
        print(f"{nr:4} {table.get(nr, '?'):24} {n:8}  " + " ".join(args))


if __name__ == "__main__":
    main()
