"""Tool-grant parity: the eval's cases must get the same answers with grants enforced as without (task 3.7).

    python -m gateway.tests.parity_eval --pack eval_pack --off http://localhost:18082 --on http://localhost:18182

Runs every eval case against both gateways and compares status, decision, reason code and result data.
Exits 1 and lists the cases that differ.
"""

import argparse
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

from gateway.eval import run_cases


def poster(url: str, log: list):
    def post(body):
        req = urllib.request.Request(  # noqa: S310
            f"{url}/tools/call", data=json.dumps(body).encode(), headers={"content-type": "application/json"}
        )
        try:
            with urllib.request.urlopen(req) as resp:  # noqa: S310
                status, data = resp.status, json.load(resp)
        except urllib.error.HTTPError as e:
            status, data = e.code, json.loads(e.read())
        d = data.get("decision", {})
        log.append((status, d.get("decision"), d.get("reason_code"), data.get("result"), data.get("error")))
        return status, data

    return post


def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--pack", type=Path, required=True)
    p.add_argument("--off", required=True, help="gateway whose servers run with TOOL_GRANTS=off")
    p.add_argument("--on", required=True, help="gateway whose servers run with TOOL_GRANTS=enforce")
    a = p.parse_args(argv)
    off_log, on_log = [], []
    lines = [line for _, line in run_cases(a.pack, poster(a.off, off_log))]
    run_cases(a.pack, poster(a.on, on_log))
    diffs = [(line, x, y) for line, x, y in zip(lines, off_log, on_log, strict=True) if x != y]
    for line, x, y in diffs:
        print(f"DIFF {line}")
        print(f"  off: {x[:3]} rows={len(x[3] or [])} err={x[4]}")
        print(f"  on:  {y[:3]} rows={len(y[3] or [])} err={y[4]}")
    print(f"{len(lines) - len(diffs)}/{len(lines)} cases identical with tool grants enforced")
    sys.exit(1 if diffs else 0)


if __name__ == "__main__":
    main()
