#!/usr/bin/env python3
"""Run one named CI command with a deadline and process-group cleanup."""

import argparse
import math
import os
import signal
import subprocess
import sys
import time


class CommandInterrupted(Exception):
    def __init__(self, signum):
        self.signum = signum


def positive_seconds(value):
    seconds = float(value)
    if not math.isfinite(seconds) or seconds <= 0:
        raise argparse.ArgumentTypeError("must be a positive finite duration")
    return seconds


def stop_processes(process, grace):
    def send(sig):
        try:
            if os.name == "posix":
                os.killpg(process.pid, sig)
            else:
                process.send_signal(sig)
        except ProcessLookupError:
            pass

    send(signal.SIGTERM)
    try:
        process.wait(timeout=grace)
    except subprocess.TimeoutExpired:
        pass
    # The parent may exit on TERM while a descendant ignores it. Always
    # finish the process group, even when waiting for the parent succeeded.
    send(signal.SIGKILL if os.name == "posix" else signal.SIGTERM)
    if os.name != "posix" and process.poll() is None:
        process.kill()
    process.wait()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--name", required=True)
    parser.add_argument("--timeout", type=positive_seconds, required=True)
    parser.add_argument("--kill-after", type=positive_seconds, default=2)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command:
        parser.error("a command is required after --")

    started = time.monotonic()
    print(f"[ci-stage] START {args.name} (timeout {args.timeout:g}s)",
          file=sys.stderr, flush=True)
    process = None

    def interrupt(signum, _frame):
        raise CommandInterrupted(signum)

    previous_handlers = {sig: signal.signal(sig, interrupt)
                         for sig in (signal.SIGINT, signal.SIGTERM)}
    try:
        try:
            process = subprocess.Popen(command, stdin=subprocess.DEVNULL,
                                       start_new_session=os.name == "posix")
        except OSError as error:
            print(f"[ci-stage] FAIL {args.name}: {error}", file=sys.stderr, flush=True)
            return 127
        try:
            code = process.wait(timeout=args.timeout)
        except subprocess.TimeoutExpired:
            print(f"[ci-stage] TIMEOUT {args.name} after {args.timeout:g}s; "
                  "terminating command process group", file=sys.stderr, flush=True)
            return 124
    except CommandInterrupted as error:
        print(f"[ci-stage] INTERRUPTED {args.name} signal={error.signum}",
              file=sys.stderr, flush=True)
        return 128 + error.signum
    finally:
        # Cleanup must survive a second cancellation signal. Also clean up
        # descendants of successful commands: an inherited output pipe can
        # otherwise keep the enclosing CI step alive after its parent exits.
        for sig in previous_handlers:
            signal.signal(sig, signal.SIG_IGN)
        try:
            if process is not None:
                stop_processes(process, args.kill_after)
        finally:
            for sig, handler in previous_handlers.items():
                signal.signal(sig, handler)
    print(f"[ci-stage] END {args.name} exit={code} "
          f"elapsed={time.monotonic() - started:.1f}s", file=sys.stderr, flush=True)
    return code if code >= 0 else 128 - code


if __name__ == "__main__":
    sys.exit(main())
