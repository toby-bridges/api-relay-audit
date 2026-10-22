"""Behavior checks for the CI command deadline wrapper's public CLI."""

import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest


RUNNER = Path(__file__).with_name("run-ci-command.py")


def process_is_running(pid):
    """Treat exited zombies as stopped, even before the OS reaps them."""
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    result = subprocess.run(
        ["ps", "-o", "stat=", "-p", str(pid)],
        capture_output=True,
        text=True,
        timeout=2,
    )
    state = result.stdout.strip()
    return bool(state) and not state.startswith("Z")


def kill_fixture_processes(paths):
    """Do not leave sleepers behind if the wrapper or an assertion fails."""
    for path in paths:
        if path.is_file():
            try:
                os.kill(
                    int(path.read_text()),
                    signal.SIGKILL if os.name == "posix" else signal.SIGTERM,
                )
            except ProcessLookupError:
                pass


class RunCICommandTests(unittest.TestCase):
    def invoke(self, code, *, timeout=3, name="fixture", args=(), input=None,
               kill_after=None):
        command = [
            sys.executable, str(RUNNER), "--timeout", str(timeout),
            "--name", name,
        ]
        if kill_after is not None:
            command.extend(["--kill-after", str(kill_after)])
        command.extend(["--", sys.executable, "-c", code, *map(str, args)])
        started = time.monotonic()
        result = subprocess.run(
            command, input=input, capture_output=True, text=True, timeout=8,
        )
        return result, time.monotonic() - started

    def test_success_preserves_stdout_stderr_and_zero_exit(self):
        result, _ = self.invoke(
            "import sys; print('stdout fixture'); "
            "print('stderr fixture', file=sys.stderr)"
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("stdout fixture", result.stdout)
        self.assertIn("stderr fixture", result.stderr)

    def test_nonzero_exit_and_output_are_preserved(self):
        result, _ = self.invoke(
            "import sys; print('before failure'); "
            "print('failure detail', file=sys.stderr); sys.exit(7)"
        )
        self.assertEqual(result.returncode, 7, result.stderr)
        self.assertIn("before failure", result.stdout)
        self.assertIn("failure detail", result.stderr)

    def test_command_stdin_is_devnull(self):
        result, _ = self.invoke(
            "import sys; print(repr(sys.stdin.read()))",
            input="this must not reach the wrapped command\n",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "''")

    def test_short_timeout_returns_124_promptly_with_named_diagnostic(self):
        with tempfile.TemporaryDirectory(prefix="ci-short-deadline-") as temp:
            pid_path = Path(temp) / "command.pid"
            try:
                result, elapsed = self.invoke(
                    "import os, pathlib, sys, time; "
                    "pathlib.Path(sys.argv[1]).write_text(str(os.getpid())); "
                    "time.sleep(60)",
                    args=(pid_path,), timeout=0.2, kill_after=0.1,
                    name="short-deadline-fixture",
                )
                self.assertEqual(result.returncode, 124, result.stderr)
                self.assertLess(elapsed, 4, "The deadline must bound the command run")
                self.assertIn("short-deadline-fixture", result.stderr)
                self.assertIn("timeout", result.stderr.lower())
            finally:
                kill_fixture_processes((pid_path,))

    def assert_process_group_stops(self, *, parent_ignores_term):
        with tempfile.TemporaryDirectory(prefix="ci-deadline-fixture-") as temp:
            temp = Path(temp)
            parent_pid = temp / "parent.pid"
            child_pid = temp / "child.pid"
            parent_term = temp / "parent-term.txt"
            child_code = """
import os
from pathlib import Path
import signal
import sys
import time
signal.signal(signal.SIGTERM, signal.SIG_IGN)
Path(sys.argv[1]).write_text(str(os.getpid()))
time.sleep(60)
"""
            parent_code = """
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

def terminate(signum, frame):
    Path(sys.argv[3]).write_text('TERM')
    raise SystemExit(0)

signal.signal(signal.SIGTERM, signal.SIG_IGN if sys.argv[4] == 'ignore' else terminate)
Path(sys.argv[1]).write_text(str(os.getpid()))
subprocess.Popen([sys.executable, '-c', sys.argv[5], sys.argv[2]])
while True:
    time.sleep(0.05)
"""
            try:
                result, elapsed = self.invoke(
                    parent_code, timeout=0.8, kill_after=0.15,
                    name="process-group-fixture",
                    args=(parent_pid, child_pid, parent_term,
                          "ignore" if parent_ignores_term else "exit", child_code),
                )
                self.assertTrue(parent_pid.is_file(), "Parent did not start")
                self.assertTrue(child_pid.is_file(), "Descendant did not start")
                self.assertEqual(result.returncode, 124, result.stderr)
                self.assertLess(elapsed, 4)
                self.assertIn("process-group-fixture", result.stderr)
                self.assertIn("timeout", result.stderr.lower())
                if not parent_ignores_term:
                    self.assertEqual(parent_term.read_text(), "TERM")
                pids = [int(path.read_text()) for path in (parent_pid, child_pid)]
                deadline = time.monotonic() + 2
                while any(process_is_running(pid) for pid in pids):
                    if time.monotonic() >= deadline:
                        self.fail("A timed-out command left a running descendant")
                    time.sleep(0.03)
            finally:
                kill_fixture_processes((parent_pid, child_pid))

    def start_heartbeat_tree(self, temp, *, parent_exits):
        parent_pid = temp / "parent.pid"
        child_pid = temp / "child.pid"
        child_code = """
import os
from pathlib import Path
import signal
import sys
import time
signal.signal(signal.SIGTERM, signal.SIG_IGN)
print('fixture heartbeat', flush=True)
Path(sys.argv[1]).write_text(str(os.getpid()))
while True:
    print('fixture heartbeat', flush=True)
    time.sleep(0.05)
"""
        parent_code = """
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
signal.signal(signal.SIGTERM, signal.SIG_IGN)
Path(sys.argv[1]).write_text(str(os.getpid()))
subprocess.Popen([sys.executable, '-c', sys.argv[4], sys.argv[2]])
while not Path(sys.argv[2]).is_file():
    time.sleep(0.01)
if sys.argv[3] == 'exit':
    print('fixture parent finished', flush=True)
else:
    while True:
        time.sleep(0.05)
"""
        command = [
            sys.executable, str(RUNNER), "--timeout", "1" if parent_exits else "20",
            "--kill-after", "0.1", "--name", "heartbeat-fixture", "--",
            sys.executable, "-c", parent_code, str(parent_pid), str(child_pid),
            "exit" if parent_exits else "wait", child_code,
        ]
        process = subprocess.Popen(
            command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        return process, (parent_pid, child_pid)

    def cleanup_heartbeat_tree(self, process, pid_paths):
        kill_fixture_processes(pid_paths)
        if process.poll() is None:
            process.kill()
        process.communicate(timeout=2)

    @unittest.skipUnless(os.name == "posix", "Process groups require POSIX")
    def test_success_cleans_background_descendant_and_delivers_stdout_eof(self):
        with tempfile.TemporaryDirectory(prefix="ci-success-background-") as temp:
            process, pid_paths = self.start_heartbeat_tree(Path(temp), parent_exits=True)
            started = time.monotonic()
            try:
                try:
                    stdout, stderr = process.communicate(timeout=1.8)
                except subprocess.TimeoutExpired:
                    self.fail(
                        "Successful parent left a heartbeat descendant holding stdout "
                        "open beyond the command deadline"
                    )
                self.assertEqual(process.returncode, 0, stderr)
                self.assertLess(time.monotonic() - started, 2.5)
                self.assertIn("fixture parent finished", stdout)
                self.assertIn("fixture heartbeat", stdout)
                self.assertTrue(pid_paths[1].is_file(), "Descendant did not start")
                self.assertFalse(process_is_running(int(pid_paths[1].read_text())))
            finally:
                self.cleanup_heartbeat_tree(process, pid_paths)

    @unittest.skipUnless(os.name == "posix", "Process groups require POSIX")
    def test_wrapper_sigterm_cleans_command_group_and_returns_143(self):
        with tempfile.TemporaryDirectory(prefix="ci-wrapper-sigterm-") as temp:
            process, pid_paths = self.start_heartbeat_tree(Path(temp), parent_exits=False)
            try:
                ready_deadline = time.monotonic() + 1
                while not all(path.is_file() for path in pid_paths):
                    if time.monotonic() >= ready_deadline:
                        self.fail("Command and descendant did not become ready")
                    time.sleep(0.01)
                process.send_signal(signal.SIGTERM)
                try:
                    _, stderr = process.communicate(timeout=1.8)
                except subprocess.TimeoutExpired:
                    self.fail(
                        "SIGTERM left the command's new session running and output "
                        f"pipes open (wrapper return code: {process.poll()})"
                    )
                self.assertEqual(process.returncode, 143, stderr)
                for path in pid_paths:
                    self.assertFalse(process_is_running(int(path.read_text())))
            finally:
                self.cleanup_heartbeat_tree(process, pid_paths)

    @unittest.skipUnless(os.name == "posix", "Process groups require POSIX")
    def test_timeout_kills_descendant_even_after_parent_exits_on_term(self):
        self.assert_process_group_stops(parent_ignores_term=False)

    @unittest.skipUnless(os.name == "posix", "Process groups require POSIX")
    def test_timeout_kills_parent_and_descendant_that_ignore_term(self):
        self.assert_process_group_stops(parent_ignores_term=True)


if __name__ == "__main__":
    unittest.main()
