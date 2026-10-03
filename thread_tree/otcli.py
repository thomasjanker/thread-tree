"""Minimal client for the OpenThread CLI on a serial port (e.g. the USB console of an nRF52840).

Standard library only (termios; Linux/macOS). One command at a time: write the line, then collect the
output up to the terminating "Done" or "Error <n>: <message>" line.
"""

from __future__ import annotations

import os
import re
import select
import termios
import time
import tty
from types import TracebackType

_PROMPT = re.compile(r"^(?:> )+")
_LOG_LINE = re.compile(r"^\[[A-Z]\]\s")  # OpenThread log lines that may be mixed into the CLI output
_ERROR = re.compile(r"^Error\s+(\d+)\s*:?\s*(.*)$")


class OtCliError(Exception):
    """The CLI answered with 'Error <code>: <message>'."""

    def __init__(self, command: str, code: int, message: str):
        super().__init__(f"{command!r}: Error {code}: {message}")
        self.command, self.code, self.message = command, code, message


class OtCliTimeout(TimeoutError):
    """No terminating 'Done' / 'Error' line within the time limit."""


class OtCli:
    def __init__(self, port: str, timeout: float = 15.0):
        self.port, self.timeout = port, timeout
        self.fd: int | None = None
        self._commands: set[str] | None = None

    # ---- connection ---------------------------------------------------------

    def open(self) -> "OtCli":
        fd = os.open(self.port, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
        try:
            tty.setraw(fd)
            attrs = termios.tcgetattr(fd)
            attrs[2] |= termios.CLOCAL | termios.CREAD
            attrs[4] = attrs[5] = termios.B115200  # ignored by USB CDC, needed for a real UART
            termios.tcsetattr(fd, termios.TCSANOW, attrs)
        except Exception:
            os.close(fd)
            raise
        self.fd = fd
        return self

    def close(self) -> None:
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

    def __enter__(self) -> "OtCli":
        return self.open()

    def __exit__(self, exc_type: type[BaseException] | None, exc: BaseException | None,
                 tb: TracebackType | None) -> None:
        self.close()

    # ---- raw I/O ------------------------------------------------------------

    def _read(self, timeout: float) -> str:
        assert self.fd is not None, "port not open"
        ready, _, _ = select.select([self.fd], [], [], max(0.0, timeout))
        if not ready:
            return ""
        try:
            data = os.read(self.fd, 4096)
        except BlockingIOError:
            return ""
        if not data:
            raise OSError("serial port closed")
        return data.decode("utf-8", "replace")

    def _write(self, text: str) -> None:
        assert self.fd is not None, "port not open"
        data = text.encode()
        while data:
            _, writable, _ = select.select([], [self.fd], [], 5.0)
            if not writable:
                raise OSError("serial port not accepting data")
            try:
                data = data[os.write(self.fd, data):]
            except BlockingIOError:
                continue

    def _drain(self) -> None:
        while self._read(0):
            pass

    # ---- commands -----------------------------------------------------------

    def command(self, line: str, timeout: float | None = None) -> list[str]:
        """Run one CLI command and return its output lines (without echo, prompt and 'Done')."""
        limit = self.timeout if timeout is None else timeout
        self._drain()
        self._write(line + "\n")
        deadline = time.monotonic() + limit
        out: list[str] = []
        buf, echoed = "", False
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise OtCliTimeout(f"{line!r}: no response within {limit:.0f} s")
            buf += self._read(min(remaining, 0.5))
            while "\n" in buf:
                raw, buf = buf.split("\n", 1)
                text = _PROMPT.sub("", raw.replace("\r", "")).rstrip()
                if not text or _LOG_LINE.match(text):
                    continue
                if not echoed and text == line.strip():  # the device echoes what it receives
                    echoed = True
                    continue
                if text == "Done":
                    return out
                error = _ERROR.match(text)
                if error:
                    raise OtCliError(line, int(error.group(1)), error.group(2))
                out.append(text)

    def commands(self) -> set[str]:
        """Names of the commands this firmware knows (output of `help`)."""
        if self._commands is None:
            self._commands = {name.split()[0] for name in self.command("help") if name.strip()}
        return self._commands
