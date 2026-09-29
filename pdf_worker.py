"""Resource-bounded Linux subprocess for untrusted PDF parsing.

This is a restricted child process, not a complete container sandbox: it keeps
the service UID and filesystem view. Linux seccomp blocks network and child
process syscalls; rlimits and a parent wall-clock timeout bound parser work.
"""
from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import tempfile
from typing import Any

from audit_contract import IntakeError, MAX_PAGES

WALL_TIMEOUT_SECONDS = 12
MAX_EXTRACTED_CHARS = 250_000
MAX_WORKER_OUTPUT_BYTES = 2 * 1024 * 1024

_BOOTSTRAP = r'''
import ctypes
import ctypes.util
import errno
import json
import os
import resource
import socket
import sys

MAX_BYTES = 20 * 1024 * 1024
MAX_PAGES = 300
MAX_EXTRACTED_CHARS = 250_000
MAX_ADDRESS_SPACE = 512 * 1024 * 1024
DENIED_SYSCALLS = (
    "socket", "socketpair", "connect", "bind", "listen", "accept", "accept4",
    "sendto", "sendmsg", "sendmmsg", "recvfrom", "recvmsg", "recvmmsg",
    "shutdown", "fork", "vfork", "clone", "clone3", "execve", "execveat",
)

def install_limits():
    resource.setrlimit(resource.RLIMIT_CPU, (8, 10))
    resource.setrlimit(resource.RLIMIT_AS, (MAX_ADDRESS_SPACE, MAX_ADDRESS_SPACE))
    resource.setrlimit(resource.RLIMIT_NOFILE, (32, 32))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

def install_seccomp():
    library_name = ctypes.util.find_library("seccomp")
    if not library_name:
        raise RuntimeError("seccomp unavailable")
    seccomp = ctypes.CDLL(library_name, use_errno=True)
    seccomp.seccomp_init.argtypes = [ctypes.c_uint32]
    seccomp.seccomp_init.restype = ctypes.c_void_p
    seccomp.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
    seccomp.seccomp_syscall_resolve_name.restype = ctypes.c_int
    seccomp.seccomp_rule_add.argtypes = [
        ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int, ctypes.c_uint,
    ]
    seccomp.seccomp_rule_add.restype = ctypes.c_int
    seccomp.seccomp_load.argtypes = [ctypes.c_void_p]
    seccomp.seccomp_load.restype = ctypes.c_int
    seccomp.seccomp_release.argtypes = [ctypes.c_void_p]
    seccomp.seccomp_release.restype = None

    libc = ctypes.CDLL(None, use_errno=True)
    libc.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong,
                           ctypes.c_ulong, ctypes.c_ulong]
    libc.prctl.restype = ctypes.c_int
    if libc.prctl(38, 1, 0, 0, 0) != 0:  # PR_SET_NO_NEW_PRIVS
        raise RuntimeError("no_new_privs unavailable")

    allow = 0x7FFF0000  # SCMP_ACT_ALLOW
    deny = 0x00050000 | errno.EPERM  # SCMP_ACT_ERRNO(EPERM)
    context = seccomp.seccomp_init(allow)
    if not context:
        raise RuntimeError("seccomp initialization failed")
    try:
        for name in DENIED_SYSCALLS:
            number = seccomp.seccomp_syscall_resolve_name(name.encode("ascii"))
            if number >= 0 and seccomp.seccomp_rule_add(context, deny, number, 0) != 0:
                raise RuntimeError("seccomp rule failed")
        if seccomp.seccomp_load(context) != 0:
            raise RuntimeError("seccomp load failed")
    finally:
        seccomp.seccomp_release(context)

def resolve(value):
    try:
        return value.get_object()
    except AttributeError:
        return value

def has_invoked_image(page, reader):
    from pypdf.generic import ContentStream

    seen_forms = set()

    def scan(operations, resources, depth):
        resources = resolve(resources) if resources is not None else {}
        xobjects = resolve(resources.get("/XObject", {}))
        for operands, operator in operations:
            if operator != b"Do" or not operands:
                continue
            name = operands[0]
            target = resolve(xobjects.get(name))
            if target is None:
                continue
            subtype = str(target.get("/Subtype", ""))
            if subtype == "/Image":
                return True
            if subtype == "/Form" and depth < 4 and id(target) not in seen_forms:
                seen_forms.add(id(target))
                form_resources = target.get("/Resources", resources)
                form_stream = ContentStream(target, reader)
                if scan(form_stream.operations, form_resources, depth + 1):
                    return True
        return False

    contents = page.get_contents()
    if contents is None:
        return False, False
    return scan(contents.operations, page.get("/Resources", {}), 0), bool(contents.operations)

def coverage_for(page, text, reader):
    has_text = bool(text.strip())
    try:
        has_image, has_operations = has_invoked_image(page, reader)
    except Exception:
        # Parsing already succeeded; retain explicit uncertainty if resource
        # inspection cannot classify unusual drawing operators.
        has_image, has_operations = False, True
    controls = sum(1 for char in text
                   if ord(char) < 32 and char not in "\t\n\r\f")
    if "\ufffd" in text or (text and controls / len(text) > 0.02):
        return "garbled"
    if has_text and has_image:
        return "mixed"
    if has_text:
        return "text_extracted"
    if has_image:
        return "image_only"
    if page.get("/Annots") or has_operations:
        return "unclassified_content"
    return "blank"

def parse(data):
    from io import BytesIO
    from pypdf import PdfReader

    if not data:
        return {"error": "EMPTY_FILE"}
    if len(data) > MAX_BYTES:
        return {"error": "FILE_TOO_LARGE"}
    reader = PdfReader(BytesIO(data), strict=True)
    if reader.is_encrypted:
        return {"error": "ENCRYPTED_PDF"}
    if not 1 <= len(reader.pages) <= MAX_PAGES:
        return {"error": "PAGE_LIMIT"}
    rows = []
    total_chars = 0
    for index, page in enumerate(reader.pages, start=1):
        text = page.extract_text() or ""
        total_chars += len(text)
        if total_chars > MAX_EXTRACTED_CHARS:
            return {"error": "PDF_TEXT_LIMIT"}
        rows.append({
            "number": index,
            "text": text,
            "coverage_status": coverage_for(page, text, reader),
        })
    return {"pages": rows}

def main():
    self_test = "--self-test" in sys.argv
    try:
        install_limits()
        if self_test:
            os.write(2, b"limits-installed\n")
        install_seccomp()
        if self_test:
            os.write(2, b"seccomp-installed\n")
    except Exception:
        sys.stdout.write(json.dumps({"error": "PDF_WORKER_ISOLATION_UNAVAILABLE"}))
        return 0
    if self_test:
        try:
            socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        except OSError as exc:
            blocked = exc.errno == errno.EPERM
        else:
            blocked = False
        limits = {
            "cpu": resource.getrlimit(resource.RLIMIT_CPU),
            "address_space": resource.getrlimit(resource.RLIMIT_AS),
            "open_files": resource.getrlimit(resource.RLIMIT_NOFILE),
            "core": resource.getrlimit(resource.RLIMIT_CORE),
        }
        sys.stdout.write(json.dumps({"network_blocked": blocked, "limits": limits}))
        return 0 if blocked else 1
    try:
        data = sys.stdin.buffer.read(MAX_BYTES + 1)
        result = parse(data)
    except MemoryError:
        result = {"error": "PDF_RESOURCE_LIMIT"}
    except Exception:
        result = {"error": "PDF_PARSE_FAILED"}
    sys.stdout.write(json.dumps(result, ensure_ascii=False, separators=(",", ":")))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
'''


def _run_worker(data: bytes = b"", *, self_test: bool = False) -> dict[str, Any]:
    command = [sys.executable, "-I", "-B", "-c", _BOOTSTRAP]
    if self_test:
        command.append("--self-test")
    env = {"PATH": os.defpath, "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"}
    try:
        result = subprocess.run(
            command,
            input=data,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE if self_test else subprocess.DEVNULL,
            cwd=tempfile.gettempdir(),
            env=env,
            timeout=WALL_TIMEOUT_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired:
        raise IntakeError("PDF_TIMEOUT") from None
    except OSError:
        raise IntakeError("PDF_WORKER_UNAVAILABLE") from None

    if result.returncode != 0:
        if self_test:
            marker = result.stderr.decode("ascii", errors="ignore").strip().splitlines()
            stage = marker[-1] if marker else "before-limits"
            raise IntakeError(f"PDF_WORKER_SELF_TEST_FAILED_{stage}")
        signal_errors = {
            -signal.SIGXCPU: "PDF_CPU_LIMIT",
            -signal.SIGKILL: "PDF_WORKER_KILLED",
            -signal.SIGSEGV: "PDF_WORKER_CRASHED",
        }
        if result.returncode in signal_errors:
            raise IntakeError(signal_errors[result.returncode])
        raise IntakeError("PDF_WORKER_FAILED")
    if len(result.stdout) > MAX_WORKER_OUTPUT_BYTES:
        raise IntakeError("PDF_TEXT_LIMIT")
    try:
        payload = json.loads(result.stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise IntakeError("PDF_WORKER_PROTOCOL_FAILED") from None
    if not isinstance(payload, dict):
        raise IntakeError("PDF_WORKER_PROTOCOL_FAILED")
    error = payload.get("error")
    if error is not None:
        if not isinstance(error, str) or not error.isascii():
            raise IntakeError("PDF_WORKER_PROTOCOL_FAILED")
        raise IntakeError(error)
    return payload


def parse_pdf_isolated(data: bytes) -> tuple[dict[str, Any], ...]:
    """Return bounded page data from a no-network, rlimit-bounded child."""
    payload = _run_worker(data)
    pages = payload.get("pages")
    if not isinstance(pages, list) or not 1 <= len(pages) <= MAX_PAGES:
        raise IntakeError("PDF_WORKER_PROTOCOL_FAILED")
    for index, page in enumerate(pages, start=1):
        status = page.get("coverage_status") if isinstance(page, dict) else None
        if (not isinstance(page, dict)
                or type(page.get("number")) is not int
                or page.get("number") != index
                or not isinstance(page.get("text"), str)
                or not isinstance(status, str)
                or status not in {
                    "text_extracted", "mixed", "image_only", "blank",
                    "unclassified_content", "garbled",
                }):
            raise IntakeError("PDF_WORKER_PROTOCOL_FAILED")
    return tuple(pages)


def check_worker_isolation() -> dict[str, Any]:
    """Run a synthetic self-test of Linux resource limits and network denial."""
    result = _run_worker(self_test=True)
    if result.get("network_blocked") is not True:
        raise IntakeError("PDF_WORKER_ISOLATION_UNAVAILABLE")
    return result
