"""Resource-bounded Bubblewrap sandbox for untrusted PDF parsing."""
from __future__ import annotations

import ctypes.util
import json
import os
import shutil
import signal
import subprocess
import sys
import sysconfig
import tempfile
from pathlib import Path
from typing import Any

from audit_contract import IntakeError, MAX_PAGES

WALL_TIMEOUT_SECONDS = 12
MAX_EXTRACTED_CHARS = 250_000
MAX_WORKER_OUTPUT_BYTES = 2 * 1024 * 1024
SANDBOX_TMPFS_BYTES = 64 * 1024 * 1024

_NAMESPACE_NAMES = ("user", "mnt", "pid")

_BOOTSTRAP = r'''
import ctypes
import errno
import json
import os
import resource
import socket
import sys
import tempfile

MAX_BYTES = 20 * 1024 * 1024
MAX_PAGES = 300
MAX_EXTRACTED_CHARS = 250_000
MAX_ADDRESS_SPACE = 512 * 1024 * 1024
DENIED_SYSCALLS = (
    "socket", "socketpair", "connect", "bind", "listen", "accept", "accept4",
    "sendto", "sendmsg", "sendmmsg", "recvfrom", "recvmsg", "recvmmsg",
    "shutdown", "socketcall", "fork", "vfork", "clone", "clone3", "execve", "execveat",
    "unshare", "setns", "mount", "umount2", "pivot_root", "open_by_handle_at",
    "io_uring_setup", "io_uring_enter", "io_uring_register", "bpf",
    "userfaultfd", "ptrace", "process_vm_readv", "process_vm_writev",
    "perf_event_open",
)

def install_limits():
    resource.setrlimit(resource.RLIMIT_CPU, (8, 10))
    resource.setrlimit(resource.RLIMIT_AS, (MAX_ADDRESS_SPACE, MAX_ADDRESS_SPACE))
    resource.setrlimit(resource.RLIMIT_NOFILE, (32, 32))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

def install_seccomp():
    library_name = os.environ.get("TRC_SECCOMP_LIBRARY")
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
        install_seccomp()
    except Exception:
        sys.stdout.write(json.dumps({"error": "PDF_WORKER_ISOLATION_UNAVAILABLE"}))
        return 0
    if self_test:
        blocked = True
        for family in (socket.AF_INET, socket.AF_UNIX):
            try:
                test_socket = socket.socket(family, socket.SOCK_STREAM)
            except OSError as exc:
                blocked = blocked and exc.errno == errno.EPERM
            else:
                blocked = False
                test_socket.close()
        limits = {
            "cpu": resource.getrlimit(resource.RLIMIT_CPU),
            "address_space": resource.getrlimit(resource.RLIMIT_AS),
            "open_files": resource.getrlimit(resource.RLIMIT_NOFILE),
            "core": resource.getrlimit(resource.RLIMIT_CORE),
        }
        expected_namespaces = json.loads(os.environ.get("TRC_PARENT_NAMESPACES", "{}"))
        namespaces = {}
        for name in ("user", "mnt", "pid"):
            try:
                namespaces[name] = (
                    os.stat("/proc/self/ns/" + name).st_ino
                    != int(expected_namespaces[name])
                )
            except (KeyError, OSError, ValueError, TypeError):
                namespaces[name] = False
        caps = {}
        try:
            with open("/proc/self/status", encoding="ascii") as status_file:
                for line in status_file:
                    if line.startswith(("CapEff:", "CapPrm:")):
                        name, value = line.split(":", 1)
                        caps[name] = int(value.strip(), 16)
        except (OSError, ValueError):
            caps = {}
        try:
            with open("/proc/self/mountinfo", encoding="ascii") as mounts_file:
                root_readonly = any(
                    line.split()[4] == "/" and "ro" in line.split()[5].split(",")
                    for line in mounts_file
                )
        except (OSError, IndexError):
            root_readonly = False
        marker = os.environ.get("TRC_HOST_MARKER", "")
        host_workspace = os.environ.get("TRC_HOST_WORKSPACE", "")
        host_home = os.environ.get("TRC_HOST_HOME", "")
        try:
            with tempfile.NamedTemporaryFile(prefix="trc-worker-", dir="/tmp"):
                tmp_writable = True
        except OSError:
            tmp_writable = False
        try:
            tmpfs_stats = os.statvfs("/tmp")
            tmpfs_bytes = tmpfs_stats.f_blocks * tmpfs_stats.f_frsize
        except OSError:
            tmpfs_bytes = 0
        checks = {
            "network_blocked": blocked,
            "namespaces_isolated": namespaces,
            "host_tmp_hidden": bool(marker) and not os.path.exists(marker),
            "host_workspace_hidden": bool(host_workspace) and not os.path.exists(host_workspace),
            "host_home_hidden": bool(host_home) and not os.path.exists(host_home),
            "pid_isolated": os.getpid() == 1,
            "capabilities_dropped": caps == {"CapEff": 0, "CapPrm": 0},
            "root_readonly": root_readonly,
            "tmp_writable": tmp_writable,
            "tmpfs_bytes": tmpfs_bytes,
            "limits": limits,
        }
        sys.stdout.write(json.dumps(checks))
        return 0 if all([
            blocked, all(namespaces.values()), checks["host_tmp_hidden"],
            checks["host_workspace_hidden"], checks["host_home_hidden"],
            checks["pid_isolated"],
            checks["capabilities_dropped"], root_readonly, tmp_writable,
            0 < tmpfs_bytes <= int(os.environ["TRC_TMPFS_LIMIT_BYTES"]),
        ]) else 1
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


def _path_contains(parent: str, child: str) -> bool:
    try:
        return os.path.commonpath((parent, child)) == parent
    except ValueError:
        return False


def _sandbox_mounts(excluded_paths: tuple[str, ...] = ()) -> list[tuple[str, str]]:
    """Return a narrow set of read-only runtime mounts; never bind app data."""
    code_root = str(Path(__file__).resolve().parent)
    protected_roots = {
        code_root,
        str(Path.cwd().resolve()),
        str(Path.home().resolve()),
        str(Path(tempfile.gettempdir()).resolve()),
    }
    for candidate in excluded_paths:
        if not os.path.isabs(candidate):
            raise IntakeError("PDF_WORKER_ISOLATION_UNAVAILABLE")
        protected_roots.add(str(Path(candidate).resolve()))
    runtime_roots: set[str] = set()
    for candidate in (sys.prefix, sys.base_prefix, sys.exec_prefix, sys.base_exec_prefix):
        path = os.path.abspath(candidate)
        if path == os.path.sep or not os.path.isdir(path):
            raise IntakeError("PDF_WORKER_ISOLATION_UNAVAILABLE")
        resolved = os.path.realpath(path)
        if any(_path_contains(root, resolved) or _path_contains(resolved, root)
               for root in protected_roots):
            raise IntakeError("PDF_WORKER_ISOLATION_UNAVAILABLE")
        runtime_roots.add(path)

    for key in ("stdlib", "platstdlib", "purelib", "platlib"):
        candidate = sysconfig.get_path(key)
        if candidate and os.path.isabs(candidate) and os.path.isdir(candidate):
            path = os.path.abspath(candidate)
            resolved = os.path.realpath(path)
            if any(_path_contains(root, resolved) or _path_contains(resolved, root)
                   for root in protected_roots):
                raise IntakeError("PDF_WORKER_ISOLATION_UNAVAILABLE")
            runtime_roots.add(path)

    executable = os.path.abspath(sys.executable)
    executable_dir = os.path.dirname(executable)
    if not os.path.isfile(executable) or not os.path.isdir(executable_dir):
        raise IntakeError("PDF_WORKER_ISOLATION_UNAVAILABLE")
    real_executable_dir = os.path.realpath(executable_dir)
    if any(_path_contains(root, real_executable_dir)
           or _path_contains(real_executable_dir, root)
           for root in protected_roots):
        raise IntakeError("PDF_WORKER_ISOLATION_UNAVAILABLE")
    runtime_roots.add(executable_dir)

    for candidate in ("/lib", "/lib64", "/usr/lib", "/usr/lib64"):
        if os.path.isdir(candidate):
            resolved = os.path.realpath(candidate)
            if any(_path_contains(root, resolved) or _path_contains(resolved, root)
                   for root in protected_roots):
                raise IntakeError("PDF_WORKER_ISOLATION_UNAVAILABLE")
            runtime_roots.add(candidate)

    # Nested runtime directories are already covered by the shortest parent.
    mount_roots: list[str] = []
    for path in sorted(runtime_roots, key=lambda item: (item.count(os.sep), item)):
        if not any(_path_contains(os.path.abspath(parent), os.path.abspath(path))
                   for parent in mount_roots):
            mount_roots.append(path)
    return [(os.path.realpath(path), path) for path in mount_roots]


def _worker_command(*, probe: dict[str, str] | None = None,
                    excluded_paths: tuple[str, ...] = ()) -> list[str]:
    bubblewrap = shutil.which("bwrap")
    seccomp_library = ctypes.util.find_library("seccomp")
    if not bubblewrap or not seccomp_library:
        raise IntakeError("PDF_WORKER_ISOLATION_UNAVAILABLE")

    mounts = _sandbox_mounts(excluded_paths)
    command = [
        bubblewrap,
        "--unshare-user",
        "--unshare-pid",
        "--unshare-ipc",
        "--unshare-uts",
        "--die-with-parent",
        "--new-session",
        "--as-pid-1",
        "--cap-drop", "ALL",
        "--hostname", "pdf-worker",
    ]
    target_paths = {"/dev", "/proc", "/tmp"}
    target_paths.update(destination for _, destination in mounts)
    directories_to_create: set[str] = set()
    for path in target_paths:
        absolute = Path(path)
        directories_to_create.add(str(absolute))
        directories_to_create.update(
            str(parent) for parent in absolute.parents if str(parent) != os.path.sep
        )
    for path in sorted(directories_to_create,
                       key=lambda item: (item.count(os.sep), item)):
        command.extend(("--dir", path))
    for source, destination in mounts:
        command.extend(("--ro-bind", source, destination))
    command.extend(("--proc", "/proc", "--dev", "/dev"))
    command.extend(("--size", str(SANDBOX_TMPFS_BYTES), "--tmpfs", "/tmp"))
    command.extend(("--remount-ro", "/", "--chdir", "/tmp", "--clearenv"))

    safe_env = {
        "HOME": "/tmp",
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": os.defpath,
        "TRC_SECCOMP_LIBRARY": seccomp_library,
        "TRC_TMPFS_LIMIT_BYTES": str(SANDBOX_TMPFS_BYTES),
    }
    if probe:
        safe_env.update(probe)
    for name, value in safe_env.items():
        command.extend(("--setenv", name, value))

    command.extend((sys.executable, "-I", "-B", "-c", _BOOTSTRAP))
    return command


def _run_worker(data: bytes = b"", *, self_test: bool = False,
                probe: dict[str, str] | None = None,
                excluded_paths: tuple[str, ...] = (),
                timeout_seconds: float = WALL_TIMEOUT_SECONDS) -> dict[str, Any]:
    try:
        command = _worker_command(probe=probe, excluded_paths=excluded_paths)
    except IntakeError:
        raise
    if self_test:
        command.append("--self-test")
    env = {"PATH": os.defpath, "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"}
    try:
        result = subprocess.run(
            command,
            input=data,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            cwd=tempfile.gettempdir(),
            env=env,
            timeout=timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired:
        raise IntakeError("PDF_TIMEOUT") from None
    except OSError:
        raise IntakeError("PDF_WORKER_ISOLATION_UNAVAILABLE") from None

    if result.returncode != 0:
        if self_test:
            raise IntakeError("PDF_WORKER_ISOLATION_UNAVAILABLE")
        if result.returncode == 1 and not result.stdout:
            raise IntakeError("PDF_WORKER_ISOLATION_UNAVAILABLE")
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


def parse_pdf_isolated(data: bytes, *,
                       excluded_paths: tuple[str, ...] = ()) -> tuple[dict[str, Any], ...]:
    """Return bounded page data from a no-network, rlimit-bounded child."""
    payload = _run_worker(data, excluded_paths=excluded_paths)
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
    """Verify the namespace, filesystem, capability, network, and limit boundary."""
    try:
        parent_namespaces = {
            name: str(os.stat("/proc/self/ns/" + name).st_ino)
            for name in _NAMESPACE_NAMES
        }
        with tempfile.TemporaryDirectory(prefix="trc-host-private-") as host_dir:
            marker = Path(host_dir) / "sentinel"
            marker.write_text("synthetic host-only sentinel", encoding="ascii")
            result = _run_worker(self_test=True, probe={
                "TRC_PARENT_NAMESPACES": json.dumps(parent_namespaces),
                "TRC_HOST_MARKER": str(marker),
                "TRC_HOST_WORKSPACE": str(Path(__file__).resolve().parent),
                "TRC_HOST_HOME": str(Path.home().resolve()),
            }, timeout_seconds=5)
    except (OSError, IntakeError):
        raise IntakeError("PDF_WORKER_ISOLATION_UNAVAILABLE") from None
    namespaces = result.get("namespaces_isolated")
    if (
        result.get("network_blocked") is not True
        or not isinstance(namespaces, dict)
        or any(namespaces.get(name) is not True for name in _NAMESPACE_NAMES)
        or result.get("host_tmp_hidden") is not True
        or result.get("host_workspace_hidden") is not True
        or result.get("host_home_hidden") is not True
        or result.get("pid_isolated") is not True
        or result.get("capabilities_dropped") is not True
        or result.get("root_readonly") is not True
        or result.get("tmp_writable") is not True
        or not 0 < result.get("tmpfs_bytes", 0) <= SANDBOX_TMPFS_BYTES
    ):
        raise IntakeError("PDF_WORKER_ISOLATION_UNAVAILABLE")
    return result
