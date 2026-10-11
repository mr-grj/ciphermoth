import ctypes
import os
import signal
import sys
import threading
import time

_PR_SET_PDEATHSIG = 1
_PR_SET_DUMPABLE = 4
_SEM_FAILCRITICALERRORS = 0x0001
_SEM_NOGPFAULTERRORBOX = 0x0002
_WER_FAULT_REPORTING_FLAG_NOHEAP = 1


def isolate_stdio() -> tuple[int, int]:
    proto_in = os.dup(0)
    proto_out = os.dup(1)
    null = os.open(os.devnull, os.O_RDONLY)
    os.dup2(null, 0)
    os.close(null)
    try:
        os.dup2(2, 1)
    except OSError:
        sink = os.open(os.devnull, os.O_WRONLY)
        os.dup2(sink, 1)
        os.close(sink)
    sys.stdout = sys.stderr
    if sys.platform == "win32":
        import msvcrt

        msvcrt.setmode(proto_in, os.O_BINARY)
        msvcrt.setmode(proto_out, os.O_BINARY)
    return proto_in, proto_out


def disable_crash_dumps() -> list[str]:
    applied = []
    if sys.platform != "win32":
        import resource

        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        applied.append("rlimit_core=0")
    if sys.platform.startswith("linux"):
        libc = ctypes.CDLL(None, use_errno=True)
        if libc.prctl(_PR_SET_DUMPABLE, 0, 0, 0, 0) == 0:
            applied.append("pr_set_dumpable=0")
        if libc.prctl(_PR_SET_PDEATHSIG, signal.SIGKILL, 0, 0, 0) == 0:
            applied.append("pr_set_pdeathsig=SIGKILL")
    if sys.platform == "win32":
        kernel32 = ctypes.WinDLL("kernel32")
        kernel32.SetErrorMode(_SEM_FAILCRITICALERRORS | _SEM_NOGPFAULTERRORBOX)
        applied.append("seterrormode")
        if kernel32.WerSetFlags(_WER_FAULT_REPORTING_FLAG_NOHEAP) == 0:
            applied.append("wer_noheap")
    return applied


def watch_parent(on_orphaned) -> None:
    if sys.platform == "win32":
        return
    parent = os.getppid()

    def poll() -> None:
        while True:
            time.sleep(0.5)
            if os.getppid() != parent:
                on_orphaned()
                return

    threading.Thread(target=poll, name="parent-watch", daemon=True).start()
