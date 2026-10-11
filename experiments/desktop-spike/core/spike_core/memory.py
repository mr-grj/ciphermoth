import ctypes
import sys


class _ProcessMemoryCounters(ctypes.Structure):
    _fields_ = [
        ("cb", ctypes.c_ulong),
        ("PageFaultCount", ctypes.c_ulong),
        ("PeakWorkingSetSize", ctypes.c_size_t),
        ("WorkingSetSize", ctypes.c_size_t),
        ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
        ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
        ("PagefileUsage", ctypes.c_size_t),
        ("PeakPagefileUsage", ctypes.c_size_t),
    ]


def _windows_counters() -> _ProcessMemoryCounters:
    counters = _ProcessMemoryCounters()
    counters.cb = ctypes.sizeof(counters)
    psapi = ctypes.WinDLL("psapi")
    kernel32 = ctypes.WinDLL("kernel32")
    kernel32.GetCurrentProcess.restype = ctypes.c_void_p
    psapi.GetProcessMemoryInfo(
        ctypes.c_void_p(kernel32.GetCurrentProcess()),
        ctypes.byref(counters),
        counters.cb,
    )
    return counters


def peak_rss() -> int:
    if sys.platform == "win32":
        return int(_windows_counters().PeakWorkingSetSize)
    import resource

    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return int(peak if sys.platform == "darwin" else peak * 1024)


def current_rss() -> int | None:
    if sys.platform == "win32":
        return int(_windows_counters().WorkingSetSize)
    if sys.platform.startswith("linux"):
        with open("/proc/self/statm") as statm:
            pages = int(statm.read().split()[1])
        import os

        return pages * os.sysconf("SC_PAGE_SIZE")
    return None
