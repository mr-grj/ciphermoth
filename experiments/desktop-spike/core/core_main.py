import time

STARTED = time.monotonic()


def _bootstrap() -> int:
    from spike_core.entry import main

    return main(STARTED)


if __name__ == "__main__":
    import os
    import sys

    code = _bootstrap()
    sys.stdout.flush()
    sys.stderr.flush()
    os._exit(code)
