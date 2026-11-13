import errno
from collections.abc import Callable
from pathlib import Path

import pytest


class CapacityProbed(Exception):
    pass


class Peer:
    def __init__(self, index: int) -> None:
        self.index = index
        self.closed = False

    def send(self, _message: dict[str, object]) -> None:
        pass

    def raw(self, _data: bytes) -> None:
        pass

    def receive(self) -> dict[str, str] | None:
        if self.index in (1, 2):
            return {"t": "refused", "code": "caller"}
        if self.index == 12:
            return {"t": "hello_ok"}
        return None

    def close(self) -> None:
        self.closed = True


@pytest.fixture
def capacity_probe(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> Callable[[OSError | None], list[Peer]]:
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[2] / "harness"))
    import extension_attacks as attacks

    def probe(failure: OSError | None) -> list[Peer]:
        peers: list[Peer] = []

        def raw(_path: Path, hello: bool = True) -> Peer:
            del hello
            if len(peers) == 11 and failure is not None:
                raise failure
            peer = Peer(len(peers) + 1)
            peers.append(peer)
            return peer

        def after_capacity(*_args: object) -> None:
            raise CapacityProbed

        monkeypatch.setattr(
            attacks.ext, "socket_path", lambda _root: tmp_path / "unused.sock"
        )
        monkeypatch.setattr(attacks, "UNIX", True)
        monkeypatch.setattr(attacks, "Raw", raw)
        monkeypatch.setattr(attacks, "link", after_capacity)
        monkeypatch.setattr(attacks.time, "sleep", lambda _seconds: None)
        with pytest.raises(CapacityProbed):
            attacks.before_pairing(tmp_path, tmp_path / "report.json", "unused")
        return peers

    return probe


@pytest.mark.parametrize("code", [errno.EPIPE, errno.ECONNRESET, errno.ENOTCONN])
def test_closed_ninth_connection_is_accepted(
    capacity_probe: Callable[[OSError | None], list[Peer]], code: int
) -> None:
    peers = capacity_probe(OSError(code, "synthetic closed socket"))
    assert len(peers) == 11
    assert all(peer.closed for peer in peers)


@pytest.mark.parametrize("code", [errno.EACCES, errno.EMFILE, errno.ETIMEDOUT])
def test_other_socket_failures_are_not_accepted(
    capacity_probe: Callable[[OSError | None], list[Peer]], code: int
) -> None:
    failure = OSError(code, "synthetic unexpected socket failure")
    with pytest.raises(OSError) as caught:
        capacity_probe(failure)
    assert caught.value is failure


def test_served_ninth_connection_still_fails(
    capacity_probe: Callable[[OSError | None], list[Peer]],
) -> None:
    with pytest.raises(AssertionError, match="a ninth connection was served"):
        capacity_probe(None)
