import pytest
from desktop_core import framing, server


def test_stalled_protocol_output_fails_closed_at_queue_limit(monkeypatch):
    monkeypatch.setattr(server.threading.Thread, "start", lambda self: None)
    writer = server.ProtocolWriter(-1)

    def exited(code):
        raise SystemExit(code)

    monkeypatch.setattr(server.os, "_exit", exited)
    for request_id in range(server.MAX_IN_FLIGHT):
        writer.send(framing.RESPONSE, request_id, {}, b"ciphertext")
    with pytest.raises(SystemExit) as error:
        writer.send(framing.RESPONSE, 100, {}, b"ciphertext")
    assert error.value.code == 3
    assert writer.queue.qsize() == server.MAX_IN_FLIGHT
    writer.close()  # shutdown cannot block on the full queue either
