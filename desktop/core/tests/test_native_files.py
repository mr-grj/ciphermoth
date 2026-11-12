import asyncio

import pytest
from desktop_core import asgi_bridge, native_files


@pytest.mark.parametrize("failure", [OSError("disk full"), asyncio.CancelledError()])
def test_failed_or_cancelled_backup_leaves_no_final_or_partial(
    tmp_path, monkeypatch, failure
):
    async def broken(*args, output, **kwargs):
        output.write(b"encrypted staging bytes")
        raise failure

    monkeypatch.setattr(asgi_bridge, "call", broken)
    target = tmp_path / "backup.cmbackup"
    with pytest.raises(type(failure)):
        asyncio.run(
            native_files._call(
                None,
                {"native": "backup_export", "file": str(target), "session": "x"},
                b"{}",
            )
        )
    assert list(tmp_path.iterdir()) == []


def test_destination_race_does_not_replace_file(tmp_path, monkeypatch):
    target = tmp_path / "backup.cmbackup"

    async def racing(*args, output, **kwargs):
        output.write(b"encrypted backup")
        target.write_bytes(b"another application saved this")
        return 200, [], b""

    monkeypatch.setattr(asgi_bridge, "call", racing)
    with pytest.raises(FileExistsError):
        asyncio.run(
            native_files._call(
                None,
                {"native": "backup_export", "file": str(target), "session": "x"},
                b"{}",
            )
        )
    assert target.read_bytes() == b"another application saved this"
    assert list(tmp_path.iterdir()) == [target]


def test_disk_full_has_an_actionable_error(tmp_path, monkeypatch):
    import errno

    async def broken(*args, **kwargs):
        raise OSError(errno.ENOSPC, "secret exception text is never forwarded")

    monkeypatch.setattr(asgi_bridge, "call", broken)
    result = asyncio.run(
        native_files.call(
            None,
            {
                "native": "backup_export",
                "file": str(tmp_path / "backup.cmbackup"),
                "session": "x",
            },
            b"{}",
        )
    )
    assert result[0] == 400
    assert b"Not enough free disk space" in result[2]
    assert b"secret exception" not in result[2]
    assert not list(tmp_path.iterdir())
