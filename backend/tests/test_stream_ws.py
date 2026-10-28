"""The live stream WebSocket: what it does with input it did not expect.

The protocol is JSON text frames. Anything else that can arrive on the wire has to
leave the connection usable, because a stream that stops answering without closing is
the worst of both worlds: the browser still shows a live view, and nothing ever
arrives in it again.
"""
from __future__ import annotations

import threading

import pytest
from fastapi.testclient import TestClient

from backend.auth import store as store_module
from backend.auth.store import AdminStore, get_admin_store
from backend.auth.models import ALL_PERMISSIONS
from backend.config import settings


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "admin_store_path", str(tmp_path / "admins.json"))
    monkeypatch.setattr(settings, "audit_enabled", False)
    monkeypatch.setattr(store_module, "_store", AdminStore())
    store = get_admin_store()
    store.create("admin", "password1")
    store.create_group("Administrators", ALL_PERMISSIONS,
                       members=[{"type": "local", "ref": "admin"}])

    from backend.main import app

    c = TestClient(app)
    assert c.post("/api/auth/login", json={"username": "admin", "password": "password1"}).status_code == 200
    return c


def _in_background(fn, seconds: float = 10.0) -> dict:
    """Run a WebSocket conversation with a deadline.

    A wedged stream does not fail, it waits, so a plain call here would hang the whole
    test run instead of reporting anything.
    """
    out: dict = {}

    def run() -> None:
        try:
            fn(out)
        except BaseException as exc:  # noqa: BLE001 - the failure itself is the result
            out["error"] = f"{type(exc).__name__}: {exc}"

    worker = threading.Thread(target=run, daemon=True)
    worker.start()
    worker.join(seconds)
    out["timed_out"] = worker.is_alive()
    return out


def test_binary_frame_does_not_wedge_the_stream(client):
    """A binary frame used to kill the receive loop and leave the socket open.

    ``WebSocket.receive_text()`` reads ``message["text"]``, which a binary frame does
    not have, so it raised ``KeyError`` inside the receive task. The task died, the
    other two were cancelled, and the endpoint returned without closing: the client
    kept a connection that answered nothing, for ever.
    """
    def talk(out: dict) -> None:
        with client.websocket_connect("/api/stream/ws") as ws:
            ws.receive_json()  # greeting snapshot
            ws.send_bytes(b"\x00\x01\x02")
            ws.send_json({"type": "set_filters",
                          "filters": [{"field": "src_ip", "value": "10.0.0.1"}]})
            out["msg"] = ws.receive_json()

    result = _in_background(talk)
    assert not result["timed_out"], "the stream stopped answering after a binary frame"
    assert "error" not in result, result.get("error")
    assert [f["field"] for f in result["msg"]["stats"]["filters"]] == ["src_ip"]


def test_unknown_message_type_is_ignored(client):
    def talk(out: dict) -> None:
        with client.websocket_connect("/api/stream/ws") as ws:
            ws.receive_json()
            ws.send_json({"type": "definitely-not-a-command", "payload": {"a": 1}})
            ws.send_text("{ this is not json")
            ws.send_json({"type": "set_filters",
                          "filters": [{"field": "dst_ip", "value": "1.1.1.1"}]})
            out["msg"] = ws.receive_json()

    result = _in_background(talk)
    assert not result["timed_out"] and "error" not in result, result
    assert [f["field"] for f in result["msg"]["stats"]["filters"]] == ["dst_ip"]
