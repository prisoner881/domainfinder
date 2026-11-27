import socket

import pytest


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    """Unit tests never touch the network: any real socket connect fails."""

    def guard(*args, **kwargs):
        raise RuntimeError("network access in unit tests")

    monkeypatch.setattr(socket.socket, "connect", guard)
    monkeypatch.setattr(socket, "create_connection", guard)
    monkeypatch.setattr(socket, "getaddrinfo", guard)

    # psycopg's binary driver connects from C, past the socket guard above.
    async def no_db(self):
        raise RuntimeError("database access in unit tests")

    from domainfinder.sources.crtsh_db import CrtshDb

    monkeypatch.setattr(CrtshDb, "_connect", no_db)


def pytest_pyfunc_call(pyfuncitem):
    """Run `async def` tests with asyncio.run (no plugin needed)."""
    import asyncio
    import inspect

    if inspect.iscoroutinefunction(pyfuncitem.obj):
        args = {k: pyfuncitem.funcargs[k] for k in pyfuncitem._fixtureinfo.argnames}
        asyncio.run(pyfuncitem.obj(**args))
        return True
    return None
