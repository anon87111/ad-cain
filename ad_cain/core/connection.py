"""LDAP connection manager with context-manager support."""

from __future__ import annotations

import ldap3
from ldap3 import Server, Connection, ALL, NTLM, SUBTREE

from ad_cain.config import LDAPConfig
from ad_cain.logger import get_logger
from ad_cain.utils.errors import LDAPConnectionError

log = get_logger("connection")


class LDAPConnectionManager:
    """Manages LDAP connection lifecycle."""

    def __init__(self, config: LDAPConfig):
        self.config = config
        self._server: Server | None = None
        self._conn: Connection | None = None
        self._base_dn: str = ""

    # -- context manager --------------------------------------------------

    def __enter__(self) -> LDAPConnectionManager:
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.disconnect()

    # -- public API -------------------------------------------------------

    def connect(self) -> None:
        """Establish an LDAP connection to the target DC."""
        try:
            self._server = Server(
                self.config.server,
                port=self.config.port,
                use_ssl=self.config.use_ssl,
                get_info=ALL,
                connect_timeout=self.config.timeout,
            )

            auth = NTLM if "\\" in self.config.username else None
            self._conn = Connection(
                self._server,
                user=self.config.username,
                password=self.config.password,
                authentication=auth,
                auto_bind=True,
                raise_exceptions=True,
                receive_timeout=self.config.timeout,
            )
            self._base_dn = self._discover_base_dn()
            log.info("Connected to %s (base DN: %s)", self.config.server, self._base_dn)
        except Exception as exc:
            raise LDAPConnectionError(
                f"Failed to connect to {self.config.server}:{self.config.port}: {exc}"
            ) from exc

    def disconnect(self) -> None:
        """Close the LDAP connection."""
        if self._conn and self._conn.bound:
            self._conn.unbind()
            log.info("Disconnected from %s", self.config.server)
        self._conn = None

    @property
    def connection(self) -> Connection:
        if self._conn is None or not self._conn.bound:
            raise LDAPConnectionError("Not connected — call connect() first.")
        return self._conn

    @property
    def server(self) -> Server:
        if self._server is None:
            raise LDAPConnectionError("Server not initialised.")
        return self._server

    @property
    def base_dn(self) -> str:
        return self._base_dn

    def is_connected(self) -> bool:
        return self._conn is not None and self._conn.bound

    # -- private ----------------------------------------------------------

    def _discover_base_dn(self) -> str:
        """Read defaultNamingContext from RootDSE."""
        if self._server and self._server.info and self._server.info.other:
            ctx = self._server.info.other.get("defaultNamingContext")
            if ctx:
                return ctx[0] if isinstance(ctx, list) else ctx
        raise LDAPConnectionError("Could not discover base DN from RootDSE.")
