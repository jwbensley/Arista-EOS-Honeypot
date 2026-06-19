#!/usr/bin/env python3

from __future__ import annotations

import argparse
import enum
import gzip
import logging
import re
import socket
from datetime import datetime
from typing import Optional, Tuple

logger = logging.getLogger(__name__)


class SessionCommand:
    """Represents a single command executed during a session."""

    def __init__(self, command: str, timestamp: datetime):
        self.command = command
        self.timestamp = timestamp

    def __repr__(self):
        return f"SessionCommand(timestamp={self.timestamp}, command={self.command!r})"


class SessionCommands:
    """Container for a list of SessionCommand objects."""

    def __init__(self, user_session: UserSession):
        self.commands: list[SessionCommand] = []
        self.user_session = user_session

    def __len__(self):
        return len(self.commands)

    def add_command(self, command: SessionCommand):
        """Add a command to the session."""
        self.commands.append(command)

    def get_commands(self) -> list[SessionCommand]:
        """Get the list of commands executed during the session, in chronological order."""
        return sorted(self.commands, key=lambda c: c.timestamp)

    def __repr__(self):
        return f"SessionCommands(count={len(self.commands)})"


class SessionProtocol(enum.Enum):
    SSH = "SSH"
    TELNET = "TELNET"
    EITHER = "EITHER"

    @staticmethod
    def from_str(value: str) -> SessionProtocol:
        value = value.upper()
        # This covers ssh and sshd, as well as telnet and telnetd
        if value.startswith("SSH"):
            return SessionProtocol.SSH
        elif value.startswith("TELNET"):
            return SessionProtocol.TELNET
        elif value.startswith("REMOTE"):
            # Some log entries use "remote" as the service name
            return SessionProtocol.EITHER
        else:
            raise ValueError(f"Unknown protocol: {value}")


class SessionStatus(enum.Enum):
    CONNECTED = "Connected"
    SESSION_LIMIT_REACHED = "Session Limit Reached"


class UserSession:
    """Represents a user authentication session."""

    def __init__(
        self,
        connect_time: datetime,
        protocol: SessionProtocol,
        client: Client,
        disconnect_time: Optional[datetime] = None,
        pid: Optional[int] = None,
        connect_error: Optional[SessionStatus] = None,
        auth_success: bool = False,
    ):
        self.connect_time = connect_time
        self.disconnect_time: Optional[datetime] = disconnect_time
        self.pid: Optional[int] = pid
        self.connect_error: Optional[SessionStatus] = connect_error
        self.protocol = protocol
        self.auth_success = auth_success
        self.client = client
        self.commands = SessionCommands(self)

    def __repr__(self):
        return f"UserSession(connect_time={self.connect_time}, protocol={self.protocol.name}, client={self.client}, pid={self.pid}, auth_success={self.auth_success}, commands={len(self.commands.commands)})"


class UserSessions:
    """Container for a list of UserSession objects."""

    def __init__(self):
        self.sessions: list[UserSession] = []

    def __len__(self):
        return len(self.sessions)

    def add_session(self, session: UserSession) -> UserSession:
        """Add a user session to the container."""
        self.sessions.append(session)
        return session

    def get_session(
        self,
        connect_time: Optional[datetime],
        protocol: Optional[SessionProtocol],
        pid: Optional[int],
        client: Optional[Client],
    ) -> UserSession:
        """Retrieve a session based on its unique attributes."""

        if not any([connect_time, protocol, pid, client]):
            raise ValueError(
                "At least one attribute must be provided to identify a session."
            )

        for session in self.sessions:
            if (
                (connect_time is None or session.connect_time == connect_time)
                and (protocol is None or session.protocol == protocol)
                and (pid is None or session.pid == pid)
                and (client is None or session.client == client)
            ):
                return session

        raise LookupError("No session found matching the provided attributes.")

    def find_latest_session(
        self,
        protocol: Optional[SessionProtocol] = None,
        pid: Optional[int] = None,
        client: Optional[Client] = None,
        auth_success: Optional[bool] = None,
        require_not_disconnected: bool = False,
    ) -> Optional[UserSession]:
        """Find the most recent session that matches a set of optional filters."""

        candidates = self.sessions

        if protocol is not None:
            candidates = [s for s in candidates if s.protocol == protocol]
        if pid is not None:
            candidates = [s for s in candidates if s.pid == pid]
        if client is not None:
            candidates = [s for s in candidates if s.client == client]
        if auth_success is not None:
            candidates = [s for s in candidates if s.auth_success == auth_success]
        if require_not_disconnected:
            candidates = [s for s in candidates if s.disconnect_time is None]

        if not candidates:
            return None

        return sorted(candidates, key=lambda s: s.connect_time, reverse=True)[0]

    def __repr__(self):
        return f"UserSessions(count={len(self.sessions)})"


class Client:
    """Represents a client address with its associated sessions."""

    def __init__(self, address: str):
        self.address = Client.normalize_ip(address)
        self.sessions: list[UserSession] = []

    def add_session(self, session: UserSession) -> None:
        """Add a user session to this client IP."""
        self.sessions.append(session)

    def get_address(self) -> str:
        return self.address

    def get_sessions(self) -> list[UserSession]:
        return self.sessions

    @staticmethod
    def normalize_ip(ip: str) -> str:
        return ip.removeprefix("::ffff:")

    def __repr__(self):
        return f"Client(address={self.get_address()!r}, sessions={len(self.sessions)})"


class Clients:
    """Container for a list of Client objects."""

    def __init__(self):
        self.clients: dict[str, Client] = {}

    def get_or_create_client(self, address: str) -> Client:
        """Retrieve an existing Client or create a new one if it doesn't exist."""
        normalized_ip = Client.normalize_ip(address)
        if normalized_ip not in self.clients:
            self.clients[normalized_ip] = Client(normalized_ip)
        return self.clients[normalized_ip]

    def get_clients(self) -> list[Client]:
        return list(self.clients.values())

    def __repr__(self):
        return f"Clients(count={len(self.clients)})"

    def __len__(self):
        return len(self.clients)


class Resolver:
    cache: dict[str, str] = {}

    @staticmethod
    def guess_ip_from_hostname(hostname: str) -> Optional[str]:
        # 85.111.68.99.dynamic.ttnet.com.tr
        match = re.match(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})", hostname)
        if match:
            ip = ".".join(match.groups())
            logger.debug("Guessed IP %s from hostname %s", ip, hostname)
            return ip
        logger.warning("Failed to guess IP from hostname %s", hostname)
        return None

    @staticmethod
    def resolve_hostname(hostname: str) -> str:
        # Is this an IP which doesn't need resolving
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname) or re.match(
            r"^[a-fA-F0-9:]+$", hostname
        ):
            return hostname

        if hostname in Resolver.cache:
            logger.debug(
                "Cache hit for hostname %s: %s", hostname, Resolver.cache[hostname]
            )
            return Resolver.cache[hostname]

        try:
            resolved_ip = socket.gethostbyname(hostname)
            logger.debug(
                "Resolved IP %s from hostname %s",
                resolved_ip,
                hostname,
            )
        except Exception as e:
            logger.warning(
                "Failed to resolve IP from hostname %s: %s",
                hostname,
                e,
            )
            resolved_ip = None

        if not resolved_ip:
            resolved_ip = Resolver.guess_ip_from_hostname(hostname)

        if not resolved_ip:
            logger.warning(f"Unable to resolve IP for hostname: {hostname}")
            resolved_ip = hostname

        Resolver.cache[hostname] = resolved_ip
        return resolved_ip


def parse_log_files(filepaths: list[str]) -> None:
    """Parse a gzip-compressed log files"""
    logger.info(f"Starting to parse {len(filepaths)} log files")

    for filepath in filepaths:
        user_sessions, clients = parse_log_file(filepath)
        print_stats(user_sessions, clients)


def parse_log_file(filepath: str) -> Tuple[UserSessions, Clients]:
    logger.info("Parsing log file: %s", filepath)

    user_sessions = UserSessions()
    clients = Clients()

    START_RE = re.compile(
        r"^(?P<ts>\d{4}\s+\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+UTC\s+\S+\s+xinetd\[\d+\]:\s+START:\s+(?P<proto>ssh|telnet)\s+pid=(?P<pid>\d+)\s+from=(?P<ip>\S+)"
    )
    FAIL_LIMIT_RE = re.compile(
        r"^(?P<ts>\d{4}\s+\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+UTC\s+\S+\s+xinetd\[\d+\]:\s+FAIL:\s+telnet\s+service_limit\s+from=(?P<ip>\S+)"
    )
    TELNET_EOF_RE = re.compile(
        r"^(?P<ts>\d{4}\s+\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+UTC\s+\S+\s+telnetd\[(?P<pid>\d+)\]:\s+ttloop:\s+peer\s+died:\s+EOF"
    )
    EXIT_RE = re.compile(
        r"^(?P<ts>\d{4}\s+\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+UTC\s+\S+\s+xinetd\[\d+\]:\s+EXIT:\s+(?P<proto>ssh|telnet)\s+status=\d+\s+pid=(?P<pid>\d+)"
    )
    LOGIN_SUCCESS_RE = re.compile(
        r"^(?P<ts>\d{4}\s+\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+UTC\s+\S+\s+Aaa:\s+\d+:\s+%AAA-5-LOGIN:\s+user\s+.+\s+logged\s+in\s+\[from:\s+(?P<ip>[^\]]+)\]\s+\[service:\s+(?P<service>[^\]]+)\]"
    )
    CMD_RE = re.compile(
        r"^(?P<ts>\d{4}\s+\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+UTC\s+\S+\s+Aaa:\s+\d+:\s+%ACCOUNTING-6-CMD:\s+\S+\s+\S+\s+(?P<hostname>\S+)\s+\S+\s+.+?\s+cmd=(?P<cmd>.+?)(?:\s+<cr>)?$"
    )

    def parse_timestamp(ts: str) -> datetime:
        return datetime.strptime(ts, "%Y %b %d %H:%M:%S")

    with gzip.open(filepath, "rt", encoding="utf-8", errors="ignore") as f:
        """
        These are the different log entries we need to parse:

        A new session is created when a user attempts to connect.
        We need to strip "::ffff:" from the IP address.

        Create a new session with connect_time="2026 May  3 23:13:08", protocol=SSH, pid=13707, client_ip="116.110.218.192":
        2026 May  3 23:13:08 UTC edge_rtr_001.ariosnetworks.net xinetd[341]: START: ssh pid=13707 from=116.110.218.192

        Create a new session with connect_time="2026 May  3 23:13:12", protocol=TELNET, pid=13763, client_ip="144.91.97.227":
        2026 May  3 23:13:12 UTC edge_rtr_001.ariosnetworks.net xinetd[341]: START: telnet pid=13763 from=::ffff:144.91.97.227

        A session couldn't be create because the session limit was reached.
        The PID is not known for this log entry.
        Create a new session with connect_error set to "Session Limit Reached" for the session, connect_time="2026 May  3 23:18:00", disconnect_time="2026 May  3 23:18:00", protocol=TELNET, client_ip="202.91.32.11"
        2026 May  3 23:18:00 UTC edge_rtr_001.ariosnetworks.net xinetd[341]: FAIL: telnet service_limit from=::ffff:202.91.32.11
messages.20260510-200028.gz
        A session couldn't be create because there was an error during the connection process.
        The client IP is not known for this log entry.
        Set the connect_error to "Session Limit Reached" for the session with connect_time="2026 Jun 17 00:57:50", protocol=TELNET, pid=12782.
        2026 Jun 17 00:57:50 UTC edge_rtr_001.ariosnetworks.net telnetd[12782]: ttloop: peer died: EOF

        In the following case, the connection ended before the authentication process could complete.
        We don't have enough info to tie this to a specific session, do nothing.
        There is always an EXIT log entry, which we can use to identify and update the session.
        2026 Jun 16 14:47:10 UTC edge_rtr_001.ariosnetworks.net Aaa: 132: %AAA-4-LOGIN_FAILED: user  failed to login [from: 45.192.243.92] [service: remote] [reason: Authentication aborted]

        In the following case the the user failed to authentication.
        We don't have enough info to tie this to a specific session, do nothing.
        2026 Jun 17 04:48:56 UTC edge_rtr_001.ariosnetworks.net Aaa: 369: %AAA-4-LOGIN_FAILED: user admin failed to login [from: 35.187.99.195] [service: sshd] [reason: Authentication failed - Bad secret]

        A session ended.
        There is no client IP.
        Set the disconnect time for the session with protocol=TELNET, pid=13574.
        2026 Jun 17 05:52:03 UTC edge_rtr_001.ariosnetworks.net xinetd[344]: EXIT: telnet status=1 pid=13574 duration=33(sec)
        Set the disconnect time for the session with protocol=SSH, pid=13574.
        2026 Jun 13 02:45:02 UTC edge_rtr_001.ariosnetworks.net xinetd[336]: EXIT: ssh status=5 pid=5712 duration=6(sec)

        A user successfully authenticated.
        No session PID is available in this log entry, but we can tie it to the session using the client IP and protocol.
        Set the auth_success to True for the session with protocol=SSH, client_ip="116.110.218.192".
        2026 May  3 23:11:32 UTC edge_rtr_001.ariosnetworks.net Aaa: 101: %AAA-5-LOGIN: user admin logged in [from: 116.110.218.192] [service: sshd]

        A command was run by a user during a session.
        Add a new SessionCommand to the UserSession with matching client IP, auth_success=True, and no disconnect time.
        The SessionCommand should have the command set to "echo James test" and the timestamp set to "2026 May  3 15:14:46".
        2026 May  3 15:14:46 UTC edge_rtr_001.ariosnetworks.net Aaa: 54: %ACCOUNTING-6-CMD: admin vty6 p3ee0912d.dip0.t-ipconnect.de stop task_id=5 start_time=1777821286.0536559 timezone=UTC service=shell priv-lvl=15 cmd=echo James test <cr>
        """
        for line in f:
            line = line.rstrip("\n")

            try:
                start_match = START_RE.match(line)
                if start_match:
                    ts = parse_timestamp(start_match.group("ts"))
                    protocol = SessionProtocol.from_str(start_match.group("proto"))
                    pid = int(start_match.group("pid"))
                    ip = start_match.group("ip")
                    client = clients.get_or_create_client(ip)

                    session = user_sessions.add_session(
                        UserSession(
                            connect_time=ts,
                            protocol=protocol,
                            pid=pid,
                            client=client,
                        )
                    )
                    client.add_session(session)
                    logger.debug("Created session from START line: %s", session)
                    continue

                fail_limit_match = FAIL_LIMIT_RE.match(line)
                if fail_limit_match:
                    ts = parse_timestamp(fail_limit_match.group("ts"))
                    ip = fail_limit_match.group("ip")
                    client = clients.get_or_create_client(ip)

                    session = user_sessions.add_session(
                        UserSession(
                            connect_time=ts,
                            protocol=SessionProtocol.TELNET,
                            pid=None,
                            client=client,
                            disconnect_time=ts,
                            connect_error=SessionStatus.SESSION_LIMIT_REACHED,
                        )
                    )
                    client.add_session(session)
                    logger.debug(
                        "Created session with session-limit error: %s", session
                    )
                    continue

                telnet_eof_match = TELNET_EOF_RE.match(line)
                if telnet_eof_match:
                    pid = int(telnet_eof_match.group("pid"))
                    session = user_sessions.find_latest_session(
                        protocol=SessionProtocol.TELNET,
                        pid=pid,
                        require_not_disconnected=True,
                    )

                    if session is not None:
                        session.connect_error = SessionStatus.SESSION_LIMIT_REACHED
                        logger.debug(
                            "Updated existing TELNET session from ttloop line: %s",
                            session,
                        )
                    else:
                        logger.error(
                            "No matching session found for ttloop line: %s", line
                        )
                    continue

                exit_match = EXIT_RE.match(line)
                if exit_match:
                    ts = parse_timestamp(exit_match.group("ts"))
                    protocol = SessionProtocol.from_str(exit_match.group("proto"))
                    pid = int(exit_match.group("pid"))
                    try:
                        session = user_sessions.find_latest_session(
                            protocol=protocol,
                            pid=pid,
                            require_not_disconnected=True,
                        )
                        if not session:
                            logger.error(
                                f"Couldn't find session to update disconnect time for EXIT line: {line}"
                            )
                            continue

                        session.disconnect_time = ts
                        logger.debug("Updated session disconnect time: %s", session)
                    except LookupError:
                        logger.error(
                            "No matching session found for EXIT line: %s", line
                        )
                    continue

                login_success_match = LOGIN_SUCCESS_RE.match(line)
                if login_success_match:
                    ts = parse_timestamp(login_success_match.group("ts"))
                    ip = Resolver.resolve_hostname(login_success_match.group("ip"))
                    service: str = login_success_match.group("service")
                    protocol = (
                        SessionProtocol.from_str(service)
                        if SessionProtocol.from_str(service) != SessionProtocol.EITHER
                        else None
                    )
                    client = clients.get_or_create_client(ip)

                    session = user_sessions.find_latest_session(
                        protocol=protocol,
                        client=client,
                        require_not_disconnected=True,
                    )

                    if session is not None:
                        session.auth_success = True
                        logger.debug("Marked session authenticated: %s", session)
                    else:
                        # This can happen when then IP has a PTR record, but there is no A/AAAA
                        logger.error(
                            "No matching session found for LOGIN success line, creating session:\n%s",
                            line,
                        )
                        session = user_sessions.add_session(
                            UserSession(
                                connect_time=ts,
                                protocol=SessionProtocol.from_str(service),
                                pid=None,
                                client=client,
                                auth_success=True,
                            )
                        )
                    continue

                cmd_match = CMD_RE.match(line)
                if cmd_match:
                    ts = parse_timestamp(cmd_match.group("ts"))
                    hostname = Resolver.resolve_hostname(cmd_match.group("hostname"))
                    cmd: str = cmd_match.group("cmd").strip()

                    # Find matching authenticated session that is still connected
                    session = user_sessions.find_latest_session(
                        client=clients.get_or_create_client(hostname),
                        auth_success=True,
                        require_not_disconnected=True,
                    )

                    if session is not None:
                        session.commands.add_command(
                            SessionCommand(command=cmd, timestamp=ts)
                        )
                        logger.debug("Added command to session: %s", session)
                    else:
                        logger.error(
                            "No matching authenticated session found for CMD line:\n%s",
                            line,
                        )
                    continue

            except Exception as e:
                logger.error("Error processing line:\n%s\nException: %s", line, e)
                raise e

    logger.info(
        "Parsed %s: sessions=%d unique_client_ips=%d\n",
        filepath,
        len(user_sessions.sessions),
        len(clients),
    )

    return user_sessions, clients


def print_stats(user_sessions: UserSessions, clients: Clients):
    successful_auths = sum(1 for s in user_sessions.sessions if s.auth_success)
    failed_auths = len(user_sessions) - successful_auths
    connected_sessions = sum(
        1 for s in user_sessions.sessions if s.disconnect_time is None
    )
    error_sessions = sum(
        1 for s in user_sessions.sessions if s.connect_error is not None
    )
    non_error_sessions = len(user_sessions) - error_sessions
    ssh_sessions = sum(
        1 for s in user_sessions.sessions if s.protocol == SessionProtocol.SSH
    )
    telnet_sessions = sum(
        1 for s in user_sessions.sessions if s.protocol == SessionProtocol.TELNET
    )

    print(f"Total sessions: {len(user_sessions)}")
    print(f"SSH sessions: {ssh_sessions}")
    print(f"Telnet sessions: {telnet_sessions}")
    print(f"Sessions with errors: {error_sessions}")
    print(f"Sessions without errors: {non_error_sessions}")
    print(f"Failed authentications: {failed_auths}")
    print(f"Successful authentications: {successful_auths}")
    print(f"Still connected sessions: {connected_sessions}")

    print(f"Unique client IPs: {len(clients)}")

    """
    For all sessions with commands, print the session details and the list of commands executed during the session.
    These should be group by IP, so search via client IP and print the sessions for each client together.
    """
    for client in clients.get_clients():
        first_session = True
        for session in client.get_sessions():
            if len(session.commands):
                if first_session:
                    print(client)
                    first_session = False
                print(f"\nSession: {session}")
                for cmd in session.commands.get_commands():
                    print(cmd)

    print("")
    print("")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Parse gzip-compressed log files")

    parser.add_argument(
        "-d",
        "--debug",
        action="store_true",
        help="Enable DEBUG level logging verbosity (default: INFO)",
    )

    parser.add_argument(
        "files", nargs="+", help="List of gzip-compressed log files to parse"
    )

    args = parser.parse_args()
    return args


def setup_logging(args: argparse.Namespace):
    log_level = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(level=log_level, format="%(levelname)s: %(message)s")


def main():
    args = parse_args()
    setup_logging(args)

    # Process each log file
    parse_log_files(args.files)

    logger.info("Finished processing all log files")


if __name__ == "__main__":
    main()
