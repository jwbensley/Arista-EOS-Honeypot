#!/usr/bin/env python3

from __future__ import annotations

import argparse
import enum
import gzip
import logging
import re
from datetime import datetime
from typing import Optional, Tuple

logger = logging.getLogger(__name__)


class SessionCommand:
    """Represents a single command executed during a session."""

    def __init__(self, command: str, timestamp: datetime, result: str):
        self.command = command
        self.timestamp = timestamp
        self.result = result

    def __repr__(self):
        return f"SessionCommand(command='{self.command}', timestamp={self.timestamp}, result='{self.result}')"

class SessionCommands:
    """Container for a list of SessionCommand objects."""
    
    def __init__(self):
        self.commands: list[SessionCommand] = []

    def add_command(self, command: SessionCommand):
        """Add a command to the session."""
        self.commands.append(command)

    def __repr__(self):
        return f"SessionCommands(count={len(self.commands)})"

class SessionProtocol(enum.Enum):
    SSH = "SSH"
    TELNET = "TELNET"

    @staticmethod
    def from_str(value: str) -> SessionProtocol:
        value = value.upper()
        # This covers ssh and sshd, as well as telnet and telnetd
        if value.startswith("SSH"):
            return SessionProtocol.SSH
        elif value.startswith("TELNET"):
            return SessionProtocol.TELNET
        elif value.startswith("REMOTE"):
            # Some log entries use "remote" as the service name for SSH sessions
            return SessionProtocol.SSH
        else:
            raise ValueError(f"Unknown protocol: {value}")

class SessionStatus(enum.Enum):
    CONNECTED = "Connected"
    SESSION_LIMIT_REACHED = "Session Limit Reached"

class UserSession:
    """Represents a user authentication session."""

    def __init__(self, connect_time: datetime, protocol: SessionProtocol, pid: Optional[int], client_ip: ClientIP, disconnect_time: Optional[datetime] = None, connect_error: Optional[SessionStatus] = None):
        self.connect_time = connect_time
        self.disconnect_time: Optional[datetime] = disconnect_time
        self.pid: Optional[int] = pid
        self.connect_error: Optional[SessionStatus] = connect_error
        self.protocol = protocol
        self.auth_success = False 
        self.client_ip = client_ip
        self.commands = SessionCommands()

    def __repr__(self):
        return f"UserSession(connect_time={self.connect_time}, protocol={self.protocol}, pid={self.pid}, auth_success={self.auth_success}, commands={len(self.commands.commands)})"

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

    def get_session(self, connect_time: Optional[datetime], protocol: Optional[SessionProtocol], pid: Optional[int], client_ip: Optional[ClientIP]) -> UserSession:
        """Retrieve a session based on its unique attributes."""

        if not any([connect_time, protocol, pid, client_ip]):
            raise ValueError("At least one attribute must be provided to identify a session.")

        for session in self.sessions:
            if ((connect_time is None or session.connect_time == connect_time) and
                (protocol is None or session.protocol == protocol) and
                (pid is None or session.pid == pid) and
                (client_ip is None or session.client_ip == client_ip)):
                return session

        raise LookupError("No session found matching the provided attributes.")

    def find_latest_session(
        self,
        protocol: Optional[SessionProtocol] = None,
        pid: Optional[int] = None,
        client_ip: Optional[ClientIP] = None,
        require_not_disconnected: bool = False
    ) -> Optional[UserSession]:
        """Find the most recent session that matches a set of optional filters."""

        candidates = self.sessions

        if protocol is not None:
            candidates = [s for s in candidates if s.protocol == protocol]
        if pid is not None:
            candidates = [s for s in candidates if s.pid == pid]
        if client_ip is not None:
            candidates = [s for s in candidates if s.client_ip == client_ip]
        if require_not_disconnected:
            candidates = [s for s in candidates if s.disconnect_time is None]

        if not candidates:
            return None

        return sorted(candidates, key=lambda s: s.connect_time, reverse=True)[0]

    def __repr__(self):
        return f"UserSessions(count={len(self.sessions)})"

class ClientIP:
    """Represents a client IP address with its associated sessions."""
    
    def __init__(self, ip_address: str):
        self.ip_address = ClientIP.normalize_ip(ip_address)
        self.sessions: list[UserSession] = []

    def add_session(self, session: UserSession) -> None:
        """Add a user session to this client IP."""
        self.sessions.append(session)

    @staticmethod
    def normalize_ip(ip: str) -> str:
        return ip.removeprefix("::ffff:")

    def __repr__(self):
        return f"ClientIP(ip='{self.ip_address}', sessions={len(self.sessions)})"

class ClientIPs:
    """Container for a list of ClientIP objects."""
    
    def __init__(self):
        self.client_ips: dict[str, ClientIP] = {}

    def get_or_create_client_ip(self, ip_address: str) -> ClientIP:
        """Retrieve an existing ClientIP or create a new one if it doesn't exist."""
        normalized_ip = ClientIP.normalize_ip(ip_address)
        if normalized_ip not in self.client_ips:
            self.client_ips[normalized_ip] = ClientIP(normalized_ip)
        return self.client_ips[normalized_ip]

    def __repr__(self):
        return f"ClientIPs(count={len(self.client_ips)})"

    def __len__(self):
        return len(self.client_ips)

def parse_log_files(filepaths: list[str]) -> Tuple[UserSessions, ClientIPs]:
    """Parse a gzip-compressed log files"""
    user_sessions = UserSessions()
    client_ips = ClientIPs()

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

    def parse_timestamp(ts: str) -> datetime:
        return datetime.strptime(ts, "%Y %b %d %H:%M:%S")

    for filepath in filepaths:

        with gzip.open(filepath, 'rt', encoding='utf-8', errors='ignore') as f:
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
            Set the disconnect time for the session with connect_time="2026 Jun 17 05:51:30", protocol=TELNET, pid=13574.
            2026 Jun 17 05:52:03 UTC edge_rtr_001.ariosnetworks.net xinetd[344]: EXIT: telnet status=1 pid=13574 duration=33(sec)

            A user successfully authenticated.
            No session PID is available in this log entry, but we can tie it to the session using the client IP and protocol.
            Set the auth_success to True for the session with protocol=SSH, client_ip="116.110.218.192".
            2026 May  3 23:11:32 UTC edge_rtr_001.ariosnetworks.net Aaa: 101: %AAA-5-LOGIN: user admin logged in [from: 116.110.218.192] [service: sshd]


            2026 May  4 04:35:45 UTC edge_rtr_001.ariosnetworks.net Aaa: 159: %ACCOUNTING-5-EXEC: admin ssh 87.251.64.176 start task_id=27 start_time=1777869345 timezone=UTC service=shell

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
                        client_ip = client_ips.get_or_create_client_ip(ip)

                        session = user_sessions.add_session(
                            UserSession(connect_time=ts, protocol=protocol, pid=pid, client_ip=client_ip)
                        )
                        client_ip.add_session(session)
                        logger.debug("Created session from START line: %s", session)
                        continue

                    fail_limit_match = FAIL_LIMIT_RE.match(line)
                    if fail_limit_match:
                        ts = parse_timestamp(fail_limit_match.group("ts"))
                        ip = fail_limit_match.group("ip")
                        client_ip = client_ips.get_or_create_client_ip(ip)

                        session = user_sessions.add_session(
                            UserSession(connect_time=ts, protocol=SessionProtocol.TELNET, pid=None, client_ip=client_ip, disconnect_time=ts, connect_error=SessionStatus.SESSION_LIMIT_REACHED)
                        )
                        client_ip.add_session(session)
                        logger.debug("Created session with session-limit error: %s", session)
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
                            logger.debug("Updated existing TELNET session from ttloop line: %s", session)
                        else:
                            logger.error("No matching session found for ttloop line: %s", line)
                        continue

                    exit_match = EXIT_RE.match(line)
                    if exit_match:
                        ts = parse_timestamp(exit_match.group("ts"))
                        protocol = SessionProtocol.from_str(exit_match.group("proto"))
                        pid = int(exit_match.group("pid"))
                        try:
                            session = user_sessions.get_session(
                                connect_time=None,
                                protocol=protocol,
                                pid=pid,
                                client_ip=None,
                            )
                            session.disconnect_time = ts
                            logger.debug("Updated session disconnect time: %s", session)
                        except LookupError:
                            logger.error("No matching session found for EXIT line: %s", line)
                        continue

                    login_success_match = LOGIN_SUCCESS_RE.match(line)
                    if login_success_match:
                        ip = login_success_match.group("ip")
                        service = login_success_match.group("service")
                        protocol = SessionProtocol.from_str(service)
                        client_ip = client_ips.get_or_create_client_ip(ip)

                        session = user_sessions.find_latest_session(
                            protocol=protocol,
                            client_ip=client_ip,
                            require_not_disconnected=True,
                        )

                        if session is not None:
                            session.auth_success = True
                            logger.debug("Marked session authenticated: %s", session)
                        else:
                            logger.error("No matching session found for LOGIN success line: %s", line)
                
                except Exception as e:
                    logger.error("Error processing line:\n%s\nException: %s", line, e)
                    raise e

        logger.info(
            "Parsed %s: sessions=%d unique_client_ips=%d",
            filepath,
            len(user_sessions.sessions),
            len(client_ips),
        )
    
    return user_sessions, client_ips

def print_stats(user_sessions: UserSessions, client_ips: ClientIPs):
    successful_auths = sum(1 for s in user_sessions.sessions if s.auth_success)
    failed_auths = len(user_sessions) - successful_auths
    connected_sessions = sum(1 for s in user_sessions.sessions if s.disconnect_time is None)
    error_sessions = sum(1 for s in user_sessions.sessions if s.connect_error is not None)
    non_error_sessions = len(user_sessions) - error_sessions
    ssh_sessions = sum(1 for s in user_sessions.sessions if s.protocol == SessionProtocol.SSH)
    telnet_sessions = sum(1 for s in user_sessions.sessions if s.protocol == SessionProtocol.TELNET)

    print(f"Total sessions: {len(user_sessions)}")
    print(f"SSH sessions: {ssh_sessions}")
    print(f"Telnet sessions: {telnet_sessions}")
    print(f"Sessions with errors: {error_sessions}")
    print(f"Sessions without errors: {non_error_sessions}")
    print(f"Failed authentications: {failed_auths}")
    print(f"Successful authentications: {successful_auths}")
    print(f"Still connected sessions: {connected_sessions}")

    print(f"Unique client IPs: {len(client_ips)}")

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Parse gzip-compressed log files"
    )
    
    parser.add_argument(
        "-d", "--debug",
        action="store_true",
        help="Enable DEBUG level logging verbosity (default: INFO)"
    )
    
    parser.add_argument(
        "files",
        nargs="+",
        help="List of gzip-compressed log files to parse"
    )
    
    args = parser.parse_args()
    return args

def setup_logging(args: argparse.Namespace):
    log_level = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(levelname)s: %(message)s"
    )

def main():
    args = parse_args()
    setup_logging(args)
    
    # Process each log file
    user_sessions, client_ips = parse_log_files(args.files)

    # Print summary statistics
    print_stats(user_sessions, client_ips)

    logger.info("Finished processing log files")

if __name__ == "__main__":
    main()

