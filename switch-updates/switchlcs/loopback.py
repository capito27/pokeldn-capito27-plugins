"""An lcs group over the loopback interface, for development: tools/lcs_host.py --loopback and
lcs_match.py --loopback run the 55555 and 55556 protocols over the OS's TCP between two local
addresses, with no LDN network and no radio, so a multi-GB transfer runs at disk speed.

The two stand in for switchlcs.net's Host and Guest with the attributes the
tools use. LDN's scan has no loopback equivalent, so the host serves its advertise data on
ADVERTISE_PORT: a joiner connects and reads the 0x100 bytes. That port exists only here.
"""

import socket
import threading
import time

from switchlcs import advertise as adv

HOST_IP = "127.0.0.1"
GUEST_IP = "127.0.0.2"
ADVERTISE_PORT = 45554                  # below the dynamic range: see session.SocketNetwork


class LoopbackHost:
    """net.Host's part the lcs host uses: start, stop, our_ip, net and set_app_data_later."""

    net = None                         # no radio: net.tcp_for gives session.SocketNetwork on our_ip

    def __init__(self, app_data: bytes, ip: str = HOST_IP):
        self.our_ip, self.app_data = ip, bytes(app_data)
        self._listener = None

    def start(self) -> None:
        self._listener = socket.socket()
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.bind((self.our_ip, ADVERTISE_PORT))
        self._listener.listen(8)
        threading.Thread(target=self._serve, args=(self._listener,), name="lcs-loopback-advertise",
                         daemon=True).start()

    def _serve(self, listener) -> None:
        """Until stop closes `listener`: its own reference, as stop drops the attribute."""
        while True:
            try:
                conn, _addr = listener.accept()
            except OSError:
                return
            with conn:
                conn.sendall(self.app_data)

    def set_app_data_later(self, app_data: bytes) -> None:
        self.app_data = bytes(app_data)

    def stop(self) -> None:
        if self._listener is not None:
            # Linux leaves a listener that another thread waits on in accept listening after close, still
            # serving this group's data to the next joiner; shutdown wakes it there. Windows refuses shutdown
            # on a listener, and close alone wakes it.
            try:
                self._listener.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            self._listener.close()
            self._listener = None


class LoopbackGuest:
    """net.Guest's part the lcs joiner uses: start (the "scan"), stop, app_data, host_ip, our_ip
    and net."""

    net = None

    def __init__(self, host_ip: str = HOST_IP, ip: str = GUEST_IP):
        self.host_ip, self.our_ip, self.app_data = host_ip, ip, b""

    def start(self, timeout: float = 30) -> None:
        """Read the host's advertise data, waiting up to `timeout` for the host to come up."""
        deadline = time.monotonic() + timeout
        while True:
            try:
                with socket.create_connection((self.host_ip, ADVERTISE_PORT), 5,
                                              source_address=(self.our_ip, 0)) as sock:
                    data = b""
                    while len(data) < adv.SIZE:
                        part = sock.recv(adv.SIZE - len(data))
                        if not part:
                            break
                        data += part
            except OSError:
                if time.monotonic() > deadline:
                    raise TimeoutError(f"no lcs host at {self.host_ip}") from None
                time.sleep(0.25)
                continue
            if len(data) == adv.SIZE:
                self.app_data = data
                return
            raise ConnectionError(f"advertise data of {len(data)} bytes from {self.host_ip}")

    def stop(self) -> None:
        pass
