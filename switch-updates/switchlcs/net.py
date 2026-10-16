"""The console's group through pokeldn's plugin surface (pokeldn.ldn.network, since API 1.7), with this plugin's TCP
(switchlcs.tcp) on the network's IP protocol hook. `Guest` joins a console's group, `Host` opens one for a console
to join; both start, stop and carry the addresses the scripts read, as switchlcs.loopback's stand-ins do."""
from pokeldn.ldn import network

from switchlcs import advertise as adv, session
from switchlcs.tcp import PROTO_TCP, TcpLayer

NAME = "Match Version With Local Users"


class _Stack:
    """What TcpLayer needs of a stack: our address, a name for its timer thread, and send_ip."""

    def __init__(self, net: network.Network):
        self._net = net
        self.name = "lcs"

    @property
    def ip(self) -> str:
        return self._net.ip

    def send_ip(self, protocol: int, dst_ip: str, payload: bytes) -> bool:
        return self._net.send_ip(protocol, dst_ip, payload)


def tcp_for(link):
    """The TCP that carries 55555 and 55556 on `link`: this plugin's on the radio's stack, or the OS's for
    switchlcs.loopback's stand-ins."""
    net = getattr(link, "net", None)
    if net is None:
        return session.SocketNetwork(link.our_ip)
    layer = TcpLayer(_Stack(net))
    net.add_protocol(PROTO_TCP, layer.handle)
    return layer


class Guest:
    """pokeldn as a member of the console's group."""

    def __init__(self, keys: str, log=print):
        self._keys, self._log, self.net = keys, log, None

    def start(self, timeout: float = 30) -> None:
        self.net = network.join(adv.LOCAL_COMMUNICATION_ID, keys=self._keys, password=adv.PASSPHRASE,
                                nickname=adv.GUEST_USER_NAME, app_version=adv.LOCAL_COMMUNICATION_VERSION,
                                name=NAME, log=self._log, timeout=timeout)

    @property
    def app_data(self) -> bytes:
        return self.net.application_data

    @property
    def host_ip(self) -> str:
        return self.net.host_ip

    @property
    def our_ip(self) -> str:
        return self.net.ip

    def stop(self) -> None:
        if self.net is not None:
            self.net.close()


class Host:
    """pokeldn hosting a group a console joins (tools/lcs_host.py)."""

    def __init__(self, keys: str, app_data: bytes, protocol: int, channel: int | None = None, log=print):
        self._keys, self._app_data, self._protocol, self._channel, self._log = keys, app_data, protocol, channel, log
        self.net = None

    def start(self, timeout: float = 30) -> None:
        self.net = network.host(adv.LOCAL_COMMUNICATION_ID, keys=self._keys, password=adv.PASSPHRASE,
                                nickname=adv.HOST_USER_NAME, application_data=self._app_data,
                                scene_id=adv.SCENE_ID, app_version=adv.LOCAL_COMMUNICATION_VERSION,
                                max_participants=adv.MAX_NODES, channel=self._channel, protocol=self._protocol,
                                log=self._log, timeout=timeout)

    @property
    def our_ip(self) -> str:
        return self.net.ip

    def set_app_data_later(self, data: bytes) -> None:
        self.net.set_application_data(data)

    def stop(self) -> None:
        if self.net is not None:
            self.net.close()
