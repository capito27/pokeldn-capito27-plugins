"""The lcs group's 0x100-byte advertise data. The vectors are what qlaunch 20.5.0's builder (0x432fd0)
wrote under unicorn; tools/lcs_qlaunch_check.py also runs the guest's parser (0x4331f0)."""

import pytest

from switchlcs import advertise as adv

APP = 0x01008F6008C5E000


def test_matches_qlaunch():
    raw = adv.Advertisement("pokeldn", [adv.App.from_info(adv.application_info(APP, b"1.2.0", attributes=0x30000))]).pack()
    assert raw[:0x20].hex() == "1301010801000000000000000000000000000000000000706f6b656c646e0000"
    assert raw[0xD8:].hex() == ("0400000000030000" "01008f6008c5e000" "0000000000000000"
                                "312e322e300000000000000000000000")
    assert raw[0x1E:0xD8] == bytes(0xD8 - 0x1E)
    assert len(raw) == adv.SIZE


def test_round_trip_and_guest_checks():
    a = adv.Advertisement("Player's Switch", [adv.App(APP, 0x50000, b"2.0.1".ljust(16, b"\0"))], node_count=3)
    assert adv.Advertisement.parse(a.pack()) == a
    raw = bytearray(a.pack())
    for at, value, what in ((2, 0, "node count"), (2, 9, "node count"), (3, 9, "node count"),
                            (4, 2, "applications")):
        bad = bytearray(raw)
        bad[at] = value
        with pytest.raises(ValueError, match=what):
            adv.Advertisement.parse(bytes(bad))
    with pytest.raises(ValueError):
        adv.Advertisement("x", [adv.App(1, 1), adv.App(2, 2)]).pack()


def test_ldn_parameters():
    assert adv.LOCAL_COMMUNICATION_VERSION == 1 and len(adv.PASSPHRASE) == 16
    info = adv.application_info(APP, b"1.0.0", update_size=0x25FA600, attributes=3)
    assert adv.App.from_info(info) == adv.App(APP, 3, b"1.0.0".ljust(16, b"\0"), update_size=0x25FA600)


def test_a_consoles_entry_names_the_update_by_size_and_display_version():
    """A Switch hosting Let's Go, Pikachu! with update 1.0.2 (v131072) installed, as its advertisement
    arrived over the board: no internal version, the update's size at +0x10."""
    raw = bytearray(adv.SIZE)
    raw[0:5] = bytes((0x13, 1, 1, 8, 1))
    raw[0xD8:] = bytes.fromhex("0400000000000000" "010003f003a34000" "00000000025fa600"
                               "312e302e320000000000000000000000")
    [app] = adv.Advertisement.parse(bytes(raw)).apps
    assert (app.application_id, app.attributes, app.update_size) == (0x010003F003A34000, 0, 39_822_848)
    assert app.display_version.rstrip(b"\0") == b"1.0.2"
