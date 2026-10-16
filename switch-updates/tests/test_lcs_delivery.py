"""lcs delivery infos: layout, HMAC and ns's join checks. The two reference blobs are ones 20.5.0's own
ns code accepted, run under unicorn (tools/lcs_ns_check.py)."""

import pytest

from switchlcs import delivery as d

# SystemDeliveryInfo for a retail Switch on 20.5.0 (build 100), accepted by ns 0x13fa5c.
SYSTEM_20_5_0_DATA = bytes.fromhex(
    "01000000010000000100000064005050160800000000000109060000010000001608000000000001")
SYSTEM_20_5_0_MAC = bytes.fromhex(
    "42b065f28f8d90f77951e0f8a3ad10c58f4a9e812fb8ca3ef35566cbf0b80378")
# ApplicationDeliveryInfo for the Violet update v786432, accepted by ns 0x141304 / 0x1412c0.
VIOLET_DATA = bytes.fromhex("010000000000000000e0c508608f000100000c000000000000000000020000000000")
VIOLET_MAC = bytes.fromhex("0a85470e1b0d6b3e1e47f13125ba0954885b350b6dd7f14755c2c54f72caa183")


def system_20_5_0():
    return d.SystemDeliveryInfo(system_update_version=d.system_version(20, 5, 0, 100))


def test_system_reference_blob():
    blob = system_20_5_0().pack()
    assert len(blob) == d.SIZE
    assert blob[:len(SYSTEM_20_5_0_DATA)] == SYSTEM_20_5_0_DATA
    assert blob[len(SYSTEM_20_5_0_DATA):d.SIGNED] == bytes(d.SIGNED - len(SYSTEM_20_5_0_DATA))
    assert blob[d.SIGNED:] == SYSTEM_20_5_0_MAC
    assert d.verify_system(blob) == 0


def test_application_reference_blob():
    blob = d.ApplicationDeliveryInfo(application_id=0x01008F6008C5E000,
                                     application_version=786432, attributes=d.ATTRIBUTE_REQUESTED).pack()
    assert blob[:len(VIOLET_DATA)] == VIOLET_DATA
    assert blob[d.SIGNED:] == VIOLET_MAC
    assert d.verify_application(blob) == 0


def test_round_trip():
    info = system_20_5_0()
    assert d.SystemDeliveryInfo.parse(info.pack()) == info
    app = d.ApplicationDeliveryInfo(application_id=1, application_version=0x10000,
                                    required_system_version=d.system_version(20, 0, 1),
                                    attributes=d.ATTRIBUTE_REQUESTED | d.ATTRIBUTE_BIT28)
    assert d.ApplicationDeliveryInfo.parse(app.pack()) == app


def test_parse_rejects_a_bad_mac():
    blob = bytearray(system_20_5_0().pack())
    blob[0x0C] ^= 1
    with pytest.raises(ValueError, match="2016-0931"):
        d.SystemDeliveryInfo.parse(bytes(blob))
    assert d.SystemDeliveryInfo.parse(bytes(blob), verify=False).system_update_version & 1
    # The keys differ: an application info signed with the system key fails.
    app = d.ApplicationDeliveryInfo(application_id=1, application_version=1).pack(key=d.SYSTEM_KEY)
    assert d.verify_application(app) == d.RESULT_APPLICATION_MAC


@pytest.mark.parametrize("field,value,result", [
    ("system_delivery_protocol_version", 0, d.RESULT_SYSTEM_PROTOCOL_LOW),
    ("system_delivery_protocol_version", 2, d.RESULT_SYSTEM_PROTOCOL_HIGH),
    ("application_delivery_protocol_version", 2, d.RESULT_APPLICATION_PROTOCOL_HIGH),
    ("reserved", b"\xff" * 0xB8, 0),
    ("system_update_id", 0, 0),
])
def test_join_gate(field, value, result):
    info = d.SystemDeliveryInfo(**{**system_20_5_0().__dict__, field: value})
    assert d.verify_system(info.pack()) == result


def test_version_floor():
    blob = system_20_5_0().pack()
    assert d.verify_system(blob, required_system_version=d.system_version(20, 5, 1)) \
        == d.RESULT_SYSTEM_VERSION_FLOOR
    assert d.verify_system(blob, required_system_version=d.system_version(20, 5, 0, 100)) == 0


def test_error_codes_and_versions():
    assert d.error_code(d.RESULT_SYSTEM_MAC) == "2016-0931"
    assert d.error_code(d.RESULT_SYSTEM_PROTOCOL_LOW) == "2016-0801"
    assert d.error_code(d.RESULT_SYSTEM_VERSION_FLOOR) == "2016-1110"
    assert d.system_version(20, 5, 0, 100) == 0x50500064
    assert d.version_string(1342242866) == "20.0.1-50"


def test_selectable():
    me = system_20_5_0()
    assert d.selectable(system_20_5_0(), me)
    assert not d.selectable(d.SystemDeliveryInfo(**{**me.__dict__, "platform_region": 1}), me)
    assert not d.selectable(d.SystemDeliveryInfo(**{**me.__dict__, "has_exfat": 0}), me)
    assert not d.selectable(d.SystemDeliveryInfo(**{**me.__dict__,
                                                    "updatable_firmware_group_id": 0xFF}), me)
    # Group 0 is "1": only firmware variation 0 may take its update.
    assert not d.selectable(d.SystemDeliveryInfo(**{**me.__dict__,
                                                    "updatable_firmware_group_id": 0}), me)


def test_can_deliver_application():
    def app(version, bit28=False, required=0):
        attrs = d.ATTRIBUTE_REQUESTED | (d.ATTRIBUTE_BIT28 if bit28 else 0)
        return d.ApplicationDeliveryInfo(application_id=1, application_version=version,
                                         required_application_version=required, attributes=attrs)
    assert d.can_deliver_application(app(0), app(0x10000))
    assert not d.can_deliver_application(app(0x20000), app(0x10000))
    assert d.can_deliver_application(app(0x10000), app(0x10000))
    assert not d.can_deliver_application(app(0x10000, bit28=True), app(0x10000))
    assert not d.can_deliver_application(app(0, required=0x30000), app(0x10000))
    assert not d.can_deliver_application(None, app(0x10000))


def test_a_member_at_the_consoles_version_is_sent_nothing():
    """A console's delivery info (Let's Go 1.0.2, seen live) and pokeldn's after installing that update.
    Without bit 28 in pokeldn's, CanDeliverApplication allows an equal version and the console sent the
    update again without end."""
    console = d.ApplicationDeliveryInfo(application_id=0x010003F003A34000, application_version=131072,
                                        required_application_version=131072, required_system_version=0x20100000,
                                        attributes=0x50000002)
    assert d.CONSOLE_ATTRIBUTES == console.attributes
    ours = d.ApplicationDeliveryInfo(application_id=0x010003F003A34000, application_version=131072)
    assert not d.can_deliver_application(ours, console)
    assert d.can_deliver_application(d.ApplicationDeliveryInfo(application_id=0x010003F003A34000,
                                                               application_version=0), console)
    looped = d.ApplicationDeliveryInfo(application_id=0x010003F003A34000, application_version=131072,
                                       attributes=d.ATTRIBUTE_REQUESTED)
    assert d.can_deliver_application(looped, console)
