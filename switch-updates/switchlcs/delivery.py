"""SystemDeliveryInfo and ApplicationDeliveryInfo: what each lcs member advertises, and `ns`'s checks.

Both are 0x100 bytes, 0xE0 of little-endian data then HMAC-SHA256 over it. The two keys are constants in
`ns`'s read-only data (20.5.0: 0x2c3340 and 0x2c3360), the same on every console; run under unicorn,
`ns`'s MAC function 0x31a80 is exactly HMAC-SHA256 under them. docs/lcs.md "DeliveryInfo and the join
gate".
"""

import hashlib
import hmac
import struct
from dataclasses import dataclass

SYSTEM_KEY = bytes.fromhex("5680121bb673e04289ef4ae6d7aef6f6b3a8cd677651957319a2fa598f32eccb")
APPLICATION_KEY = bytes.fromhex("1ea1fe6a41e2438b3a382357dd03af627a443ee098aec445f9446f18ae5f97c4")

SIZE = 0x100
SIGNED = 0xE0

# The Switch's system update title; Switch 2 adds 0x0400000000000816.
SYSTEM_UPDATE_ID = 0x0100000000000816
ACCEPTABLE_SYSTEM_UPDATE_IDS = (0x0400000000000816, SYSTEM_UPDATE_ID)

# System settings `contents_delivery!*` defaults (switchbrew System Settings).
SYSTEM_DELIVERY_PROTOCOL_VERSION = 1
APPLICATION_DELIVERY_PROTOCOL_VERSION = 1
ACCEPTABLE_APPLICATION_DELIVERY_PROTOCOL_VERSION = 0
REQUIRED_SYSTEM_VERSION_TO_DELIVER_APPLICATION = 0
UPDATABLE_FIRMWARE_GROUPS = (1, 3, 4, 8, 23, 127, 2047, 2048, 6144)      # 20.0.0+

# A retail Switch from 13.0.0 (`ns.systemupdate!*`, global region).
RETAIL_FIRMWARE_VARIATION = 9
RETAIL_UPDATABLE_FIRMWARE_GROUP = 6

# ns results (module 16, error code 2016-<desc>), as 20.5.0's validator 0x13fa5c returns them.
RESULT_SYSTEM_PROTOCOL_LOW = 0x64210         # 2016-0801: below the setting
RESULT_SYSTEM_PROTOCOL_HIGH = 0x64410        # 2016-0802: above the setting
RESULT_APPLICATION_PROTOCOL_LOW = 0x65610    # 2016-0811: below the acceptable minimum
RESULT_APPLICATION_PROTOCOL_HIGH = 0x65810   # 2016-0812: above the setting
RESULT_APPLICATION_MAC = 0x74410             # 2016-0930
RESULT_SYSTEM_MAC = 0x74610                  # 2016-0931
RESULT_SYSTEM_VERSION_FLOOR = 0x8AC10        # 2016-1110

# ApplicationDeliveryAttributeTag bits ns sets beside the caller's bit 1.
ATTRIBUTE_REQUESTED = 1 << 1
ATTRIBUTE_BIT28 = 1 << 28
ATTRIBUTE_BIT30 = 1 << 30
# What a 20.x console's GetApplicationDeliveryInfo gives (seen live: 0x50000002). Bit 28 makes
# CanDeliverApplication want a strictly newer sender, so a member at the host's version is sent
# nothing; without it, a console host sends the update again to a member that already has it.
CONSOLE_ATTRIBUTES = ATTRIBUTE_REQUESTED | ATTRIBUTE_BIT28 | ATTRIBUTE_BIT30


def error_code(result):
    """An nn::Result as the UI shows it, e.g. 0x74610 -> '2016-0931'."""
    return f"{2000 + (result & 0x1FF):04d}-{(result >> 9) & 0x1FFF:04d}"


def system_version(major, minor, micro, relstep=0):
    """The packed version ns and cnmt use: 20.5.0 build 100 -> 0x50500064."""
    return (major << 26) | (minor << 20) | (micro << 16) | relstep


def version_string(value):
    return f"{value >> 26}.{(value >> 20) & 0x3F}.{(value >> 16) & 0xF}-{value & 0xFFFF}"


def _mac(key, data):
    return hmac.new(key, data[:SIGNED], hashlib.sha256).digest()


_SYSTEM = struct.Struct("<IIB3xIQBBBBB3xQ")         # through 0x28; reserved to 0xE0


@dataclass
class SystemDeliveryInfo:
    system_update_version: int
    system_update_id: int = SYSTEM_UPDATE_ID
    old_system_update_id: int = SYSTEM_UPDATE_ID
    system_update_id_flag: int = 1               # set by GetSystemDeliveryInfo from 20.0.0
    has_exfat: int = 1
    firmware_variation_id: int = RETAIL_FIRMWARE_VARIATION
    updatable_firmware_group_id: int = RETAIL_UPDATABLE_FIRMWARE_GROUP
    platform_region: int = 0                     # 0 global, 1 China
    platform: int = 0                            # SystemDeliveryInfoPlatform, 20.0.0+
    system_delivery_protocol_version: int = SYSTEM_DELIVERY_PROTOCOL_VERSION
    application_delivery_protocol_version: int = APPLICATION_DELIVERY_PROTOCOL_VERSION
    reserved: bytes = bytes(SIGNED - _SYSTEM.size)

    def data(self):
        return _SYSTEM.pack(self.system_delivery_protocol_version,
                            self.application_delivery_protocol_version, self.has_exfat,
                            self.system_update_version, self.old_system_update_id,
                            self.firmware_variation_id, self.updatable_firmware_group_id,
                            self.platform_region, self.platform, self.system_update_id_flag,
                            self.system_update_id) + self.reserved

    def pack(self, key=SYSTEM_KEY):
        data = self.data()
        return data + _mac(key, data)

    @property
    def effective_system_update_id(self):
        return self.system_update_id if self.system_update_id_flag else self.old_system_update_id

    @classmethod
    def parse(cls, blob, key=SYSTEM_KEY, verify=True):
        if len(blob) != SIZE:
            raise ValueError(f"a SystemDeliveryInfo is {SIZE:#x} bytes, not {len(blob):#x}")
        if verify and not hmac.compare_digest(_mac(key, blob), blob[SIGNED:]):
            raise ValueError(f"SystemDeliveryInfo HMAC mismatch ({error_code(RESULT_SYSTEM_MAC)})")
        (spv, apv, exfat, version, old_id, variation, group, region, platform, flag,
         update_id) = _SYSTEM.unpack_from(blob)
        return cls(system_update_version=version, system_update_id=update_id,
                   old_system_update_id=old_id, system_update_id_flag=flag, has_exfat=exfat,
                   firmware_variation_id=variation, updatable_firmware_group_id=group,
                   platform_region=region, platform=platform,
                   system_delivery_protocol_version=spv,
                   application_delivery_protocol_version=apv,
                   reserved=bytes(blob[_SYSTEM.size:SIGNED]))


_APPLICATION = struct.Struct("<I4xQIIIIBB")          # through 0x22; reserved to 0xE0


@dataclass
class ApplicationDeliveryInfo:
    application_id: int
    application_version: int
    required_application_version: int = 0
    required_system_version: int = 0
    attributes: int = CONSOLE_ATTRIBUTES
    content_meta_platform: int = 0               # 20.0.0+
    proper_program_exists: int = 0               # 20.0.0+
    application_delivery_protocol_version: int = APPLICATION_DELIVERY_PROTOCOL_VERSION
    reserved: bytes = bytes(SIGNED - _APPLICATION.size)

    def data(self):
        return _APPLICATION.pack(self.application_delivery_protocol_version, self.application_id,
                                 self.application_version, self.required_application_version,
                                 self.required_system_version, self.attributes,
                                 self.content_meta_platform, self.proper_program_exists) + self.reserved

    def pack(self, key=APPLICATION_KEY):
        data = self.data()
        return data + _mac(key, data)

    @classmethod
    def parse(cls, blob, key=APPLICATION_KEY, verify=True):
        if len(blob) != SIZE:
            raise ValueError(f"an ApplicationDeliveryInfo is {SIZE:#x} bytes, not {len(blob):#x}")
        if verify and not hmac.compare_digest(_mac(key, blob), blob[SIGNED:]):
            raise ValueError(f"ApplicationDeliveryInfo HMAC mismatch "
                             f"({error_code(RESULT_APPLICATION_MAC)})")
        apv, app_id, version, req_app, req_sys, attrs, platform, proper = \
            _APPLICATION.unpack_from(blob)
        return cls(application_id=app_id, application_version=version,
                   required_application_version=req_app, required_system_version=req_sys,
                   attributes=attrs, content_meta_platform=platform, proper_program_exists=proper,
                   application_delivery_protocol_version=apv,
                   reserved=bytes(blob[_APPLICATION.size:SIGNED]))


def verify_system(blob, required_system_version=REQUIRED_SYSTEM_VERSION_TO_DELIVER_APPLICATION,
                  protocol=SYSTEM_DELIVERY_PROTOCOL_VERSION,
                  application_protocol=APPLICATION_DELIVERY_PROTOCOL_VERSION,
                  acceptable_application_protocol=ACCEPTABLE_APPLICATION_DELIVERY_PROTOCOL_VERSION):
    """The join gate, as ns 0x13fa5c runs it: -> 0 or the ns result. HMAC, then the system protocol
    version (equal to the setting), then the application protocol version (within the settings), then
    the system update version against the floor. The system update ID is not checked here."""
    if not hmac.compare_digest(_mac(SYSTEM_KEY, blob), blob[SIGNED:SIZE]):
        return RESULT_SYSTEM_MAC
    spv, apv = struct.unpack_from("<II", blob)
    if spv > protocol:
        return RESULT_SYSTEM_PROTOCOL_HIGH
    if spv < protocol:
        return RESULT_SYSTEM_PROTOCOL_LOW
    if apv > application_protocol:
        return RESULT_APPLICATION_PROTOCOL_HIGH
    if apv < acceptable_application_protocol:
        return RESULT_APPLICATION_PROTOCOL_LOW
    if struct.unpack_from("<I", blob, 0xC)[0] < required_system_version:
        return RESULT_SYSTEM_VERSION_FLOOR
    return 0


def verify_application(blob, application_protocol=APPLICATION_DELIVERY_PROTOCOL_VERSION,
                       acceptable=ACCEPTABLE_APPLICATION_DELIVERY_PROTOCOL_VERSION):
    """ns 0x141304 (HMAC) then 0x1412c0 (protocol version within the settings): -> 0 or the result."""
    if not hmac.compare_digest(_mac(APPLICATION_KEY, blob), blob[SIGNED:SIZE]):
        return RESULT_APPLICATION_MAC
    apv = struct.unpack_from("<I", blob)[0]
    if apv > application_protocol:
        return RESULT_APPLICATION_PROTOCOL_HIGH
    if apv < acceptable:
        return RESULT_APPLICATION_PROTOCOL_LOW
    return 0


def selectable(candidate, selector, groups=UPDATABLE_FIRMWARE_GROUPS):
    """SelectLatestSystemDeliveryInfo's per-candidate filter (switchbrew): whether `selector` (the
    console choosing) would consider `candidate` as the group's system update source."""
    if candidate.platform_region != selector.platform_region:
        return False
    if selector.has_exfat and not candidate.has_exfat:
        return False
    if selector.firmware_variation_id == 0xFF or candidate.updatable_firmware_group_id == 0xFF:
        return False
    if candidate.updatable_firmware_group_id >= len(groups):
        return False
    return bool((groups[candidate.updatable_firmware_group_id] >> selector.firmware_variation_id) & 1)


def can_deliver_application(receiver, sender):
    """ns CanDeliverApplication(receiver, sender) after validation (switchbrew): whether `sender`'s
    update can go to `receiver`. A receiver of None (the application not installed) gets nothing."""
    if receiver is None:
        return False
    if max(receiver.required_application_version,
           sender.required_application_version) > sender.application_version:
        return False
    if receiver.attributes & ATTRIBUTE_BIT28:
        return sender.application_version > receiver.application_version
    return sender.application_version >= receiver.application_version
