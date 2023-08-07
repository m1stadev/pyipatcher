from collections import namedtuple
from enum import IntEnum, StrEnum

iBootVersion = namedtuple('iBootVersion', ('major', 'minor'))


class iBootStage(IntEnum):
    STAGE_1 = 1
    STAGE_2 = 2


class iBootPatch(IntEnum):
    DEBUG_ENABLED = 1
    UNLOCK_NVRAM = 2
    REBOOT_TO_FSBOOT = 3
    SIG_CHECKS = 4
    FRESH_NONCE = 5
