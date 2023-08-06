from collections import namedtuple
from enum import IntEnum

iBootVersion = namedtuple('iBootVersion', ('major', 'minor'))


class iBootStage(IntEnum):
    STAGE_1 = 1
    STAGE_2 = 2
