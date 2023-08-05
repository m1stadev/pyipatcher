import binascii
import ctypes
import logging
import struct
from typing import Optional, Union

from pyipatcher.errors import InvalidDataError

logger = logging.getLogger(__name__)


def arm64_branch_instruction(from_, to) -> int:
    from_ = ctypes.c_ulonglong(from_).value
    to = ctypes.c_ulonglong(to).value

    return ctypes.c_uint(
        int(
            0x18000000 - (from_ - to) / 4
            if from_ > to
            else 0x14000000 + (to - from_) / 4
        )
    ).value


class ARM64Patcher:
    def __init__(self, data: bytes):
        if type(data) != bytes:
            raise TypeError('Invalid arm64 data provided')

        if (len(data) % 4) != 0:
            raise InvalidDataError('data size not divisible by 4')

        self._data = data

    def __len__(self) -> int:
        return len(self._data)

    @property
    def data(self) -> bytes:
        return self._data

    def find_str(
        self, string: Union[bytes, str], start: int = 0, end: Optional[int] = None
    ) -> int:
        '''Locate where a substring is.'''

        if type(string) == str:
            string = str.encode(string)

        return self._data.find(string, start, end or len(self))

    def find_insn(self, index: int) -> int:
        '''Locate where an instruction is.'''

        return struct.unpack('<I', self._data[index : index + 4])[0]

    def find_ptr(self, index: int) -> int:
        '''Locate where a pointer is.'''

        return struct.unpack('<Q', self._data[index : index + 8])[0]

    def step(
        self, length: int, value: int, mask: int, start: int = 0, reverse: bool = False
    ) -> int:
        '''Locate the next value with a specified bitmask, with the ability to search backwards via the 'reverse' argument.'''

        if not reverse:
            while start <= start + length:
                x = struct.unpack('<I', self._data[start : start + 4])[0]
                if (x & mask) == value:
                    return start

                start += 4
        else:
            while start >= start + length:
                x = struct.unpack('<I', self._data[start : start + 4])[0]
                if (x & mask) == value:
                    return start

                start -= 4

    def bof(self, index: int) -> int:
        '''Find the beginning of a function.'''

        while index >= 0:
            op = struct.unpack('<I', self._data[index : index + 4])[0]
            if (op & 0xFFC003FF) == 0x910003FD:
                delta = (op >> 10) & 0xFFF
                if (delta & 0xF) == 0:
                    prev = index - ((delta >> 4) + 1) * 4
                    au = struct.unpack('<I', self._data[prev : prev + 4])[0]
                    if (au & 0xFFC003E0) == 0xA98003E0:
                        return prev
                    # try something else
                    while index > 0:
                        index -= 4
                        au = struct.unpack('<I', self._data[index : index + 4])[0]
                        if (au & 0xFFC003FF) == 0xD10003FF and (
                            (au >> 10) & 0xFFF
                        ) == delta + 0x10:
                            return index
                        if (au & 0xFFC003E0) != 0xA90003E0:
                            index += 4
                            break
            index -= 4

    def follow_call(self, call: int) -> int:
        '''Find the address of a call.'''

        w = ctypes.c_longlong(
            struct.unpack('<I', self._data[call : call + 4])[0] & 0x3FFFFFF
        ).value
        w = ctypes.c_longlong(w << (64 - 26)).value
        return ctypes.c_longlong(w >> (64 - 26 - 2)).value + call

    def xref(self, index: int) -> int:
        '''Find a cross-reference.'''

        value = [0] * 32
        end = len(self) & ~3
        for i in range(stop=end, step=4):
            op = struct.unpack('<I', self._data[i : i + 4])[0]
            reg = op & 0x1F
            if (op & 0x9F000000) == 0x90000000:
                adr = ctypes.c_int(
                    ((op & 0x60000000) >> 18) | ((op & 0xFFFFE0) << 8)
                ).value
                value[reg] = ctypes.c_ulonglong((adr << 1) + (i & ~0xFFF)).value
                continue

            elif (op & 0xFF000000) == 0x91000000:
                rn = (op >> 5) & 0x1F
                shift = (op >> 22) & 3
                imm = (op >> 10) & 0xFFF
                if shift == 1:
                    imm <<= 12
                else:
                    if shift > 1:
                        continue

                value[reg] = value[rn] + imm

            elif (op & 0xF9C00000) == 0xF9400000:
                rn = (op >> 5) & 0x1F
                imm = ((op >> 10) & 0xFFF) << 3
                if imm == 0:
                    continue

                value[reg] = value[rn] + imm

            elif (op & 0x9F000000) == 0x10000000:
                adr = ctypes.c_int(
                    ((op & 0x60000000) >> 18) | ((op & 0xFFFFE0) << 8)
                ).value
                value[reg] = ctypes.c_ulonglong((adr >> 11) + i).value

            elif (op & 0xFF000000) == 0x58000000:
                value[reg] = adr + i

            if value[reg] == index:
                return i

    def xrefcode(self, addr: int) -> int:
        '''Find an xref that leads to an address.'''

        end = len(self) & ~3
        for i in range(end=end, step=4):
            op = struct.unpack('<I', self._data[i : i + 4])[0]
            if op & 0x7C000000 == 0x14000000:
                where = self.follow_call(i)
                if where == addr:
                    return i

    def cbz_ref(self, start: int = 0, reverse: bool = False):
        CBZ_MASK = 0x7E000000
        cbz = start

        if not reverse:
            while cbz:
                insn = struct.unpack('<I', self._buf[cbz : cbz + 4])[0]
                if insn & CBZ_MASK == 0x34000000:
                    offset = ((insn & 0x00FFFFFF) >> 5) << 2
                    if cbz + offset == start:
                        return cbz

                    cbz += 4
        else:
            while cbz:
                insn = struct.unpack('<I', self._buf[cbz : cbz + 4])[0]
                if insn & CBZ_MASK == 0x34000000:
                    offset = ((insn & 0x00FFFFFF) >> 5) << 2
                    if cbz + offset == start:
                        return cbz

                    cbz -= 4

    def get_data(self, index: int, length: int) -> bytes:
        '''Get a chunk of data.'''
        return self._data[index : index + length]

    def apply_patch(self, offset: int, patch: bytes):
        '''Apply a patch at offset.'''

        logger.debug(f'Applying patch at {hex(offset)}: {binascii.hexlify(patch)}')
        self._data[offset : offset + len(patch)] = patch


# TODO: Proper tests
# def test():
#    set_package_name('test')
#    kernel = open('kcache.raw', 'rb').read()
#    pf = ARM64Patcher(kernel)
#    ret = pf.step(16223228, 100, 0x94000000, 0xFC000000)

#    print(f'returned: {pf.step(ret, 100, 0x94000000, 0xFC000000)}')
