# Ported from kairos and liboffsetfinder
# https://github.com/dayt0n/kairos
# https://github.com/Cryptiiiic/liboffsetfinder64

import logging
import struct
from functools import cached_property

from pyipatcher.errors import NotFoundError
from pyipatcher.patchfinder import insn

# from pyipatcher.patchfinder.patcher import ARM64Patcher
# from pyipatcher.patchfinder import insn
from pyipatcher.patchfinder.patcher import ARM64Patcher
from pyipatcher.types import iBootPatch, iBootStage, iBootVersion

logger = logging.getLogger(__name__)


def make_zeroes(n):
    zeroes = b''
    for i in range(n):
        zeroes += b'\x00'
    return zeroes


class iBootPatcher(ARM64Patcher):
    def __init__(self, data: bytes):
        super().__init__(data)
        logger.debug(f'iBoot version: {self.version.major}.{self.version.minor}')

        if self.version.major < 3406:  # iOS 10b2
            raise NotImplementedError('iBoot version too outdated')

    @cached_property
    def base(self) -> int:
        offset = 0x300 if self.version.major >= 6603 else 0x318  # iOS 14b1
        return struct.unpack('<Q', self.get_data(offset, 8))[0]

    @cached_property
    def chip_id(self) -> int:
        if self.stage != iBootStage.STAGE_2:
            raise ValueError('Provided iBoot is not stage 2')

        cpid_idx = self.find_str('platform-name') + 1
        cpid = ''
        while True:
            char = self.get_data(cpid_idx, 1).decode()

            # Only get the numbers from the SoC name
            if char.isdigit():
                cpid += char
            elif char == ' ':
                break

            cpid_idx += 1

        return int(cpid, 16)

    @cached_property
    def has_kernel_load(self) -> bool:
        try:
            self.find_str('__PAGEZERO')
            return True
        except NotFoundError:
            return False

    @cached_property
    def has_recovery_console(self) -> bool:
        try:
            self.find_str('Entering recovery mode, starting command prompt')
            return True
        except NotFoundError:
            return False

    @cached_property
    def stage(self) -> iBootStage:
        try:
            self.find_str('iBootStage1')
            return iBootStage.STAGE_1
        except NotFoundError:
            pass

        try:
            self.find_str('iBootStage2')
            return iBootStage.STAGE_2
        except NotFoundError:
            pass

        # TODO: Add an enum for unified iBoot on A10+, error out

    @cached_property
    def version(self) -> iBootVersion:
        vers_idx = self.find_str('iBoot-')
        vers_str = self.get_data(vers_idx + 6, 10).split(b'.')[:2]

        return iBootVersion(int(vers_str[0]), int(vers_str[1]))

    def iboot_memmem(self, needle):
        needle = (needle + self.base).to_bytes(8, byteorder='little')
        return self.find_str(needle)

    def apply_patch(self, patch: iBootPatch) -> None:
        match patch:
            case iBootPatch.DEBUG_ENABLED:
                self.patch_debug_enabled()
            case iBootPatch.UNLOCK_NVRAM:
                self.patch_unlock_nvram()
            case iBootPatch.REBOOT_TO_FSBOOT:
                self.patch_reboot_fsboot()
            case iBootPatch.SIG_CHECKS:
                pass
            case iBootPatch.FRESH_NONCE:
                self.patch_freshnonce()
            case _:
                raise ValueError('Invalid iBoot patch provided')

    def patch_debug_enabled(self):
        logger.info('Applying debug enabled patch')

        de_idx = self.find_str('debug-enabled')
        de_xref = self.xref(de_idx)

        for _ in range(2):
            de_xref = self.step(de_xref, 0x94000000, 0xFF000000)

        bl_insn = de_xref

        # movz x0, #0x1
        self.patch_data(bl_insn, b'\x20\x00\x80\xD2')

    def patch_unlock_nvram(self):
        if self.stage == iBootStage.STAGE_1:
            return #TODO: Error out

        logger.info('Applying unlock nvram patch')

        du_idx = self.find_str('debug-uarts')
        du_xref = self.iboot_memmem(du_idx)

        whitelist1 = du_xref
        while True:
            whitelist1 -= 8
            if self.find_ptr(whitelist1) == 0:
                break

        whitelist1 += 8
        blacklistfunc = self.xref(whitelist1)
        blacklistfunc_bof = self.bof(blacklistfunc)

        # movz x0, #0; ret
        self.patch_data(blacklistfunc_bof, b'\x00\x00\x80\xd2\xc0\x03_\xd6')

        whitelist2 = whitelist1
        while True:
            whitelist2 += 8
            if self.find_ptr(whitelist2) == 0:
                break

        whitelist2 += 8
        blacklistfunc2 = self.xref(whitelist2)
        blacklistfunc2_bof = self.bof(blacklistfunc2)

        # movz x0, #0; ret
        self.patch_data(blacklistfunc2_bof, b'\x00\x00\x80\xd2\xc0\x03_\xd6')


    def patch_freshnonce(self):
        cas_idx = self.find_str('com.apple.System.\0')
        cas_ref = self.xref(cas_idx)
        cas_bof = self.bof(cas_ref)

        # movz x0, #0; ret
        self.patch_data(cas_bof, b'\x00\x00\x80\xd2\xc0\x03_\xd6')

        # freshnonce patch, shoutout cryptic
        casbn_idx = self.find_str('com.apple.System.boot-nonce')
        casbn_ref = self.xref(casbn_idx)

        func1 = self.bof(casbn_ref)
        func1_blref = self.xrefcode(func1)

        func2 = self.bof(func1_blref)
        func2_blref = self.xrefcode(func2)

        branch_loc = func2_blref
        while (
            insn.supertype(insn.get_type(self.find_insn(func2_blref)))
            != 'sut_branch_imm'
        ):
            branch_loc -= 4

        # nop
        self.patch_data(branch_loc, b'\x1F\x20\x03\xD5')


    def get_cmd_handler_patch(self, command, ptr):
        cmd = bytes('\0' + command + '\0', 'utf-8')
        cmd_loc = self.memmem(cmd)
        if cmd_loc == -1:
            logger.error(f"Could not find command \'{command}\'")
            return
        cmd_loc += 1
        logger.debug(f'cmd_loc={hex(cmd_loc + self.base)}')
        cmd_ref = self.iboot_memmem(cmd_loc)
        if cmd_ref == -1:
            logger.error('Could not find command ref')
            return
        logger.debug(f'cmd_ref={hex(cmd_ref + self.base)}')
        self.apply_patch(cmd_ref + 8, ptr.to_bytes(8, byteorder='little'))

    def get_bootarg_patch(self, bootargs):
        _bootargs = bytes(bootargs, 'utf-8')
        default_ba_str_loc = self.memmem(b'rd=md0 nand-enable-reformat=1 -progress')
        if default_ba_str_loc == -1:
            logger.debug(
                'Could not find default bootargs string loc, searching for alternative bootargs string'
            )
            default_ba_str_loc = self.memmem(b'rd=md0 -progress -restore')
            if default_ba_str_loc == -1:
                logger.debug(
                    'Alternative bootargs string 1 could not be found, searching for another alternative bootargs string'
                )
                default_ba_str_loc = self.memmem(b'rd=md0')
                if default_ba_str_loc == -1:
                    logger.error('Could not find bootargs string')
                    return -1
        logger.debug(f'default_ba_str_loc={hex(default_ba_str_loc + self.base)}')
        _7429_0 = self.vers >= 7429 and self.minor_vers >= 0
        _6723_100 = (
            (self.vers == 6723 and self.minor_vers >= 100) or (self.vers > 6723)
        ) and (not _7429_0)
        if _6723_100 or _7429_0:
            adr1 = self.xref(default_ba_str_loc)
            if adr1 == 0:
                logger.error('Could not find adr1')
                return -1
            logger.debug(f'adr1={hex(adr1 + self.base)}')
            boff = self.step(adr1, len(self) - adr1, 0x14000000, 0xFC000000)
            bastackvarbranch = insn.imm(boff, self.get_insn(boff), 'b')
            if bastackvarbranch == -1:
                logger.error('Could not find bastackvarbranch')
                return -1
            logger.debug(f'bastackvarbranch={hex(bastackvarbranch)}')
            bloff = self.step(
                bastackvarbranch, len(self) - bastackvarbranch, 0x94000000, 0xFF000000
            )
            nopoff = self.step_back(bloff, bloff, 0xD503201F, 0xFFFFFFFF)
            default_ba_xref = bastackvar = nopoff
            if default_ba_xref == 0:
                logger.error('Could not find default_ba_xref')
                return -1
            logger.debug(f'bastackvar={hex(bastackvar + self.base)}')
        else:
            default_ba_xref = self.xref(default_ba_str_loc)
            if default_ba_xref == 0:
                logger.error('Could not find default_ba_xref')
                return -1
            logger.debug(f'default_ba_xref={hex(default_ba_xref + self.base)}')
        logger.debug('Relocating boot-args string')
        _270zeroes = make_zeroes(270)
        ba_loc1 = self.memmem(_270zeroes, default_ba_xref)
        if self.cpid == 8010 or (self.cpid in (8000, 8003) and (not _7429_0)):
            logger.debug('Finding another bootarg location')
            ba_loc1 = self.memmem(_270zeroes, ba_loc1 + 270)
        logger.debug(f'ba_loc1={hex(ba_loc1 + self.base)}')
        if ba_loc1 != -1:
            ba_loc = ba_loc1 + 0x11
            logger.debug(f'ba_loc={hex(ba_loc + self.base)}')
            while True:
                if self.get_insn(ba_loc) == 0:
                    ba_loc += 4
                    if self.get_insn(ba_loc) == 0:
                        ba_loc -= 4
                        break
                    else:
                        ba_loc -= 4
                ba_loc += 4
            logger.debug(
                f'Pointing default bootargs xref to {hex(ba_loc + self.base -1 )}'
            )
            default_ba_str_loc = ba_loc - 1
        else:
            cert_str_loc = self.memmem(b'Apple Inc.1')
            if cert_str_loc == -1:
                logger.error("Could not find 'Apple Inc.1' string")
                return -1
            logger.debug(f'cert_str_loc={hex(cert_str_loc + self.base)}')
            logger.debug(
                f'Poiting default bootargs xref to {hex(cert_str_loc + self.base)}'
            )
            default_ba_str_loc = cert_str_loc
        if _6723_100 or _7429_0:
            if insn.get_type(self.get_insn(default_ba_xref)) != 'nop':
                logger.error('Invalid instruction at default bootarg xref!')
                return -1
            adr2 = self.memmem(b' -restore')
            if adr2 == -1:
                logger.error("Could not find ' -restore' string")
                return -1
            adr2_xref = self.xref(adr2)
            if adr2_xref == 0:
                logger.error("Could not find ' -restore' string xref")
                return -1
            suboff = self.step_back(adr2_xref, adr2_xref, 0xD1000000, 0xFF000000)
            _reg = insn.rd(self.get_insn(suboff), 'sub')
        else:
            if insn.get_type(self.get_insn(default_ba_xref)) != 'adr':
                default_ba_xref -= 8
                if insn.get_type(self.get_insn(default_ba_xref)) != 'bl':
                    logger.error('Invalid instruction at default bootarg xref!')
                    return -1
                default_ba_xref += 4
                _reg = insn.rd(
                    self.get_insn(default_ba_xref),
                    insn.get_type(self.get_insn(default_ba_xref)),
                )
            else:
                if insn.get_type(self.get_insn(default_ba_xref)) != 'adr':
                    logger.error('Invalid instruction at default bootarg xref!')
                    return -1
                _reg = insn.rd(self.get_insn(default_ba_xref), 'adr')
        opcode = insn.new_insn_adr(default_ba_xref, default_ba_str_loc, _reg)
        self.apply_patch(default_ba_xref, opcode.to_bytes(4, byteorder='little'))
        logger.debug(f"Applying custom boot-args '{bootargs}'")
        self.apply_patch(default_ba_str_loc, _bootargs)
        if _6723_100 or _7429_0:
            xrefRD = 4
        else:
            xrefRD = insn.rd(
                self.get_insn(default_ba_xref),
                insn.get_type(self.get_insn(default_ba_xref)),
            )
            if xrefRD == 0:
                logger.error('Could not find xrefRD')
                return -1
        logger.debug(f'xrefRD={xrefRD}')
        if xrefRD == 4 or xrefRD > 9:
            return
        cseloff = self.step(
            default_ba_xref, len(self) - default_ba_xref, 0x1A800000, 0x7FE00C00
        )
        logger.debug(f'cseloff={hex(cseloff + self.base)}')
        if not (
            xrefRD
            in (
                insn.rn(self.get_insn(cseloff), 'csel'),
                insn.rm(self.get_insn(cseloff), 'csel'),
            )
        ):
            logger.error('Invalid default_ba_xref rd')
            return -1
        cselRD = insn.rd(self.get_insn(cseloff), 'csel')
        logger.debug(f'cselRD={cselRD}')
        opcode2 = insn.new_register_mov(cseloff, 0, cselRD, -1, xrefRD)
        logger.debug(
            f"({hex(cseloff + self.base)})patching: 'mov x{cselRD}, x{xrefRD}'"
        )
        self.apply_patch(cseloff, opcode2.to_bytes(4, byteorder='little'))
        cseloff -= 4
        while (
            insn.supertype(insn.get_type(self.get_insn(cseloff))) != 'sut_branch_imm'
        ) or (insn.get_type(self.get_insn(cseloff)) == 'bl'):
            cseloff -= 4
        logger.debug(f'branch_loc={hex(cseloff + self.base)}')
        cseloff = insn.imm(
            cseloff, self.get_insn(cseloff), insn.get_type(self.get_insn(cseloff))
        )
        if cseloff == -1:
            logger.error('Could not find branch_dst')
            return -1
        logger.debug(f'branch_dst={hex(cseloff + self.base)}')
        if insn.get_type(self.get_insn(cseloff)) != 'adr':
            adroff = self.step(cseloff, len(self) - cseloff, 0x10000000, 0x9F000000)
        else:
            adroff = cseloff
        opcode3 = insn.new_insn_adr(
            adroff,
            default_ba_str_loc,
            adrrd := insn.rd(
                self.get_insn(adroff), insn.get_type(self.get_insn(adroff))
            ),
        )
        logger.debug(
            f"({hex(adroff + self.base)})patching: 'adr x{adrrd}, {hex(default_ba_str_loc + self.base)}'"
        )
        self.apply_patch(adroff, opcode3.to_bytes(4, byteorder='little'))

    def patch_reboot_fsboot(self):
        rbt_str = self.find_str(b'reboot\x00')
        rbt_ref = self.iboot_memmem(rbt_str)

        fsbt_str = self.find_str(b'fsboot\x00')
        self.patch_data(rbt_ref, fsbt_str.to_bytes(4, byteorder='little'))
        fsbt_ref = self.iboot_memmem(fsbt_str)

        fsbt_func = self.find_ptr(fsbt_ref + 8)
        self.patch_data(
            rbt_ref + 8, (fsbt_func - self.base).to_bytes(4, byteorder='little')
        )

    def get_sigcheck_patch(self):
        img4decodemanifestexists = 0
        ios14 = False
        if ios14 := (self.vers >= 6671):
            if 8419 > self.vers >= 7459:
                img4decodemanifestexists = self.memmem(
                    b'\xE8\x03\x00\xAA\xC0\x00\x80\x52\x28\x01\x00\xB4'
                )
            else:
                img4decodemanifestexists = self.memmem(
                    b'\xE8\x03\x00\xAA\xC0\x00\x80\x52\xE8\x00\x00\xB4'
                )
        else:
            if (self.vers == 5540 and self.minor_vers >= 100) or self.vers > 5540:
                img4decodemanifestexists = self.memmem(
                    b'\xE8\x03\x00\xAA\xC0\x00\x80\x52\xE8\x00\x00\xB4'
                )
            elif (self.vers == 5540 and self.minor_vers <= 100) or (
                3406 <= self.vers <= 5540
            ):
                img4decodemanifestexists = self.memmem(
                    b'\xE8\x03\x00\xAA\xE0\x07\x1F\x32\xE8\x00\x00\xB4'
                )
            else:
                logger.error(
                    f'Unsupported iBoot (iBoot-{self.vers}.{self.minor_vers}), only iOS 10 or later iBoot is supported'
                )
                return -1
        if img4decodemanifestexists == -1:
            logger.error(f'Could not find img4decodemanifestexists')
            return -1
        logger.debug(
            f'img4decodemanifestexists={hex(img4decodemanifestexists + self.base)}'
        )
        img4decodemanifestexists_ref = self.xrefcode(img4decodemanifestexists)
        if img4decodemanifestexists_ref == 0:
            logger.error('Could not find img4decodemanifestexists_ref')
            return -1
        logger.debug(
            f'img4decodemanifestexists_ref={hex(img4decodemanifestexists_ref + self.base)}'
        )
        adroff = self.step(
            img4decodemanifestexists_ref,
            len(self) - img4decodemanifestexists_ref,
            0x10000000,
            0x9F000000,
        )
        if insn.rd(self.get_insn(adroff), 'adr') != 2:
            adroff = self.step(
                img4decodemanifestexists_ref, len(self) - adroff, 0x10000000, 0x9F000000
            )
            if insn.rd(self.get_insn(adroff), 'adr') != 2:
                logger.error('Could not find adroff')
                return -1
        img4interposercallback_ptr = insn.imm(adroff, self.get_insn(adroff), 'adr')
        if img4interposercallback_ptr == -1:
            logger.debug(f'Could not find img4interposercallback_ptr')
            return -1
        logger.debug(
            f'img4interposercallback_ptr={hex(int(img4interposercallback_ptr) + self.base)}'
        )
        img4interposercallback = self.get_ptr_loc(img4interposercallback_ptr)
        real_img4interposercallback = img4interposercallback - self.base
        logger.debug(f'img4interposercallback={hex(img4interposercallback)}')
        real_img4interposercallback = self.step(
            real_img4interposercallback,
            len(self) - real_img4interposercallback,
            0xD65F03C0,
            0xFFFFFFFF,
        )
        img4interposercallback_ret = real_img4interposercallback
        if img4interposercallback_ret == 0:
            logger.error('Could not find img4interposercallback_ret')
            return -1
        logger.debug(
            f'img4interposercallback_ret={hex(img4interposercallback_ret + self.base)}'
        )
        if not ios14:
            self.apply_patch(
                img4interposercallback_ret, b'\x00\x00\x80\xD2\xC0\x03\x5F\xD6'
            )
            real_img4interposercallback += 4
            img4interposercallback_ret2 = self.step(
                real_img4interposercallback + 4,
                len(self) - real_img4interposercallback,
                0xD65F03C0,
                0xFFFFFFFF,
            )
            logger.debug(
                f'img4interposercallback_ret2={hex(img4interposercallback_ret2 + self.base)}'
            )
            self.apply_patch(img4interposercallback_ret2 - 4, b'\x00\x00\x80\xD2')
        else:
            if (
                self.step_back(real_img4interposercallback, 4, 0x91000000, 0xFF000000)
                != 0
            ):  # an add
                real_img4interposercallback = self.step_back(
                    real_img4interposercallback - 8,
                    real_img4interposercallback,
                    0xA94000F0,
                    0xFFF000F0,
                    reversed=True,
                )  # sill an ldp
                if insn.get_type(self.get_insn(real_img4interposercallback)) != 'mov':
                    real_img4interposercallback = self.step_back(
                        real_img4interposercallback,
                        real_img4interposercallback,
                        0x1F2003D5,
                        0xFFFFFFFF,
                    )
                img4interposercallback_mov = real_img4interposercallback
                if img4interposercallback_mov == 0:
                    logger.error('Could not find img4interposercallback_mov')
                    return -1
                logger.debug(
                    f'img4interposercallback_mov={hex(img4interposercallback_mov + self.base)}'
                )
                self.apply_patch(img4interposercallback_mov, b'\x00\x00\x80\xD2')
                retoff = self.step(
                    real_img4interposercallback,
                    len(self) - real_img4interposercallback,
                    0xD65F03C0,
                    0xFFFFFFFF,
                )
                img4interposercallback_ret2 = self.step(
                    retoff + 4, len(self) - retoff, 0xD65F03C0, 0xFFFFFFFF
                )
                if img4interposercallback_ret2 == 0:
                    logger.error('Could not find img4interposercallback_ret2')
                    return -1
                logger.debug(
                    f'img4interposercallback_ret2={hex(img4interposercallback_ret2 + self.base)}'
                )
                self.apply_patch(img4interposercallback_ret2 - 4, b'\x00\x00\x80\xD2')
            else:
                self.apply_patch(img4interposercallback_ret - 4, b'\x00\x00\x80\xD2')
                boff = self.step_back(
                    img4interposercallback_ret,
                    img4interposercallback_ret,
                    0x14000000,
                    0xFC000000,
                )
                if self.step_back(boff, 4, 0xA94000F0, 0xFFF000F0) == 0:
                    boff = self.step_back(boff - 4, boff - 4, 0x14000000, 0xFC000000)
                    if self.step_back(boff, 4, 0xA94000F0, 0xFFF000F0) == 0:
                        logger.error(
                            'img4interposercallback couldn\'t find branch for ret2'
                        )
                        return -1
                    else:
                        img4interposercallback_mov_x20 = self.step_back(
                            boff, boff, 0xAA0003E0, 0xFFE0FFE0, dbg=0
                        )
                        logger.debug(
                            f'img4interposercallback_mov_x20={hex(img4interposercallback_mov_x20 + self.base)}'
                        )
                        self.apply_patch(
                            img4interposercallback_mov_x20, b'\x00\x00\x80\xD2'
                        )

    @property
    def output(self):
        return bytes(self._buf)
