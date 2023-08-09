import logging

from .patcher import ARM64Patcher, arm64_branch_instruction

logger = logging.getLogger(__name__)

verbose = 0


class ASRPatcher(ARM64Patcher):
    def get_asr_sigcheck_patch(self):
        failed = self.memmem(b'Image failed signature verification')
        if failed == -1:
            logger.error('Could not find \'Image failed signature verification\'')
            return -1
        logger.debug(f'\'Image failed signature verification\' at {hex(failed)}')
        passed = self.memmem(b'Image passed signature verification')
        if passed == -1:
            logger.error('Could not find \'Image passed signature verification\'')
            return -1
        logger.debug(f'\'Image failed signature verification\' at {hex(passed)}')
        ref_failed = self.xref(failed)
        ref_passed = self.xref(passed)
        if ref_failed == 0:
            logger.error('Could not find \'Image failed signature verification\' ref')
            return -1
        if ref_passed == 0:
            logger.error('Could not find \'Image passed signature verification\' ref')
            return -1
        our_branch = arm64_branch_instruction(ref_failed, ref_passed)
        self.apply_patch(ref_failed, our_branch.to_bytes(4, byteorder='little'))
