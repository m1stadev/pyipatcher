import logging
import struct

from pyipatcher.patchfinder.patcher import ARM64Patcher, arm64_branch_instruction

logger = logging.getLogger(__name__)


class rextpatchfinder(ARM64Patcher):
    def get_skip_sealing_patch(self):
        skip_sealing = self.find_str(b'Skipping sealing system volume')
        if skip_sealing == -1:
            logger.error('Could not find skip_sealing str')
            return
        logger.debug(f'skip_sealing={hex(skip_sealing)}')
        skip_sealing_ref = self.xref(skip_sealing)
        if skip_sealing_ref == 0:
            logger.error('Could not find skip_sealing ref')
            return
        logger.debug(f'skip_sealing_ref={hex(skip_sealing_ref)}')
        skip_sealing_ref_ref = self.cbz_ref(skip_sealing_ref)
        # iOS 15
        if skip_sealing_ref_ref == 0:
            skip_sealing_ref -= 4
            skip_sealing_ref_ref = self.cbz_ref(skip_sealing_ref)
        if skip_sealing_ref_ref == 0:
            logger.error('Could not find skip_sealing_ref ref')
            return
        logger.debug(f'skip_sealing_ref_ref={hex(skip_sealing_ref_ref)}')
        our_branch = arm64_branch_instruction(skip_sealing_ref_ref, skip_sealing_ref)
        self.apply_patch(
            skip_sealing_ref_ref, our_branch.to_bytes(4, byteorder='little')
        )