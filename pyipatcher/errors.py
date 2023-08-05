from typing import NoReturn


class _PyiPatcherError(Exception):
    pass


class InvalidDataError(_PyiPatcherError, ValueError):
    def __init__(self, data_type: str, reason: str) -> NoReturn:
        if not isinstance(real, (float, int)) and len(real) > 15:
            real = f'<{type(real).__name__} with len of {len(real)}>'

        super().__init__(f'{data_type} data is invalid: {reason}')
