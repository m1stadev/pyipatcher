from typing import Any, NoReturn, Optional


class _PyiPatcherError(Exception):
    pass


class InvalidDataError(_PyiPatcherError, ValueError):
    def __init__(self, data_type: str, reason: str) -> NoReturn:
        super().__init__(f'{data_type} data is invalid: {reason}')


class NotFoundError(_PyiPatcherError, ValueError):
    def __init__(self, data_type: str, data: Optional[Any] = None) -> NoReturn:
        if data is None:
            error = f'{data_type} was not found in data'
        if not isinstance(data, (float, int, str)) and len(data) > 15:
            error = f'{data_type} "<{type(data).__name__} with len of {len(data)}>" was not found in data'

        super().__init__(error)
