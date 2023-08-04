from pyipatcher import ipatcher, logger, patchfinder

try:
    from importlib.metadata import version
except ModuleNotFoundError:
    from importlib_metadata import version

__version__ = version(__package__)
