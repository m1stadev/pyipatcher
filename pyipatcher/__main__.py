import logging
import sys

import click
import coloredlogs

from pyipatcher.cli import ibootpatcher, kernelpatcher, ramdiskpatcher

coloredlogs.install(level=logging.INFO)
logger = logging.getLogger(__name__)


@click.group()
def cli():
    sys.tracebacklimit = 0


cli.context_settings = dict(help_option_names=['-h', '--help'])

cli = click.CommandCollection(
    ramdiskpatcher.ramdiskpatcher,
    kernelpatcher.kernelpatcher,
    ibootpatcher.ibootpatcher,
)


if __name__ == '__main__':
    cli()
