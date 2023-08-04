import click
from .cli.ramdiskpatcher import ramdiskpatcher
from .cli.kernelpatcher import kernelpatcher
from .cli.ibootpatcher import ibootpatcher
import sys
import coloredlogs
import logging

coloredlogs.install(level=logging.INFO)
logger = logging.getLogger(__name__)

@click.group()
def cli():
    sys.tracebacklimit = 0


cli.context_settings = dict(help_option_names=['-h', '--help'])

cli.add_command(ramdiskpatcher)
cli.add_command(kernelpatcher)
cli.add_command(ibootpatcher)

if __name__ == '__main__':
    cli()
