#!/usr/bin/env python
# -*- coding: utf-8 -*-
# pylint: disable=invalid-name

"""This is the summary line.

This is the further elaboration of the docstring. Within this section,
you can elaborate further on details as appropriate for the situation.
Notice that the summary and the elaboration is separated by a blank new
line.
"""
import argparse
import sys

from modules.cli import process_command_line_arguments
from modules.core import run_inspector
from modules.exceptions import InvalidParameters, InvalidTargetURL
from modules.notify import error, info


def main() -> None:
    """Control the main flow of the program.

    It does stuff.
    """
    args: argparse.Namespace = process_command_line_arguments()
    run_inspector(args)
    sys.exit(0)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        info("\n[*] Exiting Program\n")
    except InvalidParameters as e:
        error(str(e))
    except InvalidTargetURL as e:
        error(str(e))
