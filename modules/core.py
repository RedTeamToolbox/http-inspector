# -*- coding: utf-8 -*-
"""This is the summary line.

This is the further elaboration of the docstring. Within this section,
you can elaborate further on details as appropriate for the situation.
Notice that the summary and the elaboration is separated by a blank new
line.
"""
import argparse
import json

from .certificates import process_certificates
from .ciphers import process_cipher_suite
from .config import create_configuration_from_arguments
from .cli import process_command_line_arguments
from .globals import global_results
from .headers import process_headers
from .portscan import process_port_scan


def core_run() -> None:
    """Define a summary.

    This is the extended summary from the template and needs to be replaced.

    Arguments:
        args (argparse.Namespace) -- _description_
    """
    args: argparse.Namespace = process_command_line_arguments()

    create_configuration_from_arguments(args)

    process_headers()
    process_certificates()
    process_cipher_suite()
    process_port_scan()

    print(json.dumps(vars(global_results), default=str, indent=4))
