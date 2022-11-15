# -*- coding: utf-8 -*-
"""This is the summary line.

This is the further elaboration of the docstring. Within this section,
you can elaborate further on details as appropriate for the situation.
Notice that the summary and the elaboration is separated by a blank new
line.
"""
import argparse
import json

from .certificates import get_certificates, process_certificates
from .ciphers import get_cipher_suite
from .config import create_configuration_from_arguments
from .globals import results
from .headers import fetch_headers
from .portscan import port_scan


def run_inspector(args: argparse.Namespace) -> None:
    """Define a summary.

    This is the extended summary from the template and needs to be replaced.

    Arguments:
        args (argparse.Namespace) -- _description_
    """
    # Process the command line arguments and create the global configuration
    create_configuration_from_arguments(args)

    # From here we should have a valid URL to work with
    fetch_headers()

    certificates: list = get_certificates()
    process_certificates(certificates)

    get_cipher_suite()

    port_scan()

    print(json.dumps(results.cipher_suite, default=str, indent=4))
    print(json.dumps(results.port_scan, default=str, indent=4))
