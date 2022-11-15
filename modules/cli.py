# -*- coding: utf-8 -*-
"""This is the summary line.

This is the further elaboration of the docstring. Within this section,
you can elaborate further on details as appropriate for the situation.
Notice that the summary and the elaboration is separated by a blank new
line.
"""
import argparse
import sys


def _add_flags_to_parser(parser: argparse.ArgumentParser) -> None:
    """Define a summary.

    This is the extended summary from the template and needs to be replaced.

    Arguments:
        parser (argparse.ArgumentParser) -- _description_
    """
    flags: argparse._ArgumentGroup = parser.add_argument_group(
        title="optional flags",
        description="Description"
    )
    flags.add_argument("-h", "--help",
                       action="help",
                       help="show this help message and exit")
    flags.add_argument("-d", "--debug",
                       action="store_true", default=False,
                       help="Very noisy")
    flags.add_argument("-v", "--verbose",
                       action="store_true", default=False,
                       help="Verbose output - show scan results as they come in")
    flags.add_argument("-4", "--ipv4-only",
                       action="store_true", default=False,
                       help="Scan IPv4 addresses only")
    flags.add_argument("-6", "--ipv6-only",
                       action="store_true", default=False,
                       help="Scan IPv6 addresses only")
    flags.add_argument("-A", "--all-results",
                       action="store_true", default=False,
                       help="Show or save all results (default is to list open ports only)")
    flags.add_argument("-s", "--shuffle",
                       action="store_true", default=False,
                       help="Randomise the port scanning order")


def _add_required_parameters(parser: argparse.ArgumentParser) -> None:
    """Define a summary.

    This is the extended summary from the template and needs to be replaced.

    Arguments:
        parser (argparse.ArgumentParser) -- _description_
    """
    required: argparse._ArgumentGroup = parser.add_argument_group(
        title="required arguments",
        description="stuff"
    )
    required.add_argument("-u", "--url",
                          type=str,
                          help="The url you want to check")


def _add_optional_parameters(parser: argparse.ArgumentParser) -> None:
    """Define a summary.

    This is the extended summary from the template and needs to be replaced.

    Arguments:
        parser (argparse.ArgumentParser) -- _description_

    Returns:
        _type_ -- _description_
    """
    required: argparse._ArgumentGroup = parser.add_argument_group(
        title="optional arguments",
        description="stuff"
    )
    required.add_argument("-m", "--max-redirects",
                          type=int, default=2,
                          help="Max redirects, set 0 to disable")
    required.add_argument("-n", "--no-check-certificate",
                          action="store_true", default=False,
                          help="Do not verify TLS chain")
    required.add_argument("-t", "--timeout",
                          type=int, default=5,
                          help="Timeout to use when making web requests")

    return parser


def _setup_arg_parser() -> argparse.ArgumentParser:
    """Define a summary.

    This is the extended summary from the template and needs to be replaced.

    Returns:
        argparse.ArgumentParser -- _description_
    """
    parser: argparse.ArgumentParser = argparse.ArgumentParser(
        add_help=False,
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        description="Check for open port(s) on target host(s)",
        epilog="For detailed documentation please refer to: https://github.com/OffSecToolbox/http-inspector",
    )
    _add_flags_to_parser(parser)
    _add_required_parameters(parser)
    _add_optional_parameters(parser)

    return parser


def process_command_line_arguments() -> argparse.Namespace:
    """Define a summary.

    This is the extended summary from the template and needs to be replaced.

    Returns:
        argparse.Namespace -- _description_
    """
    parser: argparse.ArgumentParser = _setup_arg_parser()
    args: argparse.Namespace = parser.parse_args()

    if args.url is None:
        parser.print_help()
        sys.exit(0)

    return args
