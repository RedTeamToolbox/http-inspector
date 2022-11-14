# -*- coding: utf-8 -*-
"""This is the summary line.

This is the further elaboration of the docstring. Within this section,
you can elaborate further on details as appropriate for the situation.
Notice that the summary and the elaboration is separated by a blank new
line.
"""
import argparse
import socket

from .exceptions import InvalidTargetURL
from .globals import configuration, results
from .urltools import follow_redirects, url_parser


def create_configuration_from_arguments(args: argparse.Namespace) -> None:
    """Define a summary.

    This is the extended summary from the template and needs to be replaced.

    Arguments:
        args (argparse.Namespace) -- _description_

    Raises:
        InvalidTargetURL: _description_
        InvalidTargetURL: _description_
    """
    configuration.verbose = args.verbose
    configuration.debug = args.debug
    configuration.ipv4_only = args.ipv4_only
    configuration.ipv6_only = args.ipv6_only
    configuration.all_results = args.all_results
    configuration.max_redirects = args.max_redirects
    configuration.allow_redirects = bool(args.max_redirects)
    configuration.verify_ssl = not bool(args.no_check_certificate)
    configuration.timeout = args.timeout

    # Parse the supplied url
    configuration.origin = url_parser(args.url)

    # Check the url host actually exists
    try:
        socket.gethostbyname(configuration.origin.hostname)
    except socket.gaierror as err:
        raise InvalidTargetURL("Unable to lookup address for URL") from err

    # Follow any redirects
    configuration.redirect_history = follow_redirects(configuration.origin.full_url)

    # Parse the final url
    configuration.url = url_parser(configuration.redirect_history[-1]['url'])

    # This should never fail as we have followed redirects to get here
    try:
        socket.gethostbyname(configuration.url.hostname)
    except socket.gaierror as err:
        raise InvalidTargetURL("Unable to lookup address for URL") from err

    results.url = configuration.url
