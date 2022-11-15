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
from .globals import global_configuration, global_results
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
    global_configuration.verbose = args.verbose
    global_configuration.debug = args.debug
    global_configuration.ipv4_only = args.ipv4_only
    global_configuration.ipv6_only = args.ipv6_only
    global_configuration.all_results = args.all_results
    global_configuration.shuffle = args.shuffle
    global_configuration.max_redirects = args.max_redirects
    global_configuration.allow_redirects = bool(args.max_redirects)
    global_configuration.verify_ssl = not bool(args.no_check_certificate)
    global_configuration.timeout = args.timeout

    # Parse the supplied url
    global_configuration.origin = url_parser(args.url)

    # Check the url host actually exists
    try:
        socket.gethostbyname(global_configuration.origin.hostname)
    except socket.gaierror as err:
        raise InvalidTargetURL("Unable to lookup address for URL") from err

    # Follow any redirects
    global_configuration.redirect_history = follow_redirects(global_configuration.origin.full_url)

    # Parse the final url
    global_configuration.url = url_parser(global_configuration.redirect_history[-1]['url'])

    # This should never fail as we have followed redirects to get here
    try:
        socket.gethostbyname(global_configuration.url.hostname)
    except socket.gaierror as err:
        raise InvalidTargetURL("Unable to lookup address for URL") from err

    # Keep the details in json
    global_results.url = global_configuration.url
