# -*- coding: utf-8 -*-
"""This is the summary line.

This is the further elaboration of the docstring. Within this section,
you can elaborate further on details as appropriate for the situation.
Notice that the summary and the elaboration is separated by a blank new
line.
"""
import argparse

from types import SimpleNamespace

from .dns import get_all_ips_for_host
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

    # TODO : Move this all to a verify url function in urltools.py
    # Parse the supplied url
    global_configuration.origin = url_parser(args.url)

    # Check the url host actually exists
    all_ips: SimpleNamespace = get_all_ips_for_host(global_configuration.origin.hostname)
    if not all_ips.address_count:
        raise InvalidTargetURL("Unable to lookup address for URL")

    # Follow any redirects
    global_configuration.redirect_history = follow_redirects(global_configuration.origin.full_url)

    # Parse the final url
    global_configuration.url = url_parser(global_configuration.redirect_history[-1]['url'])

    # This should never fail as we have followed redirects to get here
    all_ips = get_all_ips_for_host(global_configuration.url.hostname)
    if not all_ips.address_count:
        raise InvalidTargetURL("Unable to lookup address for URL")

    global_configuration.ips = all_ips
    print(all_ips)

    # Keep the details in json
    global_results.url = global_configuration.url
    global_results.ips = global_configuration.ips
