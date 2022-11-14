# -*- coding: utf-8 -*-
"""This is the summary line.

This is the further elaboration of the docstring. Within this section,
you can elaborate further on details as appropriate for the situation.
Notice that the summary and the elaboration is separated by a blank new
line.
"""

import dns.resolver


def get_records(host: str, record_type: str) -> list[str]:
    """Define a summary.

    This is the extended summary from the template and needs to be replaced.

    Arguments:
        host (str) -- _description_
        record_type (str) -- _description_

    Returns:
        list[str] -- _description_
    """
    try:
        resolver_results: list = dns.resolver.resolve(host, record_type)
        results: list = [val.to_text() for val in resolver_results]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        results = []

    return results
