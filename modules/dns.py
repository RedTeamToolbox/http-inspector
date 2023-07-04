# -*- coding: utf-8 -*-
"""This is the summary line.

This is the further elaboration of the docstring. Within this section,
you can elaborate further on details as appropriate for the situation.
Notice that the summary and the elaboration is separated by a blank new
line.
"""
import ipaddress

from types import SimpleNamespace
from typing import Any

import dns.resolver
import dns.reversename

from .globals import global_configuration


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
        if record_type == 'PTR':
            rev_name = dns.reversename.from_address(host)
            resolver_results: list = dns.resolver.query(rev_name,"PTR")
        else:
            resolver_results: list = dns.resolver.resolve(host, record_type)

        results: list = [val.to_text() for val in resolver_results]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.DNSException) as e:
        results = []

    return results


def get_all_ips_for_host(target: str) -> SimpleNamespace:
    """Define a summary.

    This is the extended summary from the template and needs to be replaced.

    Arguments:
        host (str) -- _description_

    Returns:
        SimpleNamespace -- _description_
    """
    all_ips: SimpleNamespace = SimpleNamespace()
    ptr_records: dict = {}

    if _is_ip_address(target) is False:
        if global_configuration.ipv4_only is True:
            all_ips.addresses = sorted(get_records(target, "A"))
        elif global_configuration.ipv6_only is True:
            all_ips.addresses = sorted(get_records(target, "AAAA"))
        else:
            all_ips.addresses = sorted(get_records(target, "A")) + sorted(get_records(target, "AAAA"))
    else:
        all_ips.addresses = [target]

    all_ips.address_count = len(all_ips.addresses)
    for ipaddr in all_ips.addresses:
        ptr_records[ipaddr] = get_records(ipaddr, 'PTR')
    all_ips.ptr_records = ptr_records

    return all_ips


def _is_ip_address(target: str) -> Any:
    """Define a summary.

    This is the extended summary from the template and needs to be replaced.

    Arguments:
        target (str) -- _description_

    Returns:
        Any -- _description_
    """
    try:
        ip_address: ipaddress.IPv4Address | ipaddress.IPv6Address = ipaddress.ip_address(target)
        status: bool = bool(isinstance(ip_address, (ipaddress.IPv4Address, ipaddress.IPv6Address)))
    except ValueError:
        status = False
    return status
