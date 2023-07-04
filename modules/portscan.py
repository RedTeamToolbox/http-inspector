# -*- coding: utf-8 -*-

"""This is the summary line.

This is the further elaboration of the docstring. Within this section,
you can elaborate further on details as appropriate for the situation.
Notice that the summary and the elaboration is separated by a blank new
line.
"""
import ipaddress
import itertools
import multiprocessing
import socket

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from .constants import PORTSCAN_PORTS
from .globals import global_configuration, global_results
from .ordering import multikeysort, shuffled


def process_port_scan() -> None:
    """Define a summary.

    This is the extended summary from the template and needs to be replaced.
    """
    scan_results: list[dict] = []

    all_ports_and_ips: list[tuple[str, int]] = list(itertools.product(global_configuration.ips.addresses, PORTSCAN_PORTS))
    if global_configuration.shuffle is True:
        all_ports_and_ips = shuffled(all_ports_and_ips)

    with ThreadPoolExecutor(max_workers=_calculate_default_threads()) as executor:
        futures: list = [executor.submit(_scan_target_port, target[0], target[1], 3) for target in all_ports_and_ips]

        for future in as_completed(futures):
            thread_results: dict = future.result()
            if thread_results:
                scan_results.append(thread_results)

    global_results.port_scan = _sort_and_clean(scan_results)


def _sort_and_clean(scan_results: list) -> list:
    """Define a summary.

    This is the extended summary from the template and needs to be replaced.

    Arguments:
        scan_results (list) -- _description_

    Returns:
        list -- _description_
    """
    if global_configuration.all_results is False:
        scan_results: list[dict] = [i for i in scan_results if i['status'] is True]

    scan_results = multikeysort(scan_results, ['target', 'ipnum', 'port'])

    for item in scan_results:
        del item["ipnum"]

    return scan_results


def _calculate_default_threads() -> int:
    """Define a summary.

    This is the extended summary from the template and needs to be replaced.

    Returns:
        int -- _description_
    """
    default_threads: int = multiprocessing.cpu_count() * 5

    if default_threads > len(PORTSCAN_PORTS):
        default_threads = len(PORTSCAN_PORTS)

    return default_threads


def _scan_target_port(target: str, port: int, socket_timeout: int = 3) -> dict[str, Any]:
    """Define a summary.

    This is the extended summary from the template and needs to be replaced.

    Arguments:
        target (str) -- _description_
        port (int) -- _description_

    Keyword Arguments:
        socket_timeout (int) -- _description_ (default: 3)

    Returns:
        dict[str, Any] -- _description_
    """
    status: bool = False
    af_type: int = socket.AF_INET

    if isinstance(ipaddress.ip_address(target), ipaddress.IPv6Address) is True:
        af_type = socket.AF_INET6

    with socket.socket(af_type, socket.SOCK_STREAM) as sock:
        sock.settimeout(socket_timeout)
        try:
            sock.connect((target, port))
            status = True
            sock.shutdown(0)
            sock.close()
        except socket.timeout:
            status = False
        except socket.error:
            status = False

    status_string: str = "Open" if status is True else "Closed"

    return {
        "target": target,
        "port": port,
        "status": status,
        "status_string": status_string,
        "ipnum": int(ipaddress.ip_address(target))
    }
