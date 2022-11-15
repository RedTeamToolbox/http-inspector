# -*- coding: utf-8 -*-
"""This is the summary line.

This is the further elaboration of the docstring. Within this section,
you can elaborate further on details as appropriate for the situation.
Notice that the summary and the elaboration is separated by a blank new
line.
"""
import os
import shutil

import shlex
import subprocess  # nosec: B404

from typing import Any

from defusedxml import ElementTree

from .globals import global_configuration, global_results
from .notify import warn


def get_cipher_suite() -> None:
    """Define a summary.

    This is the extended summary from the template and needs to be replaced.
    """
    which_nmap: str | None = shutil.which("nmap")
    if which_nmap is None:
        warn("nmap is not installed - cipher suite will be empty")
        global_results.cipher_suite = []
        return

    fname: str = _ssl_cipher_scan(global_configuration.url.hostname, global_configuration.url.port, os.getcwd())
    ciphers: dict = decode_xml(fname)
    os.remove(fname)
    global_results.cipher_suite = ciphers


def _ssl_cipher_scan(target_ip, target_ports, xml_path) -> str:
    """Define a summary.

    This is the extended summary from the template and needs to be replaced.

    Arguments:
        target_ip (_type_) -- _description_
        target_ports (_type_) -- _description_
        xml_path (_type_) -- _description_

    Returns:
        str -- _description_
    """
    out_xml: str = os.path.join(xml_path, f'{target_ip}_ssl_ciphers.xml')
    nmap_cmd: str = f"nmap {target_ip} -p {target_ports} -n -Pn --script ssl-enum-ciphers -T4 -vv -oX {out_xml}"
    sub_args: list[str] = shlex.split(nmap_cmd)

    with subprocess.Popen(sub_args, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as sub:  # nosec: B603
        sub.communicate()
    return out_xml


def decode_xml(fname: str) -> dict:
    """Define a summary.

    This is the extended summary from the template and needs to be replaced.

    Arguments:
        fname (str) -- _description_

    Returns:
        dict -- _description_
    """
    # Cipher Risk Lists
    ciphers_list: dict = {}

    xml_tree: ElementTree = ElementTree.parse(fname)
    xml_root: Any = xml_tree.getroot()

    script_element: Any = xml_root.find('.//script')
    if not script_element:
        return ciphers_list

    script_element = script_element.findall('table')
    ciphers_list = _process_tls_protocols(script_element)

    ciphers_list = dict(sorted(ciphers_list.items(), reverse=True))

    topic: Any = xml_root.find(".//*[@key='least strength']")
    if topic is not None:
        ciphers_list["least strength"] = topic.text

    return ciphers_list


def _process_tls_protocols(tables: Any) -> dict:
    """Define a summary.

    This is the extended summary from the template and needs to be replaced.

    Arguments:
        tables (Any) -- _description_

    Returns:
        dict -- _description_
    """
    ciphers_list: dict = {}

    for tls_protocol in tables:
        protocol_name: Any = tls_protocol.attrib.get('key')
        ciphers_list[protocol_name] = []

        # Cycle through TLS protocol
        for protocol in tls_protocol:
            if protocol.attrib.get('key') == 'cipher preference':
                ciphers_list[protocol_name].append({"cipher preference": protocol.text})

            if protocol.attrib.get('key') == 'compressors':
                ciphers_list[protocol_name].append({"compressors": _process_compressors(protocol)})

            if protocol.attrib.get('key') == 'warnings':
                ciphers_list[protocol_name].append(_process_warnings(protocol))

            if protocol.attrib.get('key') == 'ciphers':
                ciphers_list[protocol_name].append(_process_ciphers_table(protocol))

    return ciphers_list


def _process_compressors(protocol: Any) -> dict[str, list]:
    """Define a summary.

    This is the extended summary from the template and needs to be replaced.

    Arguments:
        protocol (Any) -- _description_

    Returns:
        dict[str, list] -- _description_
    """
    local_compressors: list = []

    for entry in protocol:
        local_compressors.append(entry.text)

    return local_compressors


def _process_warnings(protocol: Any) -> dict[str, list]:
    """Define a summary.

    This is the extended summary from the template and needs to be replaced.

    Arguments:
        protocol (Any) -- _description_

    Returns:
        dict[str, list] -- _description_
    """
    local_warnings: list = []

    for entry in protocol:
        local_warnings.append(entry.text)

    return {"warnings": local_warnings}


def _process_ciphers_table(protocol: Any) -> dict:
    """Define a summary.

    This is the extended summary from the template and needs to be replaced.

    Arguments:
        protocol (Any) -- _description_

    Returns:
        list -- _description_
    """
    local_ciphers = []
    name: str = "unknown"
    grade: str = "unknown"
    kex_info: str = "unknown"

    for entries in protocol:
        for entry in entries:
            if entry.attrib.get('key') == 'name':
                name = entry.text
            if entry.attrib.get('key') == 'strength':
                grade = entry.text
            if entry.attrib.get('key') == 'kex_info':
                kex_info = entry.text
        local_ciphers.append({'tex_info': kex_info, 'name': name, 'grade': grade})

    return {"ciphers": local_ciphers}
