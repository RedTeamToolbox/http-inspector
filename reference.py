#!/usr/bin/env python
# -*- coding: utf-8 -*-
# pylint: disable=invalid-name

"""This is the summary line.

This is the further elaboration of the docstring. Within this section,
you can elaborate further on details as appropriate for the situation.
Notice that the summary and the elaboration is separated by a blank new
line.
"""

import subprocess  # nosec: B404
import shlex
import os

import argparse
import ipaddress
import itertools
import json
import multiprocessing
import re
import socket
import sys
import warnings

from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from ipaddress import IPv4Address, IPv6Address
from re import Match
from types import SimpleNamespace
from typing import Any, Callable, Tuple
from urllib.parse import ParseResult, urlparse

import dns.resolver
import requests

from defusedxml import ElementTree
from ocspchecker import ocspchecker
from OpenSSL import SSL, crypto
from requests import Response, Session

from modules.globals import PORTSCAN_PORTS, REQUEST_HEADERS, DEFAULT_URL_SCHEME, EVAL_OK, EVAL_WARN

warnings.filterwarnings("ignore")


def decode_xml(fname: str) -> dict:
    """Docs."""
    # Cipher Risk Lists
    ciphers_list: dict = {}

    xml_tree = ElementTree.parse(fname)
    xml_root = xml_tree.getroot()

    script_element = xml_root.find('.//script')
    if script_element:
        script_element = script_element.findall('table')

        for tls_protocol in script_element:
            protocol_name = tls_protocol.attrib.get('key')
            ciphers_list[protocol_name] = []

            # Cycle through TLS protocol
            for protocol in tls_protocol:
                if protocol.attrib.get('key') == 'cipher preference':
                    ciphers_list[protocol_name].append({"cipher preference": protocol.text})

                if protocol.attrib.get('key') == 'compressors':
                    local_compressors = []
                    for entry in protocol:
                        local_compressors.append(entry.text)
                    ciphers_list[protocol_name].append({"compressors": local_compressors})

                if protocol.attrib.get('key') == 'warnings':
                    local_warnings = []
                    for entry in protocol:
                        local_warnings.append(entry.text)
                    ciphers_list[protocol_name].append({"warnings": local_warnings})

                if protocol.attrib.get('key') == 'ciphers':
                    local_ciphers = []
                    name: str = "unknown"
                    grade: str = "unknown"
                    kex_info: str = "unknown"
                    for entry in protocol:
                        for en in entry:
                            if en.attrib.get('key') == 'name':
                                name = en.text
                            if en.attrib.get('key') == 'strength':
                                grade = en.text
                            if en.attrib.get('key') == 'kex_info':
                                kex_info = en.text
                        local_ciphers.append({'tex_info': kex_info, 'name': name, 'grade': grade})
                    ciphers_list[protocol_name].append({'ciphers': local_ciphers})

    ciphers_list = dict(sorted(ciphers_list.items(), reverse=True))

    topic = xml_root.find(".//*[@key='least strength']")
    if topic is not None:
        ciphers_list["least strength"] = topic.text

    return ciphers_list


def ssl_cipher_scan(target_ip, target_ports, xml_path) -> str:
    """Docs."""
    out_xml: str = os.path.join(xml_path, f'{target_ip}_ssl_ciphers.xml')
    nmap_cmd: str = f"nmap {target_ip} -p {target_ports} -n -Pn --script ssl-enum-ciphers -T4 -vv -oX {out_xml}"
    sub_args: list[str] = shlex.split(nmap_cmd)

    with subprocess.Popen(sub_args, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as sub:  # nosec: B603
        sub.communicate()
    return out_xml


def get_cipher_suite(configuration: SimpleNamespace, results: dict):
    """Docs."""
    fname: str = ssl_cipher_scan(configuration.hostname, 443, os.getcwd())
    ciphers: dict = decode_xml(fname)
    os.remove(fname)
    results['cipher_suite'] = ciphers


def remove_prefix(text: str, prefix: str) -> str:
    """Docs."""
    if text.startswith(prefix):
        return text[len(prefix):]
    return text


def get_cert_sans(x509cert) -> list[str]:
    """Docs."""
    san: str = ''
    san_list: list[str] = []

    ext_count: int = x509cert.get_extension_count()
    for i in range(0, ext_count):
        ext = x509cert.get_extension(i)
        if 'subjectAltName' in str(ext.get_short_name()):
            san = str(ext)

    san_list = san.split(', ')
    san_list = [remove_prefix(d, 'DNS:') for d in san_list]
    return san_list


def get_records(host: str, record_type: str) -> list[str]:
    """Docs."""
    try:
        resolver_results: list = dns.resolver.resolve(host, record_type)
        results: list = [val.to_text() for val in resolver_results]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        results = []

    return results


def is_ip_address(target: str) -> Any:
    """Docs."""
    try:
        ip_address: IPv4Address | IPv6Address = ipaddress.ip_address(target)
        status: bool = bool(isinstance(ip_address, (ipaddress.IPv4Address, ipaddress.IPv6Address)))
    except ValueError:
        status = False
    return status


# TODO: IPV6
def get_ips(target: str) -> list[str]:
    """Docs."""
    results: list[str] = []

    if is_ip_address(target) is False:
        results = sorted(get_records(target, "A"))
    else:
        results.append(target)

    return results


def get_certificate_info(host, cert, primary: bool) -> dict:
    """Docs."""
    context: dict = {}

    cert_subject: Any = cert.get_subject()

    if primary:
        context['revocation'] = ocspchecker.get_ocsp_status(host)
        context['host'] = host
        caa: list[str] = get_records(host, 'CAA')
        if not caa:
            domain: str = ('.'.join(host.split('.')[-2:]))
            caa = get_records(domain, 'CAA')
            if caa:
                context['CAA'] = 'Domain Level: ' + ', '.join(caa)
            else:
                context['CAA'] = 'Not Found'
        else:
            context['CAA'] = 'Host Level: ' + ', '.join(caa)

    context['issued_to'] = cert_subject.CN
    context['issued_o'] = cert_subject.O
    context['issuer_c'] = cert.get_issuer().countryName
    context['issuer_o'] = cert.get_issuer().organizationName
    context['issuer_ou'] = cert.get_issuer().organizationalUnitName
    context['issuer_cn'] = cert.get_issuer().commonName
    context['cert_sn'] = str(cert.get_serial_number())
    context['cert_sn_hex'] = hex(cert.get_serial_number()).rstrip('L').lstrip('0x')
    # context['cert_md5'] = cert.digest('md5').decode().replace(":", "").lower()
    # context['cert_sha1'] = cert.digest('sha1').decode().replace(":", "").lower()
    # context['cert_sha224'] = cert.digest('sha224').decode().replace(":", "").lower()
    context['cert_sha256'] = cert.digest('sha256').decode().replace(":", "").lower()
    # context['cert_sha384'] = cert.digest('sha384').decode().replace(":", "").lower()
    # context['cert_sha512'] = cert.digest('sha512').decode().replace(":", "").lower()

    context['cert_alg'] = cert.get_signature_algorithm().decode()
    context['key_size'] = cert.get_pubkey().bits()
    context['cert_ver'] = cert.get_version()
    context['cert_sans'] = get_cert_sans(cert)
    context['cert_exp'] = cert.has_expired()
    context['cert_valid'] = not bool(cert.has_expired())

    # Valid from
    valid_from: datetime = datetime.strptime(cert.get_notBefore().decode('ascii'), '%Y%m%d%H%M%SZ')
    context['valid_from'] = valid_from.strftime('%Y-%m-%d %X')

    # Valid till
    valid_till: datetime = datetime.strptime(cert.get_notAfter().decode('ascii'), '%Y%m%d%H%M%SZ')
    context['valid_till'] = valid_till.strftime('%Y-%m-%d %X')

    # Validity days
    context['validity_days'] = (valid_till - valid_from).days

    # Validity in days from now
    now: datetime = datetime.now()
    context['days_left'] = (valid_till - now).days

    # Valid days left
    context['valid_days_to_expire'] = (datetime.strptime(context['valid_till'], '%Y-%m-%d %X') - datetime.now()).days

    context['pem_file'] = crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode()
    return context


#
# IPV6 ?
#
# TODO: Pull back the actual PEM files as well
def get_certificate(host: str, port: int):
    """Docs."""
    cert_chain: list = []

    sock: socket.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    osobj: SSL.Context = SSL.Context(SSL.TLS_METHOD)

    sock.connect((host, port))
    oscon: SSL.Connection = SSL.Connection(osobj, sock)
    oscon.set_tlsext_host_name(host.encode())
    oscon.set_connect_state()
    oscon.do_handshake()
    # get_cipher_list
    # get_cipher_name
    # get_cipher_bits
    # get_cipher_version
    # get_protocol_version_name
    cert_chain = oscon.get_verified_chain()
    oscon.shutdown()

    return cert_chain


def check_ssl_certificate(configuration: SimpleNamespace, results: dict) -> None:
    """Docs."""
    results['ssl_cert'] = []

    certs = get_certificate(configuration.hostname, 443)
    primary: bool = True
    for cert in certs:
        details: dict = get_certificate_info(configuration.hostname, cert, primary)
        results['ssl_cert'].append(details)
        primary = False


def eval_x_frame_options(contents: str) -> Tuple[int, list[str]]:
    """Docs."""
    if contents.lower() in ['deny', 'sameorigin']:
        return EVAL_OK, []

    return EVAL_WARN, []


def eval_sts(contents: str) -> Tuple[int, list[str]]:
    """Docs."""
    if re.match("^max-age=[0-9]+\\s*(;|$)\\s*", contents.lower()):
        return EVAL_OK, []

    return EVAL_WARN, []


def csp_parser(contents: str) -> dict:
    """Docs."""
    csp: dict = {}

    directives: list[str] = contents.split(";")

    for directive in directives:
        directive_list: list[str] = directive.strip().split()
        if directive_list:
            csp[directive_list[0]] = directive_list[1:] if len(directive_list) > 1 else []

    return csp


def eval_csp(contents: str) -> Tuple[int, list[str]]:
    """Docs."""
    unsafe_rules: dict[str, list[str]] = {
        "script-src": ["*", "'unsafe-eval'", "data:", "'unsafe-inline'"],
        "style-src": ["*", "'unsafe-inline'"],
        "frame-ancestors": ["*"],
        "form-action": ["*"],
        "object-src": ["*"],
    }
    csp_unsafe: bool = False
    csp_notes: list = []

    csp_parsed: dict = csp_parser(contents)

    for rule, rule_list in unsafe_rules.items():
        if rule not in csp_parsed:
            if '-src' in rule and 'default-src' in csp_parsed:
                # fallback to default-src
                for unsafe_src in rule_list:
                    if unsafe_src in csp_parsed['default-src']:
                        csp_unsafe = True
                        csp_notes.append(f"Directive {rule} not defined, and default-src contains unsafe source {unsafe_src}")
            elif 'default-src' not in csp_parsed:
                csp_notes.append(f"No directive {rule} nor default-src defined in the Content Security Policy")
                csp_unsafe = True
        else:
            for unsafe_src in rule_list:
                if unsafe_src in csp_parsed[rule]:
                    csp_notes.append(f"Unsafe source {unsafe_src} in directive {rule}")
                    csp_unsafe = True

    if csp_unsafe:
        return EVAL_WARN, csp_notes

    return EVAL_OK, []


def eval_version_info(contents: str) -> Tuple[int, list]:
    """Docs."""
    # Poor guess whether the header value contain something that could be a server banner including version number
    if len(contents) > 3 and re.match(".*[^0-9]+.*\\d.*", contents):
        return EVAL_WARN, []

    return EVAL_OK, []


def eval_content_type_options(contents: str) -> Tuple[int, list]:
    """Docs."""
    if contents.lower() == 'nosniff':
        return EVAL_OK, []

    return EVAL_WARN, []


def eval_x_xss_protection(contents: str) -> Tuple[int, list]:
    """Docs."""
    # This header is deprecated but still used quite a lot
    #
    # value '1' is dangerous because it can be used to block legit site features. If this header is defined, either
    # one of the below values if recommended
    if contents.lower() in ['1; mode=block', '0']:
        return EVAL_OK, []

    return EVAL_WARN, []


def eval_referrer_policy(contents: str) -> Tuple[int, list]:
    """docs."""
    if contents.lower().strip() in [
        'no-referrer',
        'no-referrer-when-downgrade',
        'origin-when-cross-origin',
        'same-origin',
        'strict-origin',
        'strict-origin-when-cross-origin',
    ]:
        return EVAL_OK, []

    return EVAL_WARN, [f"Unsafe contents: {contents}"]


def permissions_policy_parser(contents: str) -> dict:
    """Docs."""
    policies: list[str] = contents.split(",")
    retval: dict = {}
    for policy in policies:
        match: Match[str] | None = re.match('^([a-zA-Z\\-]*)=(\\(([^\\)]*)\\)|\\*|self)$', policy.strip())
        if match:
            feature: str = match.groups()[0]
            feature_policy: str = match.groups()[2] if match.groups()[2] is not None else match.groups()[1]
            retval[feature] = feature_policy.split()

    return retval


RESTRICTED_PRIVACY_POLICY_FEATURES: list[str] = [
    'accelerometer',
    'autoplay',
    'camera',
    'encrypted-media',
    'fullscreen',
    'geolocation',
    'gyroscope',
    'interest-cohort',
    'magnetometer',
    'microphone',
    'midi',
    'payment',
    'sync-xhr',
    'usb',
    'xr-spatial-tracking'
]


def eval_permissions_policy(contents: str) -> Tuple[int, list]:
    """Docs."""
    # Configuring Permission-Policy is very case-specific and it's difficult to define a particular recommendation.
    # We apply here a logic, that access to privacy-sensitive features and payments API should be restricted.

    pp_parsed: dict = permissions_policy_parser(contents)
    notes: list[str] = []
    pp_unsafe: bool = False

    for feature in RESTRICTED_PRIVACY_POLICY_FEATURES:
        if feature not in pp_parsed or "*" in pp_parsed.get(feature, []):
            pp_unsafe = True
            notes.append(f"Privacy-sensitive feature '{feature}' is not restricted to specific origins.")

    if pp_unsafe:
        return EVAL_WARN, notes

    return EVAL_OK, []


HEADERS_LIST: list[str] = [
    'content-security-policy',
    'permissions-policy',
    'referrer-policy',
    'server',
    'strict-transport-security',
    'x-content-type-options',
    'x-frame-options',
    'x-powered-by',
    'x-xss-protection',
]

HEADERS_RECOMMENDED: dict[str, bool] = {
    'content-security-policy': True,
    'permissions-policy': True,
    'referrer-policy': True,
    'server': False,
    'strict-transport-security': True,
    'x-content-type-options': True,
    'x-frame-options': True,
    'x-powered-by': False,
    'x-xss-protection': False,
}

HEADERS_HINTS: dict[str, str] = {
    "cache-control": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control",
    "connection": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Connection",
    "content-security-policy": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy",
    "content-type": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Type",
    "date": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Date",
    "expires": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Expires",
    "feature-policy": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Feature-Policy",
    "keep-alive": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Keep-Alive",
    "nel": "",
    "permissions-policy": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Feature-Policy",
    "pragma": "",
    "referrer-policy": "",
    "report-to": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/report-to",
    "server": "",
    "set-cookie": "",
    "strict-transport-security": "",
    "upgrade": "",
    "x-content-type-options": "",
    "x-frame-options": "",
    "x-xss-protection": "",
}

EVAL_FUNCTIONS: dict[str, Callable[[str], Tuple[int, list[str]]]] = {
    'content-security-policy': eval_csp,
    'permissions-policy': eval_permissions_policy,
    'referrer-policy': eval_referrer_policy,
    'server': eval_version_info,
    'strict-transport-security': eval_sts,
    'x-content-type-options': eval_content_type_options,
    'x-frame-options': eval_x_frame_options,
    'x-powered-by': eval_version_info,
    'x-xss-protection': eval_x_xss_protection,
}


class HttpInspectorException(Exception):
    """Docs."""


class InvalidParameters(HttpInspectorException):
    """Docs."""


class InvalidTargetURL(HttpInspectorException):
    """Docs."""


class InvalidResponse(HttpInspectorException):
    """Docs."""


class UnableToConnect(HttpInspectorException):
    """Docs."""


class NoHeaders(HttpInspectorException):
    """Docs."""


class NoEvalFunction(HttpInspectorException):
    """Docs."""


def follow_redirect_until_response(url: str, configuration: SimpleNamespace) -> list:
    """Docs."""
    history: list = []
    session: Session = requests.Session()

    if configuration.max_redirects:
        session.max_redirects = configuration.max_redirects

    try:
        resp: Response = session.get(url, headers=REQUEST_HEADERS, verify=configuration.verify_ssl, allow_redirects=configuration.allow_redirects)
        resp.raise_for_status()
    except requests.exceptions.TooManyRedirects as err:
        raise InvalidTargetURL("To many redirects - aborting") from err
    except requests.exceptions.HTTPError as err:
        raise InvalidTargetURL("Error with Web site") from err
    except requests.exceptions.ConnectionError as err:
        raise InvalidTargetURL("No web server there") from err

    if resp.status_code == 301:
        print("Fucker")

    if resp.history:
        for hist in resp.history:
            history.append({'code': hist.status_code, 'url': hist.url})
    history.append({'code': resp.status_code, 'url': resp.url})
    return history


def get_final_destination(configuration: SimpleNamespace, results: dict) -> None:
    """Docs."""
    initial_url: str = f"{configuration.protocol_scheme}://{configuration.hostname}{configuration.path}"

    results['url_history'] = follow_redirect_until_response(initial_url, configuration)
    results['final_destination'] = results['url_history'][-1]
    configuration.final_destination = results['final_destination']


def check_headers(results: dict) -> dict:
    """Docs."""
    retval: dict = {}
    res: int
    notes: list
    warn: bool

    for header in HEADERS_LIST:
        if any(d['name'] == header for d in results['raw_headers']):

            if header in EVAL_FUNCTIONS:
                eval_func: Callable[[str], Tuple[int, list[str]]] = EVAL_FUNCTIONS[header]
            else:
                warn = HEADERS_RECOMMENDED.get(header, False)
                retval[header] = {'defined': True, 'warn': warn, 'contents': None, 'notes': ["Eval function is missing"]}
                continue

            header_str: str = ''.join([d['value'] for d in results['raw_headers'] if d['name'] == header])
            res, notes = eval_func(header_str)
            retval[header] = {
                'defined': True,
                'warn': res == EVAL_WARN,
                'contents': header_str,
                'notes': notes
            }

        else:
            warn = HEADERS_RECOMMENDED.get(header, False)
            retval[header] = {'defined': False, 'warn': warn, 'contents': None, 'notes': []}

    results['security_headers'] = retval

    for item in results['raw_headers']:
        name: str = item['name']
        if name == "permissions-policy":
            name = "feature-policy"
        if name == "report-to":
            name = "Content-Security-Policy/report-to"

        item.update({"documentation": f"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/{name}"})

    return retval


def fetch_headers(configuration: SimpleNamespace, results: dict) -> None:
    """Docs."""
    resp: Response
    headers: list[dict[str, str]]

    # Without sending headers
    # resp = requests.head(configuration.final_destination['url'], timeout=3)
    # without_headers: list[dict[str, str]] = [{"name": key.lower(), "value": value} for key, value in resp.headers.items()]

    # With sent headers
    resp = requests.head(configuration.final_destination['url'], headers=REQUEST_HEADERS, timeout=3)
    headers: list[dict[str, str]] = [{"name": key.lower(), "value": value} for key, value in resp.headers.items()]

    results['raw_headers'] = headers


def scan_target_port(target: str, port: int, socket_timeout: int = 3) -> dict[str, Any]:
    """Define a summary.

    This is the extended summary from the template and needs to be replaced.

    Arguments:
        target (str) -- _description_
        port (int) -- _description_
        delay_time (int) -- _description_

    Returns:
        dict[str, Any] -- _description_
    """
    status: bool = False
    af_type: int = socket.AF_INET

    if isinstance(ipaddress.ip_address(target), IPv6Address) is True:
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
        "ip": target,
        "port": port,
        "status": status,
        "status_string": status_string,
    }


#
# Show open or all ?
#
def port_scan(configuration: SimpleNamespace, results: dict) -> None:
    """Docs."""
    scan_results: list[dict] = []

    ip_list: list = get_ips(configuration.hostname)
    all_ports_and_ips: list[tuple[str, int]] = list(itertools.product(ip_list, PORTSCAN_PORTS))

    default_threads: int = multiprocessing.cpu_count() * 5

    with ThreadPoolExecutor(max_workers=default_threads) as executor:
        futures: list = [executor.submit(scan_target_port, target[0], target[1], 3) for target in all_ports_and_ips]

        for future in as_completed(futures):
            thread_results: dict = future.result()
            if thread_results:
                scan_results.append(thread_results)

    # TODO - Sort results
    results['port-scan'] = scan_results


def create_configuration_from_arguments(args: argparse.Namespace) -> SimpleNamespace:
    """Docs."""
    configuration: SimpleNamespace = SimpleNamespace()

    configuration.debug = args.debug
    configuration.verbose = args.verbose
    configuration.url = args.url
    configuration.max_redirects = args.max_redirects
    configuration.allow_redirects = bool(args.max_redirects)
    configuration.verify_ssl = not bool(args.no_check_certificate)

    parsed: ParseResult = urlparse(args.url)
    if not parsed.scheme or not parsed.netloc:
        configuration.url = f"{DEFAULT_URL_SCHEME}://{args.url}"
        parsed = urlparse(configuration.url)
        if not parsed.scheme and not parsed.netloc:
            raise InvalidTargetURL("Unable to parse the URL")

    configuration.protocol_scheme = parsed.scheme
    configuration.hostname = parsed.netloc
    configuration.path = parsed.path
    configuration.port = parsed.port

    return configuration


def add_flags_to_parser(parser: argparse.ArgumentParser) -> None:
    """Docs."""
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


def add_required_parameters(parser: argparse.ArgumentParser) -> None:
    """Docs."""
    required: argparse._ArgumentGroup = parser.add_argument_group(
        title="required arguments",
        description="stuff"
    )
    required.add_argument("-u", "--url",
                          type=str,
                          help="The url you want to check")


def add_optional_parameters(parser: argparse.ArgumentParser) -> None:
    """Docs."""
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


def setup_arg_parser() -> argparse.ArgumentParser:
    """Docs."""
    parser: argparse.ArgumentParser = argparse.ArgumentParser(
        add_help=False,
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        description="HTTP Inspector",
        epilog="For detailed documentation please refer to: https://github.com/OffSecToolbox/http-inspector",
    )
    add_flags_to_parser(parser)
    add_required_parameters(parser)
    add_optional_parameters(parser)

    return parser


def process_command_line_arguments() -> argparse.Namespace:
    """Docs."""
    parser: argparse.ArgumentParser = setup_arg_parser()
    args: argparse.Namespace = parser.parse_args()

    if args.url is None:
        parser.print_help()
        sys.exit(0)

    return args


def main() -> None:
    """Docs."""
    results: dict = {}

    args: argparse.Namespace = process_command_line_arguments()
    configuration: SimpleNamespace = create_configuration_from_arguments(args)

    get_final_destination(configuration, results)
    fetch_headers(configuration, results)
    check_headers(results)
    check_ssl_certificate(configuration, results)
    get_cipher_suite(configuration, results)
    port_scan(configuration, results)
    print(json.dumps(results, indent=4, default=str))
    sys.exit(0)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[*] Exiting Program\n")
    except (InvalidParameters, InvalidTargetURL, InvalidResponse, NoHeaders) as e:
        print(str(e))
