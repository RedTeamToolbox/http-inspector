# -*- coding: utf-8 -*-
"""This is the summary line.

This is the further elaboration of the docstring. Within this section,
you can elaborate further on details as appropriate for the situation.
Notice that the summary and the elaboration is separated by a blank new
line.
"""
import ipaddress
import socket

from datetime import datetime
from typing import Any

from cryptography.x509 import ocsp
from OpenSSL import SSL, crypto

from .constants import CERTIFICATE_TIME_FORMAT
from .dns import get_records
from .globals import global_configuration, global_results
from .notify import warn
from .utils import remove_prefix


def process_certificates() -> None:
    """Define a summary.

    This is the extended summary from the template and needs to be replaced.
    """
    raw_certificates: list = []
    decoded_certificates: dict = {}

    for ipaddr in global_results.ips.addresses:
        raw_certificates = _get_certificates(ipaddr)
        decoded_certificates[ipaddr] = _decode_certificates(raw_certificates)

    global_results.ssl_certs = decoded_certificates


def _get_certificates(target: str) -> list:
    """Define a summary.

    This is the extended summary from the template and needs to be replaced.

    Returns:
        list -- _description_
    """
    cert_chain: list = []

    af_type: int = socket.AF_INET

    if isinstance(ipaddress.ip_address(target), ipaddress.IPv6Address) is True:
        af_type = socket.AF_INET6

    sock: socket.socket = socket.socket(af_type, socket.SOCK_STREAM)
    ssl_obj: SSL.Context = SSL.Context(SSL.TLSv1_2_METHOD)
    ssl_obj.set_ocsp_client_callback(_extract_ocsp_result)
    if global_configuration.verify_ssl:
        ssl_obj.set_verify(SSL.VERIFY_PEER | SSL.VERIFY_FAIL_IF_NO_PEER_CERT | SSL.VERIFY_CLIENT_ONCE, _verify_ssl)
    else:
        ssl_obj.set_verify(SSL.VERIFY_NONE)

    try:
        sock.connect((target, global_configuration.url.port))
        ssl_conn: SSL.Connection = SSL.Connection(ssl_obj, sock)
        ssl_conn.set_tlsext_host_name(global_configuration.url.hostname.encode())
        ssl_conn.request_ocsp()
        ssl_conn.set_connect_state()
        ssl_conn.do_handshake()
        # get_cipher_list
        # get_cipher_name
        # get_cipher_bits
        # get_cipher_version
        # get_protocol_version_name
        cert_chain = ssl_conn.get_verified_chain()
        ssl_conn.shutdown()
    except SSL.Error as err:
        warn(f"Unable to retrieve SSL certificates from {target} {err}")
    except OSError as err:
        warn(f"Unable to retrieve SSL certificates from {target} {err}")

    return cert_chain


def _verify_ssl(_conn, _cert, errno, depth, _result) -> bool:
    """Define a summary.

    This is the extended summary from the template and needs to be replaced.

    Arguments:
        _conn (_type_) -- _description_
        _cert (_type_) -- _description_
        errno (_type_) -- _description_
        depth (_type_) -- _description_
        _result (_type_) -- _description_

    Returns:
        bool -- _description_
    """
    if depth == 0 and (errno == 9 or errno == 10):
        return False  # or raise Exception("Certificate not yet valid or expired")
    return True


def _extract_ocsp_result(_conn, ocsp_response: bytes, _other_data) -> bool:
    """Define a summary.

    This is the extended summary from the template and needs to be replaced.

    Arguments:
        _conn (_type_) -- _description_
        ocsp_response (bytes) -- _description_
        _other_data (_type_) -- _description_

    Returns:
        bool -- _description_
    """
    try:
        ocsp_response: Any = ocsp.load_der_ocsp_response(ocsp_response)
        ocsp_status: int = int(ocsp_response.response_status.value)

        if ocsp_status != 0:
            # This will return one of five errors, which means connecting
            # to the OCSP Responder failed for one of the below reasons:
            # MALFORMED_REQUEST = 1
            # INTERNAL_ERROR = 2
            # TRY_LATER = 3
            # SIG_REQUIRED = 5
            # UNAUTHORIZED = 6
            ocsp_response = str(ocsp_response.response_status)
            ocsp_response = ocsp_response.split(".")
            global_results.ocsp_message = f"OCSP Request Error: {ocsp_response[1]}"

        certificate_status: str = str(ocsp_response.certificate_status)
        certificate_status = certificate_status.split(".")
        global_results.ocsp_message = f"{certificate_status[1]}"

    except ValueError as err:
        global_results.ocsp_message = str(err)

    # Always return True otherwise we cant retrieve and download the certs
    return True


def _decode_certificates(certificates: list) -> list:
    """Define a summary.

    This is the extended summary from the template and needs to be replaced.

    Arguments:
        certificates (list) -- _description_
    """
    decoded_certificates: list = []
    primary: bool = True

    for cert in certificates:
        details: dict = _get_certificate_info(cert, primary)
        if primary:
            details['revocation_status'] = global_results.ocsp_message
            del global_results.ocsp_message
        decoded_certificates.append(details)
        primary = False

    return decoded_certificates


def _get_certificate_info(cert, primary) -> dict:
    """Define a summary.

    This is the extended summary from the template and needs to be replaced.

    Arguments:
        cert (_type_) -- _description_
        primary (_type_) -- _description_

    Returns:
        dict -- _description_
    """
    context: dict = {}

    cert_subject: Any = cert.get_subject()

    if primary:
        context['host'] = global_configuration.url.hostname
        caa: list[str] = get_records(global_configuration.url.hostname, 'CAA')
        if not caa:
            caa = get_records(global_configuration.url.domain, 'CAA')
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
    context['cert_sha256'] = cert.digest('sha256').decode().replace(":", "").lower()
    context['cert_alg'] = cert.get_signature_algorithm().decode()
    context['key_size'] = cert.get_pubkey().bits()
    context['cert_ver'] = cert.get_version()
    context['cert_sans'] = _get_cert_sans(cert)
    context['cert_exp'] = cert.has_expired()
    context['cert_valid'] = not bool(cert.has_expired())

    # Valid from
    valid_from: datetime = datetime.strptime(cert.get_notBefore().decode('ascii'), '%Y%m%d%H%M%SZ')
    context['valid_from'] = valid_from.strftime(CERTIFICATE_TIME_FORMAT)

    # Valid till
    valid_till: datetime = datetime.strptime(cert.get_notAfter().decode('ascii'), '%Y%m%d%H%M%SZ')
    context['valid_till'] = valid_till.strftime(CERTIFICATE_TIME_FORMAT)

    # Validity days
    context['validity_days'] = (valid_till - valid_from).days

    # Validity in days from now
    now: datetime = datetime.now()
    context['days_left'] = (valid_till - now).days

    # Valid days left
    context['valid_days_to_expire'] = (datetime.strptime(context['valid_till'], CERTIFICATE_TIME_FORMAT) - datetime.now()).days

    context['pem_file'] = crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode()
    return context


def _get_cert_sans(x509cert) -> list[str]:
    """Define a summary.

    This is the extended summary from the template and needs to be replaced.

    Arguments:
        x509cert (_type_) -- _description_

    Returns:
        list[str] -- _description_
    """
    san: str = ''
    san_list: list[str] = []

    ext_count: int = x509cert.get_extension_count()
    for i in range(0, ext_count):
        ext: Any = x509cert.get_extension(i)
        if 'subjectAltName' in str(ext.get_short_name()):
            san = str(ext)

    san_list = san.split(', ')
    san_list = [remove_prefix(d, 'DNS:') for d in san_list]
    return san_list
