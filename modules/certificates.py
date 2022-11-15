# -*- coding: utf-8 -*-
"""This is the summary line.

This is the further elaboration of the docstring. Within this section,
you can elaborate further on details as appropriate for the situation.
Notice that the summary and the elaboration is separated by a blank new
line.
"""
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


def get_certificates() -> list:
    """Define a summary.

    This is the extended summary from the template and needs to be replaced.

    Returns:
        list -- _description_
    """
    cert_chain: list = []

    sock: socket.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    osobj: SSL.Context = SSL.Context(SSL.TLSv1_2_METHOD)
    osobj.set_ocsp_client_callback(_extract_ocsp_result)

    sock.connect((global_configuration.url.hostname, global_configuration.url.port))

    try:
        oscon: SSL.Connection = SSL.Connection(osobj, sock)
        oscon.set_tlsext_host_name(global_configuration.url.hostname.encode())
        oscon.request_ocsp()
        oscon.set_connect_state()
        oscon.do_handshake()
        # get_cipher_list
        # get_cipher_name
        # get_cipher_bits
        # get_cipher_version
        # get_protocol_version_name
        cert_chain = oscon.get_verified_chain()
        oscon.shutdown()
    except SSL.Error:
        warn("Unable to retrieve SSL certificates - check your url and rerun if this is unexpected")

    return cert_chain


def process_certificates(certificates: list) -> None:
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
            details['revocation'] = global_results.ocsp_message
            del global_results.ocsp_message
        decoded_certificates.append(details)
        primary = False

    global_results.ssl_certs = decoded_certificates


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
