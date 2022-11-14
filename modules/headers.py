# -*- coding: utf-8 -*-
"""This is the summary line.

This is the further elaboration of the docstring. Within this section,
you can elaborate further on details as appropriate for the situation.
Notice that the summary and the elaboration is separated by a blank new
line.
"""
import re

from typing import Tuple

import requests

from .constants import EVAL_FUNCTIONS, EVAL_OK, EVAL_WARN, HEADERS_LIST, HEADERS_RECOMMENDED, REQUEST_HEADERS, RESTRICTED_PRIVACY_POLICY_FEATURES
from .globals import configuration, results


def fetch_headers() -> None:
    """Docs."""
    resp: requests.Response
    headers: list[dict[str, str]]

    # Without sending headers
    # resp = requests.head(configuration.final_destination['url'], timeout=3)
    # without_headers: list[dict[str, str]] = [{"name": key.lower(), "value": value} for key, value in resp.headers.items()]

    # With sent headers
    resp = requests.head(configuration.url.full_url, headers=REQUEST_HEADERS, timeout=configuration.timeout)
    headers: list[dict[str, str]] = [{"name": key.lower(), "value": value} for key, value in resp.headers.items()]

    results.raw_headers = headers
    _check_headers()


def _check_headers() -> None:
    """Docs."""
    security_headers: dict = {}
    res: int
    notes: list
    warn: bool

    for header in HEADERS_LIST:
        if any(d['name'] == header for d in results.raw_headers):

            if header in EVAL_FUNCTIONS:
                eval_func: str = EVAL_FUNCTIONS[header]
            else:
                warn = HEADERS_RECOMMENDED.get(header, False)
                security_headers[header] = {'defined': True, 'warn': warn, 'contents': None, 'notes': ["Eval function is missing"]}
                continue

            header_str: str = ''.join([d['value'] for d in results.raw_headers if d['name'] == header])
            try:
                res, notes = globals()[eval_func](header_str)
            except KeyError:
                warn = HEADERS_RECOMMENDED.get(header, False)
                security_headers[header] = {'defined': False, 'warn': warn, 'contents': header_str, 'notes': ["Eval function is missing"]}
                continue

            security_headers[header] = {
                'defined': True,
                'warn': res == EVAL_WARN,
                'contents': header_str,
                'notes': notes
            }

        else:
            warn = HEADERS_RECOMMENDED.get(header, False)
            security_headers[header] = {'defined': False, 'warn': warn, 'contents': None, 'notes': []}

    for item in results.raw_headers:
        name: str = item['name']
        if name == "permissions-policy":
            name = "feature-policy"
        if name == "report-to":
            name = "Content-Security-Policy/report-to"

        item.update({"documentation": f"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/{name}"})

    results.security_headers = security_headers


def _eval_csp(contents: str) -> Tuple[int, list[str]]:
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

    csp_parsed: dict = _csp_parser(contents)

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


def _csp_parser(contents: str) -> dict:
    """Docs."""
    csp: dict = {}

    directives: list[str] = contents.split(";")

    for directive in directives:
        directive_list: list[str] = directive.strip().split()
        if directive_list:
            csp[directive_list[0]] = directive_list[1:] if len(directive_list) > 1 else []

    return csp


def _eval_permissions_policy(contents: str) -> Tuple[int, list]:
    """Docs."""
    # Configuring Permission-Policy is very case-specific and it's difficult to define a particular recommendation.
    # We apply here a logic, that access to privacy-sensitive features and payments API should be restricted.

    pp_parsed: dict = _permissions_policy_parser(contents)
    notes: list[str] = []
    pp_unsafe: bool = False

    for feature in RESTRICTED_PRIVACY_POLICY_FEATURES:
        if feature not in pp_parsed or "*" in pp_parsed.get(feature, []):
            pp_unsafe = True
            notes.append(f"Privacy-sensitive feature '{feature}' is not restricted to specific origins.")

    if pp_unsafe:
        return EVAL_WARN, notes

    return EVAL_OK, []


def _permissions_policy_parser(contents: str) -> dict:
    """Docs."""
    policies: list[str] = contents.split(",")
    retval: dict = {}

    for policy in policies:
        match: re.Match[str] | None = re.match('^([a-zA-Z\\-]*)=(\\(([^\\)]*)\\)|\\*|self)$', policy.strip())
        if match:
            feature: str = match.groups()[0]
            feature_policy: str = match.groups()[2] if match.groups()[2] is not None else match.groups()[1]
            retval[feature] = feature_policy.split()

    return retval


def _eval_referrer_policy(contents: str) -> Tuple[int, list]:
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


def _eval_version_info(contents: str) -> Tuple[int, list]:
    """Docs."""
    # Poor guess whether the header value contain something that could be a server banner including version number
    if len(contents) > 3 and re.match(".*[^0-9]+.*\\d.*", contents):
        return EVAL_WARN, []

    return EVAL_OK, []


def _eval_sts(contents: str) -> Tuple[int, list[str]]:
    """Docs."""
    if re.match("^max-age=[0-9]+\\s*(;|$)\\s*", contents.lower()):
        return EVAL_OK, []

    return EVAL_WARN, []


def _eval_content_type_options(contents: str) -> Tuple[int, list]:
    """Docs."""
    if contents.lower() == 'nosniff':
        return EVAL_OK, []

    return EVAL_WARN, []


def _eval_x_frame_options(contents: str) -> Tuple[int, list[str]]:
    """Docs."""
    if contents.lower() in ['deny', 'sameorigin']:
        return EVAL_OK, []

    return EVAL_WARN, []


def _eval_x_xss_protection(contents: str) -> Tuple[int, list]:
    """Docs."""
    # This header is deprecated but still used quite a lot
    #
    # value '1' is dangerous because it can be used to block legit site features. If this header is defined, either
    # one of the below values if recommended
    if contents.lower() in ['1; mode=block', '0']:
        return EVAL_OK, []

    return EVAL_WARN, []
