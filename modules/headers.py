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

from .constants import EVAL_ISSUE, EVAL_FUNCTIONS, HEADERS_LIST, HEADERS_RECOMMENDED, REQUEST_HEADERS, RESTRICTED_FEATURES, UNSAFE_RULES
from .globals import global_configuration, global_results


def process_headers() -> None:
    """Define a summary.

    This is the extended summary from the template and needs to be replaced.
    """
    _fetch_headers()
    _decode_headers()


def _fetch_headers() -> None:
    """Define a summary.

    This is the extended summary from the template and needs to be replaced.
    """
    resp: requests.Response = requests.head(global_configuration.url.full_url, headers=REQUEST_HEADERS, timeout=global_configuration.timeout)
    headers: list[dict[str, str]] = [{"name": key.lower(), "value": value} for key, value in resp.headers.items()]

    headers = sorted(headers, key=lambda d: d["name"])

    global_results.raw_headers = headers
    _add_documentation()


def _decode_headers() -> None:
    """Define a summary.

    This is the extended summary from the template and needs to be replaced.
    """
    security_headers: dict = {}
    res: int
    notes: list

    for header in HEADERS_LIST:
        recommended: bool = HEADERS_RECOMMENDED.get(header, False)
        # Is the header we are interested in in the raw headers?
        if not any(d["name"] == header for d in global_results.raw_headers):
            security_headers[header] = {"raw-header": False, "recommended": recommended, "issue": recommended, "contents": None, "notes": []}
            continue

        header_str: str = "".join([d["value"] for d in global_results.raw_headers if d["name"] == header])
        try:
            res, notes = globals()[EVAL_FUNCTIONS[header]](header_str)
        except KeyError:
            security_headers[header] = {
                "raw-header": False,
                "recommended": recommended,
                "issue": recommended,
                "contents": header_str,
                "notes": ["Eval function is missing"]
            }
            continue

        security_headers[header] = {"raw-header": True, "recommended": recommended, "issue": res, "contents": header_str, "notes": notes}

    global_results.security_headers = security_headers


def _add_documentation() -> None:
    """Define a summary.

    This is the extended summary from the template and needs to be replaced.
    """
    for item in global_results.raw_headers:
        name: str = item['name']
        if name == "permissions-policy":
            name = "feature-policy"
        if name == "report-to":
            name = "Content-Security-Policy/report-to"

        if name.startswith("cf-"):
            item.update({"documentation": "https://developers.cloudflare.com/fundamentals/get-started/reference/http-request-headers/"})
        else:
            item.update({"documentation": f"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/{name}"})


def _eval_csp(contents: str) -> Tuple[bool, list[str]]:
    """Define a summary.

    This is the extended summary from the template and needs to be replaced.

    Arguments:
        contents (str) -- _description_

    Returns:
        Tuple[int, list[str]] -- _description_
    """
    csp_unsafe: bool = False
    csp_notes: list = []
    tmp_notes: list = []
    csp_parsed: dict = _csp_parser(contents)

    for rule, rule_list in UNSAFE_RULES.items():
        if rule not in csp_parsed:
            csp_unsafe, tmp_notes = _rule_not_in_csp(rule, rule_list, csp_parsed, csp_unsafe)
            csp_notes += tmp_notes
        else:
            for unsafe_src in rule_list:
                if unsafe_src in csp_parsed[rule]:
                    csp_notes.append(f"Unsafe source {unsafe_src} in directive {rule}")
                    csp_unsafe = True

    if csp_unsafe:
        return EVAL_ISSUE, csp_notes

    return not EVAL_ISSUE, []


def _rule_not_in_csp(rule: str, rule_list: list, csp_parsed: dict, csp_unsafe: bool) -> Tuple[bool, list]:
    unsafe: bool = False
    notes: list = []

    if '-src' in rule and 'default-src' in csp_parsed:
        for unsafe_src in rule_list:
            if unsafe_src in csp_parsed['default-src']:
                unsafe = True
                notes.append(f"Directive {rule} not defined, and default-src contains unsafe source {unsafe_src}")
    elif 'default-src' not in csp_parsed:
        notes.append(f"No directive {rule} nor default-src defined in the Content Security Policy")
        unsafe = True

    # If it is already set - force it to remain set
    if csp_unsafe:
        unsafe = True

    return unsafe, notes


def _csp_parser(contents: str) -> dict:
    """Define a summary.

    This is the extended summary from the template and needs to be replaced.

    Arguments:
        contents (str) -- _description_

    Returns:
        dict -- _description_
    """
    csp: dict = {}

    directives: list[str] = contents.split(";")

    for directive in directives:
        directive_list: list[str] = directive.strip().split()
        if directive_list:
            csp[directive_list[0]] = directive_list[1:] if len(directive_list) > 1 else []

    return csp


def _eval_permissions_policy(contents: str) -> Tuple[bool, list]:
    """Define a summary.

    This is the extended summary from the template and needs to be replaced.

    Arguments:
        contents (str) -- _description_

    Returns:
        Tuple[int, list] -- _description_
    """
    # Configuring Permission-Policy is very case-specific and it's difficult to define a particular recommendation.
    # We apply here a logic, that access to privacy-sensitive features and payments API should be restricted.

    pp_parsed: dict = _permissions_policy_parser(contents)
    notes: list[str] = []
    pp_unsafe: bool = False

    for feature in RESTRICTED_FEATURES:
        if feature not in pp_parsed or "*" in pp_parsed.get(feature, []):
            pp_unsafe = True
            notes.append(f"Privacy-sensitive feature '{feature}' is not restricted to specific origins.")

    if pp_unsafe:
        return EVAL_ISSUE, notes

    return not EVAL_ISSUE, []


def _eval_pragma(contents: str) -> Tuple[bool, list]:
    """Define a summary.

    This is the extended summary from the template and needs to be replaced.

    Arguments:
        contents (str) -- _description_

    Returns:
        Tuple[int, list] -- _description_
    """
    if contents is not None:
        return EVAL_ISSUE, ["Deprecated: This feature is no longer recommended."]

    return not EVAL_ISSUE, []


def _permissions_policy_parser(contents: str) -> dict:
    """Define a summary.

    This is the extended summary from the template and needs to be replaced.

    Arguments:
        contents (str) -- _description_

    Returns:
        dict -- _description_
    """
    policies: list[str] = contents.split(",")
    retval: dict = {}

    for policy in policies:
        match: re.Match[str] | None = re.match('^([a-zA-Z\\-]*)=(\\(([^\\)]*)\\)|\\*|self)$', policy.strip())
        if match:
            feature: str = match.groups()[0]
            feature_policy: str = match.groups()[2] if match.groups()[2] is not None else match.groups()[1]
            retval[feature] = feature_policy.split()

    return retval


def _eval_referrer_policy(contents: str) -> Tuple[bool, list]:
    """Define a summary.

    This is the extended summary from the template and needs to be replaced.

    Arguments:
        contents (str) -- _description_

    Returns:
        Tuple[int, list] -- _description_
    """
    if contents.lower().strip() in [
        'no-referrer',
        'no-referrer-when-downgrade',
        'origin-when-cross-origin',
        'same-origin',
        'strict-origin',
        'strict-origin-when-cross-origin',
    ]:
        return not EVAL_ISSUE, []

    return EVAL_ISSUE, [f"Unsafe or non-recommended: {contents}"]


def _eval_version_info(contents: str) -> Tuple[bool, list]:
    """Define a summary.

    This is the extended summary from the template and needs to be replaced.

    Arguments:
        contents (str) -- _description_

    Returns:
        Tuple[int, list] -- _description_
    """
    # Poor guess whether the header value contain something that could be a server banner including version number
    if len(contents) > 3 and re.match(".*\\d+.*\\d.*", contents):
        return EVAL_ISSUE, []

    return not EVAL_ISSUE, []


def _eval_sts(contents: str) -> Tuple[bool, list[str]]:
    """Define a summary.

    This is the extended summary from the template and needs to be replaced.

    Arguments:
        contents (str) -- _description_

    Returns:
        Tuple[int, list[str]] -- _description_
    """
    if re.match("^max-age=\\d+\\s*(;|$)\\s*", contents.lower()):
        return not EVAL_ISSUE, []

    return EVAL_ISSUE, []


def _eval_content_type_options(contents: str) -> Tuple[bool, list]:
    """Define a summary.

    This is the extended summary from the template and needs to be replaced.

    Arguments:
        contents (str) -- _description_

    Returns:
        Tuple[int, list] -- _description_
    """
    if contents.lower() == 'nosniff':
        return not EVAL_ISSUE, []

    return EVAL_ISSUE, []


def _eval_x_frame_options(contents: str) -> Tuple[bool, list[str]]:
    """Define a summary.

    This is the extended summary from the template and needs to be replaced.

    Arguments:
        contents (str) -- _description_

    Returns:
        Tuple[int, list[str]] -- _description_
    """
    if contents.lower() in ['deny', 'sameorigin']:
        return not EVAL_ISSUE, []

    return EVAL_ISSUE, []


def _eval_x_xss_protection(contents: str) -> Tuple[bool, list]:
    """Define a summary.

    This is the extended summary from the template and needs to be replaced.

    Arguments:
        contents (str) -- _description_

    Returns:
        Tuple[int, list] -- _description_
    """
    # This header is deprecated but still used quite a lot
    #
    # value '1' is dangerous because it can be used to block legit site features. If this header is defined, either
    # one of the below values if recommended
    if contents.lower() in ['1; mode=block', '0']:
        return not EVAL_ISSUE, []

    return EVAL_ISSUE, []
