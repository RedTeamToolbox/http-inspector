# -*- coding: utf-8 -*-

"""This is the summary line.

This is the further elaboration of the docstring. Within this section,
you can elaborate further on details as appropriate for the situation.
Notice that the summary and the elaboration is separated by a blank new
line.
"""
from types import SimpleNamespace

from typing import Any
from urllib.parse import urlparse, ParseResult

import requests
import tldextract

from .constants import DEFAULT_URL_SCHEME, REQUEST_HEADERS
from .exceptions import InvalidTargetURL
from .globals import global_configuration


def url_parser(url: str) -> SimpleNamespace:
    """Define a summary.

    This is the extended summary from the template and needs to be replaced.

    Arguments:
        url (str) -- _description_

    Raises:
        InvalidTargetURL: _description_

    Returns:
        SimpleNamespace -- _description_
    """
    parsed: ParseResult = urlparse(url)

    if not parsed.scheme or not parsed.netloc:
        url: str = f"{DEFAULT_URL_SCHEME}://{url}"
        parsed = urlparse(url)
        if not parsed.scheme and not parsed.netloc:
            raise InvalidTargetURL("Unable to parse the URL")

    elements: SimpleNamespace = SimpleNamespace()
    directories: list[str] = parsed.path.strip('/').split('/')
    queries: list[str] = parsed.query.strip('&').split('&')

    elements.full_url = url
    elements.scheme = parsed.scheme
    elements.netloc = parsed.netloc
    elements.path = parsed.path
    elements.params = parsed.params
    elements.query = parsed.query
    elements.fragment = parsed.fragment
    elements.username = parsed.username
    elements.password = parsed.password
    elements.hostname = parsed.hostname
    elements.port = parsed.port
    elements.directories = directories
    elements.queries = queries

    if elements.port is None:
        if elements.scheme == "http":
            elements.port = 80
        elif elements.scheme == "https":
            elements.port = 443

    ext: Any = tldextract.extract(elements.hostname)
    elements.domain = ext.registered_domain

    return elements


def follow_redirects(url: str) -> list:
    """Define a summary.

    This is the extended summary from the template and needs to be replaced.

    Arguments:
        url (str) -- _description_

    Raises:
        InvalidTargetURL: _description_

    Returns:
        list -- _description_
    """
    history: list = []
    session: requests.Session = requests.Session()

    if global_configuration.max_redirects:
        session.max_redirects = global_configuration.max_redirects

    # TODO: requests.get('http://127.0.0.1/foo.php', headers={'host': 'example.com'})
    try:
        resp: requests.Response = session.get(
            url, headers=REQUEST_HEADERS,
            verify=global_configuration.verify_ssl,
            allow_redirects=global_configuration.allow_redirects,
            timeout=global_configuration.timeout
        )
        resp.raise_for_status()
    except requests.exceptions.TooManyRedirects as err:
        raise InvalidTargetURL("To many redirects - aborting") from err
    except requests.exceptions.HTTPError as err:
        raise InvalidTargetURL(f"Error with web site {err}") from err
    except requests.exceptions.ConnectionError as err:
        raise InvalidTargetURL(f"No web server there {err}") from err

    if resp.history:
        for hist in resp.history:
            history.append({'code': hist.status_code, 'url': hist.url})
    history.append({'code': resp.status_code, 'url': resp.url})
    return history
