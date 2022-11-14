# -*- coding: utf-8 -*-

"""This is the summary line.

This is the further elaboration of the docstring. Within this section,
you can elaborate further on details as appropriate for the situation.
Notice that the summary and the elaboration is separated by a blank new
line.
"""

import colorama

from faker import Faker

colorama.init()
fake: Faker = Faker()

RED: str = colorama.Fore.RED
YELLOW: str = colorama.Fore.YELLOW
GREEN: str = colorama.Fore.GREEN
GRAY: str = colorama.Fore.LIGHTBLACK_EX
RESET: str = colorama.Style.RESET_ALL

SUCCESS: str = colorama.Fore.GREEN
WARN: str = colorama.Fore.YELLOW
ERROR: str = colorama.Fore.RED
INFO: str = colorama.Fore.CYAN

PORTSCAN_PORTS: list = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 465, 587, 993, 995, 1723, 3306, 3389, 5900, 8080, 8443]

REQUEST_HEADERS: dict[str, str] = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    "Accept-Language": "en-GB,en;q=0.9",
    "Cache-Control": "max-age=0",
    "User-Agent": fake.user_agent(),
}

DEFAULT_URL_SCHEME: str = "https"
EVAL_WARN: int = 0
EVAL_OK: int = 1

HEADERS_LIST: list[str] = [
    "content-security-policy",
    "permissions-policy",
    "referrer-policy",
    "server",
    "strict-transport-security",
    "x-content-type-options",
    "x-frame-options",
    "x-powered-by",
    "x-xss-protection",
]

HEADERS_RECOMMENDED: dict[str, bool] = {
    "content-security-policy": True,
    "permissions-policy": True,
    "referrer-policy": True,
    "server": False,
    "strict-transport-security": True,
    "x-content-type-options": True,
    "x-frame-options": True,
    "x-powered-by": False,
    "x-xss-protection": False,
}

EVAL_FUNCTIONS: dict[str, str] = {
    "content-security-policy": "_eval_csp",
    "permissions-policy": "_eval_permissions_policy",
    "referrer-policy": "_eval_referrer_policy",
    "server": "_eval_version_info",
    "strict-transport-security": "_eval_sts",
    "x-content-type-options": "_eval_content_type_options",
    "x-frame-options": "_eval_x_frame_options",
    "x-powered-by": "_eval_version_info",
    "x-xss-protection": "_eval_x_xss_protection",
}

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
