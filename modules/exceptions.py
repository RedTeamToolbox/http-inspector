# -*- coding: utf-8 -*-
"""This is the summary line.

This is the further elaboration of the docstring. Within this section,
you can elaborate further on details as appropriate for the situation.
Notice that the summary and the elaboration is separated by a blank new
line.
"""


class HTTPInspectorException(Exception):
    """Define a summary.

    This is the extended summary from the template and needs to be replaced.

    Arguments:
        Exception (_type_) -- _description_
    """


class InvalidParameters(HTTPInspectorException):
    """Define a summary.

    This is the extended summary from the template and needs to be replaced.

    Arguments:
        PortScannerException (_type_) -- _description_
    """


class InvalidTargetURL(HTTPInspectorException):
    """Define a summary.

    This is the extended summary from the template and needs to be replaced.

    Arguments:
        PortScannerException (_type_) -- _description_
    """


class CertificateError(HTTPInspectorException):
    """Define a summary.

    This is the extended summary from the template and needs to be replaced.

    Arguments:
        PortScannerException (_type_) -- _description_
    """


class InvalidResponse(HTTPInspectorException):
    """Docs."""


class UnableToConnect(HTTPInspectorException):
    """Docs."""


class NoHeaders(HTTPInspectorException):
    """Docs."""


class NoEvalFunction(HTTPInspectorException):
    """Docs."""
