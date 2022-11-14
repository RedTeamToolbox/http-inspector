# -*- coding: utf-8 -*-

"""This is the summary line.

This is the further elaboration of the docstring. Within this section,
you can elaborate further on details as appropriate for the situation.
Notice that the summary and the elaboration is separated by a blank new
line.
"""


def remove_prefix(text: str, prefix: str) -> str:
    """Define a summary.

    This is the extended summary from the template and needs to be replaced.

    Arguments:
        text (str) -- _description_
        prefix (str) -- _description_

    Returns:
        str -- _description_
    """
    if text.startswith(prefix):
        return text[len(prefix):]
    return text
