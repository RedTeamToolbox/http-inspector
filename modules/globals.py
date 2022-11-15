# -*- coding: utf-8 -*-

"""This is the summary line.

This is the further elaboration of the docstring. Within this section,
you can elaborate further on details as appropriate for the situation.
Notice that the summary and the elaboration is separated by a blank new
line.
"""

from types import SimpleNamespace
from secrets import SystemRandom

secrets_generator: SystemRandom = SystemRandom()

global_configuration: SimpleNamespace = SimpleNamespace()
global_results: SimpleNamespace = SimpleNamespace()
