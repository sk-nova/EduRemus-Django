"""Signal receivers for the authentication layer.

Imported by ``AuthenticationConfig.ready()`` for its registration side effects,
so every receiver belongs here rather than beside the model or service it
reacts to -- an unimported receiver is silently never called.

Empty for now. Receivers arrive with the models they observe.
"""

from __future__ import annotations
