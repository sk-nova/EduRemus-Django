"""Request-scoped context for logging.

One line of work, done once per request, so that every log record emitted
anywhere downstream carries the correlation id without the emitting code
knowing anything about it.

Placement: below ``TenantMainMiddleware``, which must stay first because
anything above it queries the database with ``public`` still selected. This
middleware touches no models, so it could sit anywhere -- it goes here so that
records from every *other* middleware below it are correlated too.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from apps.authentication.logging import request_id_var
from apps.authentication.utils.request_meta import request_id

if TYPE_CHECKING:
    from collections.abc import Callable

    from django.http import HttpRequest, HttpResponse

__all__ = ["RequestIdMiddleware"]

_HEADER = "X-Request-Id"


class RequestIdMiddleware:
    """Bind a correlation id for the duration of one request.

    The id is reused rather than invented: ``request_meta.request_id`` honours
    a validated client-supplied ``X-Request-Id`` so a trace survives across
    service boundaries, and caches whatever it settles on so the header, the
    logs and the error envelope all report the same value.
    """

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]) -> None:
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        identifier = request_id(request)
        token = request_id_var.set(identifier)
        try:
            response = self.get_response(request)
            # Echoed on every response, not only the authentication ones, so
            # a user reporting any error can be matched to a log line.
            if not response.has_header(_HEADER):
                response[_HEADER] = identifier
            return response
        finally:
            # Reset rather than clear: workers are reused, and a leaked value
            # would attribute the next request's records to this one.
            request_id_var.reset(token)
