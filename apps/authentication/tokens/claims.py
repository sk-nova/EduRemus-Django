"""Canonical claim names.

Defined once so a typo at one call site cannot silently disable a check that a
test asserts is present at another. Everything that reads or writes a claim
imports from here, and this module imports nothing from the project -- it has
no dependencies to invalidate and can be read in full to know the vocabulary.

Two claims are routinely confused and are not interchangeable:

``ver``
    The claim *schema* version. Global to the deployment, compared against a
    constant in code, and bumped when the payload shape changes.
``jtv``
    The per-user token version. Compared against ``User.token_version``, and
    bumped to invalidate every credential a single account holds.
"""

from __future__ import annotations

from typing import Final, NotRequired, TypedDict

# --- Registered, RFC 7519 --------------------------------------------
CLAIM_ISSUER: Final = "iss"
CLAIM_SUBJECT: Final = "sub"
CLAIM_AUDIENCE: Final = "aud"
CLAIM_EXPIRES_AT: Final = "exp"
CLAIM_NOT_BEFORE: Final = "nbf"
CLAIM_ISSUED_AT: Final = "iat"
CLAIM_JWT_ID: Final = "jti"

# --- Token identity --------------------------------------------------
CLAIM_TOKEN_TYPE: Final = "typ"
CLAIM_VERSION: Final = "ver"

# --- Tenancy: the isolation claims -----------------------------------
CLAIM_TENANT_ID: Final = "tid"
CLAIM_SCHEMA: Final = "sch"
CLAIM_ORGANISATION: Final = "org"

# --- Authorisation ---------------------------------------------------
CLAIM_ROLES: Final = "roles"
CLAIM_SCOPES: Final = "scp"

# --- Session ---------------------------------------------------------
CLAIM_SESSION_ID: Final = "sid"
CLAIM_DEVICE_ID: Final = "did"
CLAIM_TOKEN_VERSION: Final = "jtv"
CLAIM_FAMILY: Final = "fam"
CLAIM_GENERATION: Final = "gen"

# --- Authentication context, OIDC ------------------------------------
CLAIM_AUTH_METHODS: Final = "amr"
CLAIM_AUTH_TIME: Final = "auth_time"

# --- Profile ---------------------------------------------------------
CLAIM_EMAIL: Final = "email"
CLAIM_NAME: Final = "name"
CLAIM_IS_STAFF: Final = "staff"

TOKEN_TYPE_ACCESS: Final = "access"
TOKEN_TYPE_REFRESH: Final = "refresh"

# Distinct audiences, so presenting a refresh token as a Bearer credential
# fails at the audience check even before the ``typ`` comparison runs. Two
# independent reasons to reject one confusion.
AUDIENCE_API: Final = "eduremus-api"
AUDIENCE_AUTH: Final = "eduremus-auth"

# What this build mints.
CLAIM_SCHEMA_VERSION: Final = 1

# What this build accepts. During a rolling deploy that adds a claim, both the
# outgoing and incoming versions belong here for at least one maximum refresh
# lifetime -- old and new code run side by side, and tokens minted by either
# must verify against both.
SUPPORTED_CLAIM_VERSIONS: Final[frozenset[int]] = frozenset({1})

# Claims every token carries, whatever its type. PyJWT is asked to require
# these during decode, so a missing one is a decode failure rather than a
# ``None`` that quietly compares equal to nothing.
REQUIRED_COMMON_CLAIMS: Final[tuple[str, ...]] = (
    CLAIM_ISSUER,
    CLAIM_AUDIENCE,
    CLAIM_SUBJECT,
    CLAIM_EXPIRES_AT,
    CLAIM_NOT_BEFORE,
    CLAIM_ISSUED_AT,
    CLAIM_JWT_ID,
    CLAIM_TOKEN_TYPE,
    CLAIM_VERSION,
    CLAIM_TENANT_ID,
    CLAIM_SCHEMA,
    CLAIM_SESSION_ID,
)

# Type-specific claims, checked *after* the type is known rather than during
# decode. PyJWT validates required claims before audience, so requiring these
# up front would report a refresh token presented as an access token as
# "missing jtv" -- true, but far less useful than the audience mismatch that
# actually characterises the mistake.
REQUIRED_ACCESS_CLAIMS: Final[tuple[str, ...]] = (CLAIM_TOKEN_VERSION,)

REQUIRED_REFRESH_CLAIMS: Final[tuple[str, ...]] = (CLAIM_FAMILY, CLAIM_GENERATION)

# The audience each token type is minted with and verified against.
AUDIENCE_BY_TOKEN_TYPE: Final[dict[str, str]] = {
    TOKEN_TYPE_ACCESS: AUDIENCE_API,
    TOKEN_TYPE_REFRESH: AUDIENCE_AUTH,
}

REQUIRED_CLAIMS_BY_TOKEN_TYPE: Final[dict[str, tuple[str, ...]]] = {
    TOKEN_TYPE_ACCESS: REQUIRED_ACCESS_CLAIMS,
    TOKEN_TYPE_REFRESH: REQUIRED_REFRESH_CLAIMS,
}


class AccessTokenClaims(TypedDict):
    """Shape of a v1 access-token payload."""

    iss: str
    aud: list[str]
    sub: str
    exp: int
    nbf: int
    iat: int
    jti: str
    typ: str
    ver: int
    tid: int
    sch: str
    org: str
    roles: list[str]
    scp: str
    sid: str
    did: str
    jtv: int
    amr: list[str]
    auth_time: int
    email: str
    name: str
    staff: bool


class RefreshTokenClaims(TypedDict):
    """Shape of a v1 refresh-token payload.

    Carries no ``roles``, ``scp``, ``email`` or ``name``: those are re-read
    from the database on every rotation, which is what lets a permission
    change take effect within one access-token lifetime instead of persisting
    for the refresh token's full seven days.
    """

    iss: str
    aud: list[str]
    sub: str
    exp: int
    nbf: int
    iat: int
    jti: str
    typ: str
    ver: int
    tid: int
    sch: str
    sid: str
    fam: str
    gen: int
    did: NotRequired[str]
