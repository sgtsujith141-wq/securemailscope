"""Filters that decide which bytes from a capture may become report text.

The rule: **a string only reaches a report if it was matched against a closed
set of protocol keywords, or its shape proves it cannot be a secret.**

Shape alone is not enough for command verbs.  A base64 SASL payload such as
``dXNlcgBteXBhc3N3b3Jk`` is pure alphanumeric and short, so a "letters and
digits, at most 20 characters" filter would happily pass it into a report.
Command verbs and SASL mechanism names are therefore matched against
allowlists; anything unrecognised is reported as *unrecognised*, never quoted.

Capability keywords keep a shape filter, but their real protection is
positional: they are only ever extracted from a server reply line that a
parser has already identified as a capability advertisement (an SMTP ``250-``
extension line, an IMAP ``* CAPABILITY`` response, a POP3 ``CAPA`` body).
Client-supplied bytes never reach that code path.

Every function returns ``None`` when its input fails.  There is deliberately no
"fall back to the raw bytes" path anywhere in this module.
"""

from __future__ import annotations

import string
from typing import Final

__all__ = [
    "safe_verb",
    "safe_tag",
    "safe_capability",
    "safe_mechanism",
    "safe_reply_code",
    "SMTP_VERBS",
    "IMAP_VERBS",
    "POP3_VERBS",
    "SASL_MECHANISMS",
    "MAX_CAPABILITIES",
]

#: Cap on capability keywords retained per advertisement.
MAX_CAPABILITIES: Final = 64

#: RFC 5321 commands plus the widely deployed extensions we care about.
SMTP_VERBS: Final[frozenset[str]] = frozenset(
    {
        "HELO", "EHLO", "MAIL", "RCPT", "DATA", "RSET", "VRFY", "EXPN",
        "HELP", "NOOP", "QUIT", "STARTTLS", "AUTH", "BDAT", "ETRN", "XCLIENT",
    }
)

#: RFC 9051 commands plus RFC 2595 STARTTLS and common extensions.
IMAP_VERBS: Final[frozenset[str]] = frozenset(
    {
        "CAPABILITY", "NOOP", "LOGOUT", "STARTTLS", "AUTHENTICATE", "LOGIN",
        "SELECT", "EXAMINE", "CREATE", "DELETE", "RENAME", "SUBSCRIBE",
        "UNSUBSCRIBE", "LIST", "LSUB", "STATUS", "APPEND", "CHECK", "CLOSE",
        "EXPUNGE", "SEARCH", "FETCH", "STORE", "COPY", "MOVE", "UID",
        "ENABLE", "IDLE", "NAMESPACE", "UNSELECT", "COMPRESS", "ID", "SORT",
        "THREAD", "GETQUOTA", "SETQUOTA", "GETQUOTAROOT", "DONE",
    }
)

#: RFC 1939 commands plus RFC 2449 CAPA and RFC 2595 STLS.
POP3_VERBS: Final[frozenset[str]] = frozenset(
    {
        "USER", "PASS", "APOP", "QUIT", "STAT", "LIST", "RETR", "DELE",
        "NOOP", "RSET", "TOP", "UIDL", "CAPA", "STLS", "AUTH",
    }
)

#: SASL mechanism names we will name in a report. Anything else is reported
#: as an unrecognised mechanism rather than quoted, because an unrecognised
#: token in mechanism position may be a credential.
SASL_MECHANISMS: Final[frozenset[str]] = frozenset(
    {
        "PLAIN", "LOGIN", "CRAM-MD5", "DIGEST-MD5", "EXTERNAL", "ANONYMOUS",
        "GSSAPI", "NTLM", "XOAUTH2", "OAUTHBEARER", "SCRAM-SHA-1",
        "SCRAM-SHA-1-PLUS", "SCRAM-SHA-256", "SCRAM-SHA-256-PLUS",
    }
)

_TAG_ALPHABET: Final = frozenset(string.ascii_letters + string.digits + "._-")
_CAPABILITY_ALPHABET: Final = frozenset(string.ascii_letters + string.digits + "=+._-")


def _ascii(raw: bytes, max_length: int) -> str | None:
    if not raw or len(raw) > max_length:
        return None
    try:
        return raw.decode("ascii")
    except UnicodeDecodeError:
        return None


def safe_verb(raw: bytes, allowed: frozenset[str]) -> str | None:
    """A command keyword, matched against a closed protocol vocabulary.

    Returns ``None`` for anything not in ``allowed`` -- including a token that
    merely *looks* like a verb. Callers report the absence, not the token.
    """
    text = _ascii(raw, 20)
    if text is None:
        return None
    upper = text.upper()
    return upper if upper in allowed else None


def safe_tag(raw: bytes) -> str | None:
    """An IMAP client tag such as ``a001``.

    Tags are client-chosen, so this is a shape filter rather than an
    allowlist. A tag sits in a fixed grammatical position at the start of a
    command line and is bounded to 32 characters.
    """
    text = _ascii(raw, 32)
    if text is None or any(character not in _TAG_ALPHABET for character in text):
        return None
    return text


def safe_capability(raw: bytes) -> str | None:
    """A capability keyword such as ``STARTTLS`` or ``AUTH=PLAIN``.

    Only ever called on tokens taken from a positively identified capability
    advertisement in a *server* reply.
    """
    text = _ascii(raw, 32)
    if text is None or any(character not in _CAPABILITY_ALPHABET for character in text):
        return None
    return text.upper()


def safe_mechanism(raw: bytes) -> str | None:
    """A SASL mechanism name, matched against a closed set.

    The mechanism *name* is safe. The initial response that may follow it on
    the same line is a credential and is never passed to this function.
    """
    text = _ascii(raw, 24)
    if text is None:
        return None
    upper = text.upper()
    return upper if upper in SASL_MECHANISMS else None


def safe_reply_code(raw: bytes) -> str | None:
    """A three-digit SMTP reply code."""
    if len(raw) != 3 or not raw.isdigit():
        return None
    return raw.decode("ascii")
