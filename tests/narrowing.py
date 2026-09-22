"""Type-narrowing helpers for the test suite.

Many values the engine and the database return are legitimately optional: an
analysis may have no assessment block, ``Session.get`` may find no row, a
capture may carry no ML result. The tests that touch them always operate in a
state where the value is present, so these helpers assert that and hand back a
narrowed type.

The point is not to satisfy the type checker. It is that a test which dies with
``AttributeError: 'NoneType' object has no attribute 'stored_path'`` tells you
nothing, while one that dies with ``expected a stored capture row, found None``
tells you what the code believed and what was actually true.
"""

from __future__ import annotations

from typing import TypeVar

T = TypeVar("T")

__all__ = ["present"]


def present(value: T | None, what: str = "value") -> T:
    """Return ``value``, asserting it is not ``None``."""
    assert value is not None, f"expected {what}, found None"
    return value
