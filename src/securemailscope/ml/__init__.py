"""ML-assisted analysis.

STATUS: NOT IMPLEMENTED (planned for M6).

Constraints fixed now so the later implementation cannot drift: models run
locally with scikit-learn, are trained on locally generated or explicitly
provided data, and never contact a network service.  ML output is advisory and
is always labelled INFERRED -- it never upgrades an observation's status and
never replaces the deterministic forensic engine, which must keep working with
the ML extra uninstalled.
"""
