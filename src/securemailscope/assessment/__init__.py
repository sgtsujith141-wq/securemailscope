"""Evidence-based security rules, explainable scoring, prioritisation and remediation (M4).

STATUS: IMPLEMENTED.

This package consumes the typed forensic observations produced by M1-M3 and
turns them into judgements. It never reparses a capture, never inspects JSON
with a regular expression, and never uses a language model.

The separation it maintains: a *rule outcome* records what a policy concluded,
a *finding* is only ever a FAIL, a *score* summarises evaluable controls while
disclosing its coverage, and a *remediation* is emitted only for a condition
that was actually found.
"""

from .engine import assess_capture
from .policy import DEFAULT_POLICY, AssessmentPolicy

__all__ = ["assess_capture", "AssessmentPolicy", "DEFAULT_POLICY"]
