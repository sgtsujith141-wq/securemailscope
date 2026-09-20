"""Sequence-number projection, including wraparound."""

from __future__ import annotations

import pytest

from securemailscope.network.seqspace import SEQ_MODULUS, SequenceSpace


def test_forward_progress_is_linear() -> None:
    space = SequenceSpace(1000)
    assert space.extend(1000) == 0
    assert space.extend(1010) == 10
    assert space.extend(1500) == 500


def test_retransmission_does_not_drag_the_high_water_mark_back() -> None:
    space = SequenceSpace(1000)
    space.extend(2000)
    assert space.extend(1100) == 100
    # The mark stayed at 2000, so the next forward value is still correct.
    assert space.extend(2100) == 1100


def test_wraparound_is_projected_continuously() -> None:
    space = SequenceSpace(0xFFFFFF00)
    assert space.extend(0xFFFFFF00) == 0
    assert space.extend(0xFFFFFFF0) == 240
    # Crossing 2**32 must continue counting upward, not jump backwards.
    assert space.extend(0x00000010) == 272
    assert space.wraparounds == 1
    assert space.extend(0x00000110) == 528


def test_values_before_the_anchor_project_negative() -> None:
    space = SequenceSpace(1000)
    assert space.project(900) == -100


def test_projection_does_not_advance_the_mark() -> None:
    space = SequenceSpace(1000)
    assert space.project(5000) == 4000
    assert space.extend(1100) == 100


def test_inverse_projection_round_trips() -> None:
    space = SequenceSpace(0xFFFFFF00)
    space.extend(0x00000010)
    assert space.to_sequence(272) == 0x10
    assert space.to_sequence(0) == 0xFFFFFF00


@pytest.mark.parametrize("anchor", [0, 1, 2**31, 2**32 - 1])
def test_anchor_maps_to_zero(anchor: int) -> None:
    assert SequenceSpace(anchor).extend(anchor) == 0
    assert SequenceSpace(anchor).to_sequence(0) == anchor % SEQ_MODULUS
