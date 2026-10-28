import json
import os
import tempfile
from dataclasses import replace
from types import SimpleNamespace

import pytest

from openpilot.common.constants import CV
from openpilot.starpilot.lateral.lane_change_preferences import LaneChangePolicy, LiveLaneChangePolicy, decode, to_value


def sgsp_v5(guidance=True, **extra):
  """SGSP's version 5: turnSignalGuidance, no Force turn desires."""
  return {**to_value(LaneChangePolicy()), "version": 5, "turnSignalGuidance": guidance, **extra}


def ours_v5(turn=True, speed=6.7):
  """The shape Force turn desires wrote before it shared a document with Turn Signal Guidance."""
  value = {key: item for key, item in sgsp_v5().items() if key != "turnSignalGuidance"}
  return {**value, "turnDesires": turn, "turnDesireSpeedMps": speed}


def test_turn_desires_roundtrip_and_older_documents_keep_them_off():
  policy = replace(LaneChangePolicy(), turn_desires=True, turn_desire_speed_mps=12 * CV.MPH_TO_MS)
  raw = json.dumps(to_value(policy)).encode()
  assert json.loads(raw)["version"] == 6
  assert decode(raw) == policy
  default = to_value(LaneChangePolicy())
  assert default["version"] == 5 and "turnDesires" not in default and default["turnSignalGuidance"] is True
  assert decode(json.dumps(default).encode()) == LaneChangePolicy()
  turned_off = to_value(replace(policy, turn_desires=False))
  assert turned_off["version"] == 6 and decode(json.dumps(turned_off).encode()).turn_desire_speed_mps == 12 * CV.MPH_TO_MS
  assert not LaneChangePolicy().turn_desires
  assert LaneChangePolicy().turn_desire_speed_mps == 15 * CV.MPH_TO_MS


def test_both_settings_live_in_one_document():
  policy = replace(LaneChangePolicy(), turn_signal_guidance=False, turn_desires=True)
  assert decode(json.dumps(to_value(policy)).encode()) == policy


def test_turn_desire_document_rejects_bad_values():
  good = to_value(replace(LaneChangePolicy(), turn_desires=True))
  for field, value in (("turnDesires", 1), ("turnDesireSpeedMps", 4 * CV.MPH_TO_MS), ("turnDesireSpeedMps", 21 * CV.MPH_TO_MS),
                       ("turnDesireSpeedMps", "15"), ("turnSignalGuidance", 1)):
    assert decode(json.dumps(good | {field: value}).encode()) is None
  for field in ("turnDesireSpeedMps", "turnSignalGuidance", "turnDesires"):
    missing = dict(good)
    del missing[field]
    assert decode(json.dumps(missing).encode()) is None


@pytest.mark.parametrize("turn", (True, False))
def test_our_earlier_version_5_document_still_reads(turn):
  policy = decode(json.dumps(ours_v5(turn)).encode())
  assert policy is not None and policy.turn_desires is turn and policy.turn_desire_speed_mps == 6.7
  assert policy.turn_signal_guidance and policy.enabled


@pytest.mark.parametrize("guidance", (True, False))
def test_sgsp_version_5_document_reads_with_force_turn_desires_off(guidance):
  policy = decode(json.dumps(sgsp_v5(guidance)).encode())
  assert policy is not None and policy.turn_signal_guidance is guidance and not policy.turn_desires


@pytest.mark.parametrize("make", (lambda: sgsp_v5(), lambda: ours_v5(),
                                  lambda: to_value(replace(LaneChangePolicy(), turn_desires=True))))
def test_no_saved_shape_turns_lane_change_assist_off(make):
  with tempfile.TemporaryDirectory() as root:
    path = os.path.join(root, "LaneChangePreferences")
    raw = json.dumps(make()).encode()
    with open(path, "wb") as handle:
      handle.write(raw)
    live = LiveLaneChangePolicy(SimpleNamespace(get_param_path=lambda key: path))
    assert live.requested.enabled
    with open(path, "rb") as handle:
      assert handle.read() == raw  # not rewritten on read


def test_other_shapes_stay_rejected():
  for bad in (sgsp_v5(1), sgsp_v5(bogus=1), {**sgsp_v5(), "turnDesires": True}, {**ours_v5(), "turnSignalGuidance": True},
              {**ours_v5(), "turnDesireSpeedMps": float("inf")}, {**ours_v5(), "turnDesireSpeedMps": True},
              {**ours_v5(), "bogus": 1}):
    assert decode(json.dumps(bad).encode()) is None
  missing = sgsp_v5()
  del missing["turnSignalGuidance"]
  assert decode(json.dumps(missing).encode()) is None


def test_lane_change_wire_carries_the_turn_desire_and_old_frames_read_none():
  from openpilot.starpilot.lateral.lane_change_status_wire import Direction, LaneChangeStatus, Phase, decode, encode
  status = LaneChangeStatus("s", 3, 9, 10, 20, 30, Phase.MANUAL_REQUIRED, Direction.NONE, False, True, Direction.LEFT)
  assert decode(encode(status)) == status
  old = LaneChangeStatus("s", 3, 9, 10, 20, 30, Phase.MANUAL_REQUIRED, Direction.RIGHT, False, True)
  assert decode(encode(old)).turn_direction == Direction.NONE


def test_turn_desire_speed_takes_sunnypilots_range():
  for mph in (5, 12, 15, 20):
    raw = json.dumps(to_value(replace(LaneChangePolicy(), turn_desires=True, turn_desire_speed_mps=mph * CV.MPH_TO_MS))).encode()
    assert decode(raw).turn_desire_speed_mps == mph * CV.MPH_TO_MS
