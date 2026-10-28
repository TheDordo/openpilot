"""Night Star: Force turn desires and Turn Signal Guidance live together; a route's turn wins, then Force, then guidance."""
from openpilot.cereal import log
from openpilot.common.constants import CV
from openpilot.starpilot.navigation.intent import TurnIntent
from openpilot.starpilot.navigation.tests.test_signal_guidance import NOW, case  # noqa: F401  (the guidance fixture)

FORCED_MPS = 8.


def pick(owner, sm, forced=FORCED_MPS, desire=log.Desire.none, model_stop=False):
  return owner.select(sm, NOW, desire, supported=True, model_stop=model_stop, forced_turn_speed_mps=forced)


def test_force_turn_desires_off_leaves_guidance_alone(case):  # noqa: F811
  params, cp, sm = case
  owner = TurnIntent(params, cp)
  assert pick(owner, sm, forced=None) == log.Desire.turnLeft and not owner.forced_active
  sm['carState'].leftBlindspot = True
  assert pick(owner, sm, forced=None) == log.Desire.none


def test_force_turn_desires_covers_what_guidance_withholds(case):  # noqa: F811
  params, cp, sm = case
  owner = TurnIntent(params, cp)
  sm['carState'].leftBlindspot = True                   # guidance vetoes on the blindspot
  assert pick(owner, sm) == log.Desire.turnLeft and owner.forced_active
  sm['carState'].leftBlindspot = False
  sm['carState'].vEgo = 5.
  assert pick(owner, sm, model_stop=True) == log.Desire.turnLeft   # guidance latches its stop hold; Force does not
  assert pick(owner, sm) == log.Desire.turnLeft and owner.forced_active


def test_guidance_takes_over_above_the_force_speed_and_below_20_mph(case):  # noqa: F811
  params, cp, sm = case
  owner = TurnIntent(params, cp)
  sm['carState'].vEgo = FORCED_MPS + 0.5
  assert FORCED_MPS + 0.5 < 20 * CV.MPH_TO_MS
  assert pick(owner, sm) == log.Desire.turnLeft and not owner.forced_active
  sm['carState'].vEgo = 20 * CV.MPH_TO_MS + 0.5
  assert pick(owner, sm) == log.Desire.none


def test_force_turn_desires_overrides_a_lane_change_and_guidance_does_not(case):  # noqa: F811
  params, cp, sm = case
  owner = TurnIntent(params, cp)
  assert pick(owner, sm, forced=None, desire=log.Desire.laneChangeLeft) == log.Desire.laneChangeLeft
  assert pick(owner, sm, desire=log.Desire.laneChangeLeft) == log.Desire.turnLeft and owner.forced_active


def test_force_drops_at_a_standstill(case):  # noqa: F811
  params, cp, sm = case
  owner = TurnIntent(params, cp)
  sm['carState'].standstill, sm['carState'].vEgo = True, 0.
  assert pick(owner, sm) == log.Desire.none and not owner.forced_active
