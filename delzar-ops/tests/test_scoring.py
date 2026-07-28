"""Opportunity scoring: distance weighting, eligibility, caps."""
from datetime import date
from decimal import Decimal

from delzar_ops.watch.scoring import distance_miles, score_opportunity

AS_OF = date(2026, 7, 20)


def opp(**kw):
    base = {
        "place_city": "Claremore", "place_state": "OK",
        "set_aside": "SBA", "naics": "237110",
        "response_deadline": "2026-07-30",
    }
    base.update(kw)
    return base


def test_distance_known_city():
    miles, why = distance_miles("Claremore", "OK")
    assert miles == 28 and "known city" in why


def test_distance_state_fallback():
    miles, why = distance_miles("Nowhereville", "KS")
    assert miles == 240 and "fallback" in why


def test_distance_out_of_region():
    miles, _ = distance_miles("Denver", "CO")
    assert miles == 320


def test_close_beats_far():
    near, _ = score_opportunity(opp(place_city="Tulsa"), AS_OF)
    far, _ = score_opportunity(opp(place_city="Lawton"), AS_OF)
    assert near > far


def test_ineligible_set_aside_capped():
    score, breakdown = score_opportunity(opp(set_aside="SDVOSBC", place_city="Tulsa"), AS_OF)
    assert score <= 10
    assert "ineligible_cap" in breakdown
    assert "INELIGIBLE" in breakdown["set_aside"]["why"]


def test_iee_beats_unrestricted():
    iee, _ = score_opportunity(opp(set_aside="IEE"), AS_OF)
    open_, _ = score_opportunity(opp(set_aside="NONE"), AS_OF)
    assert iee > open_


def test_dollar_band_sweet_spot():
    in_band, b1 = score_opportunity(opp(), AS_OF, estimated_value=Decimal("15000"))
    over, b2 = score_opportunity(opp(), AS_OF, estimated_value=Decimal("500000"))
    assert b1["dollar_band"]["points"] == 15.0
    assert b2["dollar_band"]["points"] == 3.0
    assert in_band > over


def test_passed_deadline_zero_points():
    _, b = score_opportunity(opp(response_deadline="2026-07-01"), AS_OF)
    assert b["deadline"]["points"] == 0.0


def test_breakdown_shows_work():
    _, b = score_opportunity(opp(), AS_OF)
    for section in ("distance", "set_aside", "dollar_band", "deadline", "licensing"):
        assert "points" in b[section] and "why" in b[section]
