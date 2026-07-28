"""Estimator: three-model cost stacks, margins, below-cost flag,
turnkey-vs-day-rate delta, win-rate reporting."""
from decimal import Decimal

from delzar_ops.bid.estimator import (
    D,
    EquipmentItem,
    EstimateInput,
    LaborItem,
    LineItem,
    demo_estimate,
    run_models,
    turnkey_vs_dayrate_delta,
    win_rate_report,
)


def simple_estimate() -> EstimateInput:
    """Round numbers so expected values are hand-checkable."""
    return EstimateInput(
        title="test",
        materials=[LineItem("pipe", D(100), "LF", D("2.00"))],          # 200
        labor=[LaborItem("Laborer", D(10), D("20.00"), D("5.00"))],     # 250
        equipment=[EquipmentItem("mini-ex", D("300"), D(1))],           # 300
        sub_turnkey_price=D("2000"),
        sub_day_rate=D("800"),
        sub_days=D(1),                                                   # 800
        mobilization_miles=D(10), mobilization_rate=D("2.00"), mobilization_trips=D(1),  # 10*2*2 = 40
        permits_fees=[LineItem("permit", D(1), "LS", D("60"))],         # 60
        payment_protection_cost=D("100"),
        contingency_pct=D("0.10"), overhead_pct=D("0.10"), profit_pct=D("0.10"),
    )


def test_component_totals():
    est = simple_estimate()
    assert est.materials_total == Decimal("200.00")
    assert est.labor_total == Decimal("250.00")
    assert est.equipment_total == Decimal("300.00")
    assert est.mobilization_total == Decimal("40.00")   # 10 mi x 2 (round trip) x $2 x 1 trip
    assert est.permits_total == Decimal("60.00")


def test_three_models_direct_costs():
    models = run_models(simple_estimate())
    # broker: 2000 turnkey + 40 mob + 60 permits + 100 protection = 2200
    assert models["broker"].direct_cost == Decimal("2200.00")
    # hybrid: 200 mat + 800 sub day + 300 equip + 200 common = 1500
    assert models["hybrid"].direct_cost == Decimal("1500.00")
    # self: 200 mat + 250 labor + 300 equip + 200 common = 950
    assert models["self"].direct_cost == Decimal("950.00")


def test_cost_stack_and_margin():
    m = run_models(simple_estimate())["self"]
    # 950 direct + 10% contingency (95) = 1045; +10% overhead (104.50) = 1149.50
    assert m.contingency == Decimal("95.00")
    assert m.overhead == Decimal("104.50")
    assert m.cost_total == Decimal("1149.50")
    # +10% profit = 1264.45
    assert m.suggested_price == Decimal("1264.45")
    # margin at suggested = profit/(price) = 114.95/1264.45 ~ 9.09%
    assert m.margin_at_suggested == Decimal("0.0909")


def test_below_direct_cost_flag():
    m = run_models(simple_estimate())["hybrid"]
    assert m.below_direct_cost(Decimal("1499"))
    assert not m.below_direct_cost(Decimal("1500"))


def test_margin_at_price():
    m = run_models(simple_estimate())["self"]
    assert m.margin_at(Decimal("1149.50")) == Decimal("0.0000")
    assert m.margin_at(Decimal("2299")) > Decimal("0.49")


def test_turnkey_vs_dayrate_delta():
    d = turnkey_vs_dayrate_delta(simple_estimate())
    # turnkey 2000 vs (800 day rate + 200 materials) = 1000 -> delta 1000
    assert d["turnkey"] == Decimal("2000.00")
    assert d["dayrate_plus_materials"] == Decimal("1000.00")
    assert d["delta"] == Decimal("1000.00")


def test_demo_estimate_produces_all_models():
    models = run_models(demo_estimate())
    assert set(models) == {"broker", "hybrid", "self"}
    for m in models.values():
        assert m.suggested_price > m.cost_total > m.direct_cost > 0


def test_win_rate_needs_five_decided():
    bids = [{"outcome": "won", "bid_price": 100, "winning_price": None}] * 4
    assert win_rate_report(bids) is None


def test_win_rate_report():
    bids = (
        [{"outcome": "won", "bid_price": 10000, "winning_price": None}] * 2
        + [{"outcome": "lost", "bid_price": 11000, "winning_price": 10000}] * 3
        + [{"outcome": "pending", "bid_price": 5000, "winning_price": None}]
    )
    rep = win_rate_report(bids)
    assert rep["decided"] == 5
    assert rep["win_rate"] == 0.4
    assert abs(rep["avg_delta_from_winner"] - 0.10) < 1e-9
