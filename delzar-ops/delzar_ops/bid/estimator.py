"""LPTA bid estimator: line-item cost buildup with three delivery models.

Models compared side by side on every estimate:
- BROKER:       subcontractor turnkey price (materials + labor included)
- HYBRID:       you buy materials, sub provides crew at a day rate
- SELF-PERFORM: your own labor at Davis-Bacon rates + equipment

The broker-vs-day-rate delta is the largest margin lever in this
business, so it is computed and displayed on every estimate.

Cost stack (identical for all three models):
    direct cost
  + contingency (rock risk, user %)      = subtotal
  + overhead (user %)                    = cost total
  + profit (user %)                      = suggested price

All money math is Decimal, rounded to cents. Every model carries an
itemized breakdown for the explain-it-to-a-CO requirement.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from decimal import ROUND_HALF_UP, Decimal

CENTS = Decimal("0.01")


def D(x) -> Decimal:
    return Decimal(str(x))


def cents(x: Decimal) -> Decimal:
    return x.quantize(CENTS, rounding=ROUND_HALF_UP)


@dataclass
class LineItem:
    description: str
    qty: Decimal
    unit: str
    unit_cost: Decimal

    @property
    def total(self) -> Decimal:
        return cents(self.qty * self.unit_cost)


@dataclass
class LaborItem:
    classification: str
    hours: Decimal
    base_rate: Decimal
    fringe_rate: Decimal

    @property
    def total(self) -> Decimal:
        return cents(self.hours * (self.base_rate + self.fringe_rate))


@dataclass
class EquipmentItem:
    name: str
    day_rate: Decimal
    days: Decimal
    owned: bool = False   # owned equipment still carries its day rate as internal cost

    @property
    def total(self) -> Decimal:
        return cents(self.day_rate * self.days)


@dataclass
class EstimateInput:
    title: str
    solicitation_no: str = ""
    materials: list[LineItem] = field(default_factory=list)
    labor: list[LaborItem] = field(default_factory=list)               # self-perform crew
    equipment: list[EquipmentItem] = field(default_factory=list)       # self-perform / hybrid
    sub_turnkey_price: Decimal = Decimal("0")                          # broker model
    sub_day_rate: Decimal = Decimal("0")                               # hybrid model
    sub_days: Decimal = Decimal("0")
    mobilization_miles: Decimal = Decimal("0")                         # one-way miles
    mobilization_rate: Decimal = Decimal("2.50")                       # $/mile loaded, round trip applied
    mobilization_trips: Decimal = Decimal("1")
    permits_fees: list[LineItem] = field(default_factory=list)         # permits, tap fees, restoration
    payment_protection_cost: Decimal = Decimal("0")                    # e.g. ILC issuance fee
    contingency_pct: Decimal = Decimal("0.10")                         # rock risk
    overhead_pct: Decimal = Decimal("0.10")
    profit_pct: Decimal = Decimal("0.10")

    @property
    def materials_total(self) -> Decimal:
        return cents(sum((m.total for m in self.materials), Decimal("0")))

    @property
    def labor_total(self) -> Decimal:
        return cents(sum((l.total for l in self.labor), Decimal("0")))

    @property
    def equipment_total(self) -> Decimal:
        return cents(sum((e.total for e in self.equipment), Decimal("0")))

    @property
    def mobilization_total(self) -> Decimal:
        # round trip: miles x 2 x rate x trips
        return cents(self.mobilization_miles * 2 * self.mobilization_rate * self.mobilization_trips)

    @property
    def permits_total(self) -> Decimal:
        return cents(sum((p.total for p in self.permits_fees), Decimal("0")))


@dataclass
class ModelResult:
    model: str                      # broker | hybrid | self
    components: dict[str, Decimal]  # itemized direct-cost breakdown
    direct_cost: Decimal
    contingency: Decimal
    overhead: Decimal
    cost_total: Decimal
    suggested_price: Decimal
    margin_at_suggested: Decimal    # fraction of price
    explain: list[str]

    def margin_at(self, bid_price: Decimal) -> Decimal:
        if bid_price == 0:
            return Decimal("0")
        return ((bid_price - self.cost_total) / bid_price).quantize(Decimal("0.0001"))

    def below_direct_cost(self, bid_price: Decimal) -> bool:
        return bid_price < self.direct_cost


def _stack(model: str, components: dict[str, Decimal], est: EstimateInput) -> ModelResult:
    direct = cents(sum(components.values(), Decimal("0")))
    contingency = cents(direct * est.contingency_pct)
    subtotal = direct + contingency
    overhead = cents(subtotal * est.overhead_pct)
    cost_total = subtotal + overhead
    price = cents(cost_total * (1 + est.profit_pct))
    margin = ((price - cost_total) / price).quantize(Decimal("0.0001")) if price else Decimal("0")
    explain = [f"{k}: ${v:,.2f}" for k, v in components.items() if v]
    explain += [
        f"direct cost = ${direct:,.2f}",
        f"contingency {est.contingency_pct:.0%} (rock risk) = ${contingency:,.2f}",
        f"overhead {est.overhead_pct:.0%} = ${overhead:,.2f}",
        f"cost total = ${cost_total:,.2f}",
        f"profit {est.profit_pct:.0%} -> suggested price ${price:,.2f}",
    ]
    return ModelResult(model, components, direct, contingency, overhead,
                       cost_total, price, margin, explain)


def run_models(est: EstimateInput) -> dict[str, ModelResult]:
    common = {
        "mobilization": est.mobilization_total,
        "permits/tap/restoration": est.permits_total,
        "payment protection": est.payment_protection_cost,
    }
    broker = _stack("broker", {
        "subcontractor (turnkey)": cents(est.sub_turnkey_price),
        **common,
    }, est)
    hybrid = _stack("hybrid", {
        "materials": est.materials_total,
        "subcontractor (day rate)": cents(est.sub_day_rate * est.sub_days),
        "equipment": est.equipment_total,
        **common,
    }, est)
    self_ = _stack("self", {
        "materials": est.materials_total,
        "labor (Davis-Bacon)": est.labor_total,
        "equipment": est.equipment_total,
        **common,
    }, est)
    return {"broker": broker, "hybrid": hybrid, "self": self_}


def turnkey_vs_dayrate_delta(est: EstimateInput) -> dict:
    """The margin lever: what the turnkey premium costs vs. day-rate + own materials."""
    turnkey = cents(est.sub_turnkey_price)
    dayrate_equiv = cents(est.sub_day_rate * est.sub_days + est.materials_total)
    delta = cents(turnkey - dayrate_equiv)
    return {
        "turnkey": turnkey,
        "dayrate_plus_materials": dayrate_equiv,
        "delta": delta,
        "explain": (
            f"Turnkey ${turnkey:,.2f} vs day-rate ${cents(est.sub_day_rate * est.sub_days):,.2f} "
            f"+ your materials ${est.materials_total:,.2f} = ${dayrate_equiv:,.2f}. "
            f"Delta ${delta:,.2f} is margin you keep (or give away) by choosing the model."
        ),
    }


def win_rate_report(bids: list[dict]) -> dict | None:
    """Win rate and average delta from winner. Needs 5+ decided bids."""
    decided = [b for b in bids if b["outcome"] in ("won", "lost")]
    if len(decided) < 5:
        return None
    won = [b for b in decided if b["outcome"] == "won"]
    deltas = []
    for b in decided:
        if b["outcome"] == "lost" and b.get("winning_price") and b.get("bid_price"):
            wp, bp = D(b["winning_price"]), D(b["bid_price"])
            if wp > 0:
                deltas.append((bp - wp) / wp)
    return {
        "decided": len(decided),
        "won": len(won),
        "win_rate": round(len(won) / len(decided), 3),
        "avg_delta_from_winner": (
            float(sum(deltas) / len(deltas)) if deltas else None
        ),
    }


def demo_estimate() -> EstimateInput:
    """Acceptance-criteria demo: 200-foot 1-inch water service line.

    Quantities are realistic; unit costs come from the seed price list
    and MUST be re-verified against current supplier quotes before use.
    """
    return EstimateInput(
        title="200 LF 1-in water service line replacement (demo)",
        solicitation_no="DEMO-0001",
        materials=[
            LineItem("1-in CTS SDR-9 HDPE (poly) pipe", D(220), "LF", D("1.85")),
            LineItem("1-in brass corp stop", D(1), "EA", D("68")),
            LineItem("1-in brass curb stop + box", D(1), "EA", D("125")),
            LineItem("Brass fittings / couplings", D(4), "EA", D("32")),
            LineItem("Bedding sand", D(6), "TON", D("28")),
        ],
        labor=[
            LaborItem("Power Equipment Operator (Backhoe)", D(16), D("28.50"), D("9.75")),
            LaborItem("Laborer (Common)", D(24), D("18.25"), D("6.10")),
        ],
        equipment=[
            EquipmentItem("Mini excavator (rental)", D("385"), D(2)),
            EquipmentItem("Trench safety / shoring", D("95"), D(2)),
        ],
        sub_turnkey_price=D("7800"),
        sub_day_rate=D("1900"),
        sub_days=D(2),
        mobilization_miles=D(45),
        mobilization_rate=D("2.50"),
        mobilization_trips=D(2),
        permits_fees=[
            LineItem("OKIE811 locate / permit misc", D(1), "LS", D("150")),
            LineItem("Surface restoration (sod/gravel)", D(1), "LS", D("400")),
        ],
        payment_protection_cost=D("250"),
        contingency_pct=D("0.10"),
        overhead_pct=D("0.10"),
        profit_pct=D("0.10"),
    )
