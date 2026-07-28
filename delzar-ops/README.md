# DELZAR OPS

Federal contracting operations system for **Delzar Solutions LLC**
(UEI TKMXZNCBPS27 · CAGE 9R0K7 · Tulsa, OK · NAICS 237110).

Everything runs on your laptop. No cloud, no subscriptions, no accounts —
one SQLite database file and PDFs in a folder. The only thing that needs
the internet is pulling new solicitations from SAM.gov.

It automates the three things that kill new federal contractors:

1. **COMPLY** — certified payroll (Form WH-347) every week, including the
   zero-work weeks everyone forgets, with wage-determination checking.
2. **WATCH** — daily SAM.gov monitoring, scored and ranked by fit, so you
   never miss a 7-day solicitation window.
3. **BID** — repeatable line-item pricing with the broker / hybrid /
   self-perform comparison on every single estimate.

Plus **CASH** (know your 90-day cash position before you accept work) and
a minimal **INTEL** module (BPA grid, waves, recompetes).

---

## Install (one time, ~5 minutes)

You need Python 3.11 or newer. Check with:

```
python3 --version
```

If that says 3.11 or higher, you're good. Then, from this folder:

```
pip install .
delzar init --seed
```

That's it. `delzar init --seed` creates the database at `~/.delzar/delzar.db`
and loads the materials price list and template rows for competitors and the
BPA grid. **Edit the CSV files in `delzar_ops/seed/data/` with your real
research, then run `delzar init --seed` again** — it updates in place.

All generated PDFs and digests land in `~/.delzar/output/`.

## Get a free SAM.gov API key (one time, ~2 minutes)

1. Log in at https://sam.gov (the same account as your entity registration).
2. Go to your **Account Details** page.
3. Find **API Key**, click to generate, copy it.
4. In your terminal:

```
export SAM_API_KEY=paste-your-key-here
```

To make that permanent, add the same line to the end of `~/.bashrc` (Linux)
or `~/.zshrc` (Mac). Without a key everything still works except live
polling. Public keys get about 10 requests/day; with your entity
registration linked it's 1,000/day. The system uses a handful per day.

---

## Daily routine (2 minutes)

```
delzar status          # one screen: deadlines, contracts, cash, top opportunities
delzar watch poll      # pull today's solicitations, ranked digest
```

Or run `delzar watch daemon` in a terminal you leave open and it polls
itself every morning at 6:30.

Local dashboard (read-only, nice for a second monitor):

```
delzar dashboard       # then open http://127.0.0.1:8765
```

---

## When you WIN a contract — do these in order

```
delzar payroll contract-add 75H711-26-P-0123        # answers a few questions
delzar cash gate "IHS water line job" 18500          # the four-question go/no-go
delzar payroll wd-import 75H711-26-P-0123 --wd-number OK20260043 --rates-file rates.csv
delzar cash instrument-add 75H711-26-P-0123 "irrevocable letter of credit" 18500
delzar comply done payment_protection --contract-no 75H711-26-P-0123
```

`contract-add` automatically creates your deadlines: **payment protection
within 10 days** (FAR 52.228-13 — it will nag you on days 1, 3, 5, 7),
debriefing request, wage-determination posting. `delzar comply calendar`
shows everything due.

The `rates.csv` for `wd-import` is three columns copied off the wage
determination attached to the solicitation:

```
classification,base_rate,fringe_rate
Laborer: Common,18.25,6.10
Power Equipment Operator: Backhoe,28.50,9.75
```

## Weekly payroll (under 5 minutes)

Log hours as they happen (or Friday afternoon):

```
delzar payroll employee-add "Joe Worker"                       # once per person
delzar payroll log 75H711-26-P-0123 "Joe Worker" 2026-07-21 8  # per day worked
delzar payroll generate 75H711-26-P-0123                       # makes the WH-347 PDF
```

**If nobody worked that week, still run `generate`.** It produces the
required zero-activity payroll automatically. This is the single most
common compliance failure and this system makes it a non-event.

If a rate is below the wage determination, generation **warns in red and
tells you exactly why**. Don't submit until it's clean.

Subcontractor payrolls: `delzar payroll sub-expect` / `sub-received` —
missing ones show up on the compliance calendar.

`delzar payroll status` shows any owed weeks on every active contract.

## Bidding (under 30 minutes)

```
delzar bid demo                      # see it work: 200-ft water line, all 3 models
delzar bid template myjob.json       # start an estimate file
# edit myjob.json quantities and prices
delzar bid new --from-file myjob.json --price 14500
delzar bid quote 1 --model hybrid --price 14500     # submittable PDF
delzar bid outcome 1 lost --winning-price 13200     # always record the result
delzar bid stats                     # win rate + delta from winner (after 5 bids)
```

Every estimate shows **broker vs hybrid vs self-perform side by side with
margins**, and the turnkey-vs-day-rate delta — the biggest margin lever
you have. It refuses to export a quote priced below direct cost.

Reminders it enforces: attach the **IEE Representation form (HHSAR
352.226-7)** to every IHS quote, and **never offer a prompt payment
discount** (not evaluated at this office — pure margin giveaway).

## Cash

```
delzar cash set-balance 23000
delzar cash invoice-add 75H711-26-P-0123 12000 --invoiced-date 2026-07-25
delzar cash outflow-add materials 4000 2026-07-22 --contract-no 75H711-26-P-0123
delzar cash project        # 90 days forward, week by week, shows every event
delzar cash aging          # who owes you and how old it is
delzar cash factoring 12000                # advance/fee/net + effective APR
delzar cash discount                       # what taking 2/10 net 30 is worth (~37%/yr)
```

Before accepting anything over $50,000, `delzar cash gate` requires four
explicit yeses (crew, materials float, payment protection in 10 days,
payroll capacity). Anything less and it recommends declining — and logs
the decision either way.

## Intel

```
delzar intel grid          # BPA holders by field office and service type
delzar intel waves         # establishment waves + predicted next window
delzar intel recompetes    # expirations, soonest first
delzar intel thin-cells    # categories with the fewest bidders
delzar intel awards-pull "Competitor Name"   # pull award history from USAspending
```

## Useful anytime

```
delzar comply calendar       # everything due, most urgent first
delzar comply dig-date       # earliest lawful dig after calling OKIE811 (dial 811)
delzar comply thresholds     # every regulatory number, citation, last-verified date
delzar watch piid 75H71124F0007   # decode: F = flowed to an agreement holder
delzar watch why NOTICE-ID   # why an opportunity scored what it scored
```

---

## Where things live

| Thing | Location |
|---|---|
| Database | `~/.delzar/delzar.db` (set `DELZAR_HOME` to move it) |
| PDFs & digests | `~/.delzar/output/` |
| Regulatory thresholds | `delzar_ops/regulatory.json` — every value has a citation and a **last verified** date. When a threshold changes, update it there and nowhere else. |
| Seed data (edit me) | `delzar_ops/seed/data/*.csv` |

**Back up `~/.delzar` regularly** — a copy to a USB stick is fine. It's
your payroll record (3-year retention requirement) and your bid history.

## Notes and limits

- **Payroll week ends Saturday.** Generate Friday or Monday, submit weekly.
- **OK811 dig dates** count Mon–Fri business days but not state holidays —
  around a holiday, call a day early.
- **DOL wage rates**: there is no free wage-rates API, so you copy rates
  from the WD attached to each solicitation into a 3-column CSV (sample
  above). The full WD text can be stored too (`--raw-file`).
- **Email digest**: the daily digest is written to `~/.delzar/output/` as
  a text file (no email service dependency). Attach or read it there.
- Withholding: FICA (7.65%) is computed automatically; federal income tax
  withholding varies per person — enter it per employee when it matters.
- This system explains its numbers, but it is not a lawyer or an
  accountant. When real money rides on a threshold, verify the citation
  shown by `delzar comply thresholds`.

## Running the tests

```
pip install .[dev]
pytest delzar-ops/tests -q
```

Every calculation touching money or compliance is covered.
