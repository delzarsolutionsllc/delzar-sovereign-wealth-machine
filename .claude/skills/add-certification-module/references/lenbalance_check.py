"""Answer-length rank check for single-answer questions. Usage: python lenbalance_check.py file.json [...]
Rank of the correct answer among the 4 options by character length (1 = longest). Ties count as 'tie'.
Targets per file: rank1 (uniquely longest) 18-30 %, rank2 <= 32 %, rank3+rank4 >= 30 %."""
import json, sys, collections
ok_all = True
for f in sys.argv[1:]:
    c = collections.Counter(); n = 0; second = []
    for q in json.load(open(f))["questions"]:
        if q.get("type", "single") != "single": continue
        L = [len(x) for x in q["choices"]]; a = len(q["answer"]); n += 1
        if L.count(a) > 1: c["tie"] += 1; continue
        r = sorted(L, reverse=True).index(a) + 1; c[r] += 1
        if r == 2: second.append(q["id"])
    p = {k: round(100 * v / n) for k, v in c.items()}
    ok = 18 <= p.get(1, 0) <= 30 and p.get(2, 0) <= 32 and p.get(3, 0) + p.get(4, 0) >= 30
    ok_all &= ok
    print(f"{f.split('/')[-1]}: n={n} rank1={p.get(1,0)}% rank2={p.get(2,0)}% rank3={p.get(3,0)}% rank4={p.get(4,0)}% tie={p.get('tie',0)}% -> {'OK' if ok else 'NEEDS WORK'}")
    if not ok: print("  rank-2 ids:", " ".join(second))
sys.exit(0 if ok_all else 1)
