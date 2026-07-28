import pytest

from delzar_ops.db import connect


@pytest.fixture
def conn(tmp_path):
    c = connect(tmp_path / "test.db")
    yield c
    c.close()


@pytest.fixture
def contract(conn):
    """An active contract awarded 2026-07-01, started Monday 2026-07-06."""
    conn.execute(
        """INSERT INTO contracts (contract_no, title, amount, award_date, notify_date,
           start_date, place_of_performance, status)
           VALUES ('75H711-26-P-TEST1', 'Test water line replacement', 18500,
                   '2026-07-01', '2026-07-01', '2026-07-06', 'Claremore, OK', 'active')"""
    )
    conn.commit()
    return conn.execute("SELECT * FROM contracts WHERE contract_no = '75H711-26-P-TEST1'").fetchone()


@pytest.fixture
def wage_determination(conn, contract):
    cur = conn.execute(
        "INSERT INTO wage_determinations (contract_id, wd_number) VALUES (?, 'OK20260043')",
        (contract["id"],),
    )
    wd_id = cur.lastrowid
    conn.executemany(
        "INSERT INTO wage_rates (wd_id, classification, base_rate, fringe_rate) VALUES (?,?,?,?)",
        [
            (wd_id, "Laborer: Common", 18.25, 6.10),
            (wd_id, "Power Equipment Operator: Backhoe", 28.50, 9.75),
        ],
    )
    conn.commit()
    return wd_id


@pytest.fixture
def employee(conn):
    conn.execute(
        """INSERT INTO employees (name, default_classification, default_base_rate,
           default_fringe_rate, id_last4, withholding_exemptions)
           VALUES ('Joe Worker', 'Laborer: Common', 20.00, 6.10, '1234', 1)"""
    )
    conn.commit()
    return conn.execute("SELECT * FROM employees WHERE name = 'Joe Worker'").fetchone()
