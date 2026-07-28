-- DELZAR OPS initial schema

-- ============ CONTRACTS & COMPLY ============

CREATE TABLE contracts (
    id INTEGER PRIMARY KEY,
    contract_no TEXT NOT NULL UNIQUE,       -- the PIID
    title TEXT NOT NULL,
    agency TEXT,
    office TEXT,
    place_of_performance TEXT,
    amount REAL NOT NULL DEFAULT 0,
    award_date TEXT,                        -- ISO date
    notify_date TEXT,                       -- date operator learned of award
    start_date TEXT,
    completion_date TEXT,                   -- actual completion (ends weekly payroll duty)
    status TEXT NOT NULL DEFAULT 'active',  -- active | completed | declined
    notes TEXT,
    created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE wage_determinations (
    id INTEGER PRIMARY KEY,
    contract_id INTEGER REFERENCES contracts(id),
    wd_number TEXT NOT NULL,                -- e.g. OK20240043
    mod_number TEXT,
    imported_at TEXT DEFAULT (datetime('now')),
    source TEXT,                            -- filename / 'manual entry'
    raw_text TEXT
);

CREATE TABLE wage_rates (
    id INTEGER PRIMARY KEY,
    wd_id INTEGER NOT NULL REFERENCES wage_determinations(id),
    classification TEXT NOT NULL,           -- e.g. 'Laborer: Common', 'Power Equipment Operator: Backhoe'
    base_rate REAL NOT NULL,
    fringe_rate REAL NOT NULL DEFAULT 0
);

CREATE TABLE employees (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    address TEXT,
    id_last4 TEXT,                          -- last 4 of SSN for WH-347 column 1
    default_classification TEXT,
    default_base_rate REAL,
    default_fringe_rate REAL DEFAULT 0,
    withholding_exemptions INTEGER DEFAULT 0,
    active INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE time_entries (
    id INTEGER PRIMARY KEY,
    contract_id INTEGER NOT NULL REFERENCES contracts(id),
    employee_id INTEGER NOT NULL REFERENCES employees(id),
    work_date TEXT NOT NULL,                -- ISO date
    hours REAL NOT NULL,
    classification TEXT,                    -- overrides employee default if set
    base_rate REAL,                         -- overrides
    fringe_rate REAL,                       -- overrides
    UNIQUE (contract_id, employee_id, work_date, classification)
);

CREATE TABLE payrolls (
    id INTEGER PRIMARY KEY,
    contract_id INTEGER NOT NULL REFERENCES contracts(id),
    payroll_number INTEGER NOT NULL,
    week_ending TEXT NOT NULL,              -- ISO date (a Saturday by convention)
    is_zero_activity INTEGER NOT NULL DEFAULT 0,
    is_final INTEGER NOT NULL DEFAULT 0,
    pdf_path TEXT,
    generated_at TEXT DEFAULT (datetime('now')),
    UNIQUE (contract_id, week_ending)
);

CREATE TABLE payroll_lines (
    id INTEGER PRIMARY KEY,
    payroll_id INTEGER NOT NULL REFERENCES payrolls(id),
    employee_name TEXT NOT NULL,
    id_last4 TEXT,
    withholding_exemptions INTEGER DEFAULT 0,
    classification TEXT NOT NULL,
    day_hours TEXT NOT NULL,                -- JSON [sun..sat] straight-time hours
    day_ot_hours TEXT NOT NULL DEFAULT '[0,0,0,0,0,0,0]',
    base_rate REAL NOT NULL,
    fringe_rate REAL NOT NULL DEFAULT 0,
    gross REAL NOT NULL,
    fica REAL NOT NULL DEFAULT 0,
    fed_withholding REAL NOT NULL DEFAULT 0,
    other_deductions REAL NOT NULL DEFAULT 0,
    other_deductions_note TEXT,
    net REAL NOT NULL
);

CREATE TABLE sub_payrolls (
    id INTEGER PRIMARY KEY,
    contract_id INTEGER NOT NULL REFERENCES contracts(id),
    subcontractor TEXT NOT NULL,
    week_ending TEXT NOT NULL,
    received_at TEXT,                       -- NULL means expected but not received
    UNIQUE (contract_id, subcontractor, week_ending)
);

CREATE TABLE compliance_events (
    id INTEGER PRIMARY KEY,
    contract_id INTEGER REFERENCES contracts(id),
    rule_key TEXT NOT NULL,                 -- e.g. payment_protection, payroll_week, debrief
    title TEXT NOT NULL,
    due_date TEXT NOT NULL,
    completed_at TEXT,
    notes TEXT,
    UNIQUE (contract_id, rule_key, due_date)
);

-- ============ BID ============

CREATE TABLE bids (
    id INTEGER PRIMARY KEY,
    solicitation_no TEXT,
    title TEXT NOT NULL,
    estimate_json TEXT NOT NULL,            -- full input + computed breakdown, for audit
    model_chosen TEXT,                      -- broker | hybrid | self
    bid_price REAL,
    total_direct_cost REAL,
    outcome TEXT NOT NULL DEFAULT 'pending',-- pending | won | lost | no_bid
    winning_price REAL,
    notes TEXT,
    created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE materials_prices (
    id INTEGER PRIMARY KEY,
    item TEXT NOT NULL UNIQUE,
    unit TEXT NOT NULL,
    unit_cost REAL NOT NULL,
    source TEXT,
    updated_at TEXT DEFAULT (datetime('now'))
);

-- ============ WATCH ============

CREATE TABLE opportunities (
    id INTEGER PRIMARY KEY,
    notice_id TEXT NOT NULL UNIQUE,
    solicitation_no TEXT,
    title TEXT,
    agency TEXT,
    office TEXT,
    set_aside TEXT,
    naics TEXT,
    psc TEXT,
    place_city TEXT,
    place_state TEXT,
    place_zip TEXT,
    posted_date TEXT,
    response_deadline TEXT,
    attachment_count INTEGER,
    poc_name TEXT,
    poc_email TEXT,
    url TEXT,
    piid_type TEXT,                         -- decoded from solicitation number position 9
    score REAL,
    score_breakdown TEXT,                   -- JSON, shows the work
    first_seen TEXT DEFAULT (datetime('now')),
    last_seen TEXT,
    amended_at TEXT,
    raw_json TEXT,
    archived INTEGER NOT NULL DEFAULT 0
);

-- ============ CASH ============

CREATE TABLE receivables (
    id INTEGER PRIMARY KEY,
    contract_id INTEGER REFERENCES contracts(id),
    invoice_no TEXT,
    amount REAL NOT NULL,
    invoiced_date TEXT NOT NULL,
    expected_date TEXT,                     -- when payment is expected (default +30d)
    paid_date TEXT
);

CREATE TABLE outflows (
    id INTEGER PRIMARY KEY,
    contract_id INTEGER REFERENCES contracts(id),
    category TEXT NOT NULL,                 -- materials | subcontractor | equipment | overhead | other
    description TEXT,
    amount REAL NOT NULL,
    due_date TEXT NOT NULL,
    paid_date TEXT
);

CREATE TABLE payment_instruments (
    id INTEGER PRIMARY KEY,
    contract_id INTEGER REFERENCES contracts(id),
    instrument_type TEXT NOT NULL,          -- irrevocable letter of credit | certificate of deposit | escrow | bond
    amount REAL NOT NULL,
    issued_date TEXT,
    released_date TEXT
);

CREATE TABLE gate_decisions (
    id INTEGER PRIMARY KEY,
    description TEXT NOT NULL,
    amount REAL NOT NULL,
    crew_ok INTEGER NOT NULL,
    materials_float_ok INTEGER NOT NULL,
    protection_ok INTEGER NOT NULL,
    payroll_capacity_ok INTEGER NOT NULL,
    recommendation TEXT NOT NULL,           -- accept | decline
    decision TEXT,                          -- what the operator actually did
    decided_at TEXT DEFAULT (datetime('now')),
    notes TEXT
);

CREATE TABLE cash_settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- ============ INTEL ============

CREATE TABLE competitors (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    uei TEXT,
    location TEXT,
    notes TEXT
);

CREATE TABLE competitor_awards (
    id INTEGER PRIMARY KEY,
    competitor_id INTEGER NOT NULL REFERENCES competitors(id),
    piid TEXT,
    piid_type TEXT,
    agency TEXT,
    amount REAL,
    award_date TEXT,
    description TEXT,
    bid_count INTEGER,                      -- number of offers received, if known
    category TEXT                           -- service type cell, for thin-cell analysis
);

CREATE TABLE bpa_holders (
    id INTEGER PRIMARY KEY,
    holder TEXT NOT NULL,
    field_office TEXT NOT NULL,
    service_type TEXT NOT NULL,
    bpa_piid TEXT,
    established_date TEXT,                  -- used for wave analysis
    expiration_date TEXT,                   -- used for recompete calendar
    notes TEXT,
    UNIQUE (holder, field_office, service_type)
);

CREATE TABLE settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
