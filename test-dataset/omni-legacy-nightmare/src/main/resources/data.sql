INSERT INTO omni_record VALUES
    (1, 'OM-001', 'client-01', 'TAG-A', 'NORTH', 'Urgent wire'),
    (2, 'OM-002', 'client-02', 'TAG-B', 'SOUTH', 'Delayed settlement');

INSERT INTO omni_payout VALUES
    (10, 'PAY-100', 'client-01', 15000),
    (20, 'PAY-200', 'client-02', 42000);

INSERT INTO legacy_contract VALUES
    (301, 'CTR-2026-1', 'client-01', 'VIP terms'),
    (302, 'CTR-2026-2', 'client-02', 'Standard terms');
