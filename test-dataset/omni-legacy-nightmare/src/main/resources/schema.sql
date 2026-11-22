CREATE TABLE omni_record (
    record_id BIGINT PRIMARY KEY,
    code VARCHAR(24) UNIQUE NOT NULL,
    holder_id VARCHAR(48) NOT NULL,
    tag VARCHAR(40) NOT NULL,
    region VARCHAR(40) NOT NULL,
    memo VARCHAR(200) NOT NULL
);

CREATE TABLE omni_payout (
    payout_id BIGINT PRIMARY KEY,
    ref_no VARCHAR(24) UNIQUE NOT NULL,
    beneficiary_id VARCHAR(48) NOT NULL,
    amount INT NOT NULL
);

CREATE TABLE legacy_contract (
    contract_id BIGINT PRIMARY KEY,
    contract_no VARCHAR(24) UNIQUE NOT NULL,
    client_account VARCHAR(48) NOT NULL,
    notes VARCHAR(200) NOT NULL
);
