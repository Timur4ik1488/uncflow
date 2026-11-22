CREATE TABLE fleet_order (
    order_id BIGINT PRIMARY KEY,
    order_code VARCHAR(24) UNIQUE NOT NULL,
    owner_id VARCHAR(48) NOT NULL,
    vin_plate VARCHAR(40) NOT NULL,
    driver_note VARCHAR(200) NOT NULL
);

CREATE TABLE dispatch_bay (
    order_id BIGINT PRIMARY KEY REFERENCES fleet_order(order_id),
    bay_note VARCHAR(120) NOT NULL
);

CREATE TABLE vehicle_invoice (
    invoice_id BIGINT PRIMARY KEY,
    invoice_number VARCHAR(24) UNIQUE NOT NULL,
    account_id VARCHAR(48) NOT NULL,
    total_amount INT NOT NULL
);
