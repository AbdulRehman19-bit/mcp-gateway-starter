-- Dev-only demo data and roles. Passwords here are placeholders for local use.
CREATE DATABASE gateway;

CREATE ROLE gateway_ro LOGIN PASSWORD 'change-me-ro';
CREATE ROLE gateway_rw LOGIN PASSWORD 'change-me-rw';
CREATE ROLE gateway_app LOGIN PASSWORD 'change-me-app';

\connect demo

CREATE TABLE customers (
    id          serial PRIMARY KEY,
    name        text NOT NULL,
    country     text NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE users (
    id             serial PRIMARY KEY,
    email          text NOT NULL,
    phone          text,
    password_hash  text NOT NULL,
    created_at     timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE orders (
    id           serial PRIMARY KEY,
    customer_id  int NOT NULL REFERENCES customers(id),
    total_cents  int NOT NULL,
    status       text NOT NULL DEFAULT 'new',
    notes        text,
    created_at   timestamptz NOT NULL DEFAULT now()
);

INSERT INTO customers (name, country) VALUES
    ('Acme Traders', 'PK'), ('Northwind Ltd', 'GB'), ('Globex', 'US');
INSERT INTO users (email, phone, password_hash) VALUES
    ('a@example.com', '+92-300-0000001', 'x'), ('b@example.com', '+44-20-0000002', 'x');
INSERT INTO orders (customer_id, total_cents, status) VALUES
    (1, 12500, 'paid'), (2, 8900, 'new'), (3, 45000, 'shipped');

-- Read-only role: SELECT only, and only on what it should see.
GRANT CONNECT ON DATABASE demo TO gateway_ro, gateway_rw;
GRANT USAGE ON SCHEMA public TO gateway_ro, gateway_rw;
GRANT SELECT ON orders, customers TO gateway_ro;
-- column-level: no email/password_hash. phone is granted so policy can mask it to "***"
-- (the mask is applied in the rewritten SQL; the DB never needs to hide it from this role).
GRANT SELECT (id, phone, created_at) ON users TO gateway_ro;

-- Read-write role: limited UPDATE on specific columns only.
GRANT SELECT ON orders, customers TO gateway_rw;
GRANT UPDATE (status, notes) ON orders TO gateway_rw;
