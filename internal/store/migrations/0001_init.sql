CREATE TABLE settings (
    id            INTEGER PRIMARY KEY CHECK (id = 1),
    endpoint_port INTEGER NOT NULL,
    endpoint_host TEXT    NOT NULL,
    tunnel_cidr   TEXT    NOT NULL,
    client_dns    TEXT    NOT NULL, -- comma-separated IPv4 addresses
    mtu           INTEGER NOT NULL, -- 0 = WireGuard default
    keepalive     INTEGER NOT NULL  -- seconds, 0 = off
);

INSERT INTO settings (id, endpoint_port, endpoint_host, tunnel_cidr, client_dns, mtu, keepalive)
VALUES (1, 51820, '', '10.8.0.0/24', '', 0, 25);

CREATE TABLE devices (
    id                 INTEGER PRIMARY KEY,
    name               TEXT    NOT NULL UNIQUE,
    public_key         TEXT    NOT NULL UNIQUE,
    ip                 TEXT    NOT NULL UNIQUE,
    enabled            INTEGER NOT NULL,
    client_allowed_ips TEXT    NOT NULL, -- comma-separated prefixes
    created_at         TEXT    NOT NULL,
    updated_at         TEXT    NOT NULL
);

CREATE TABLE profiles (
    id          INTEGER PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL
);

CREATE TABLE device_profiles (
    device_id  INTEGER NOT NULL REFERENCES devices (id) ON DELETE CASCADE,
    profile_id INTEGER NOT NULL REFERENCES profiles (id) ON DELETE CASCADE,
    PRIMARY KEY (device_id, profile_id)
);

-- A rule belongs to exactly one profile or one device.
CREATE TABLE rules (
    id          INTEGER PRIMARY KEY,
    profile_id  INTEGER REFERENCES profiles (id) ON DELETE CASCADE,
    device_id   INTEGER REFERENCES devices (id) ON DELETE CASCADE,
    destination TEXT    NOT NULL,
    protocol    TEXT    NOT NULL CHECK (protocol IN ('any', 'tcp', 'udp', 'tcp+udp', 'icmp')),
    port_from   INTEGER NOT NULL,
    port_to     INTEGER NOT NULL,
    comment     TEXT    NOT NULL,
    CHECK ((profile_id IS NULL) <> (device_id IS NULL))
);

CREATE INDEX rules_profile_id ON rules (profile_id);
CREATE INDEX rules_device_id ON rules (device_id);

INSERT INTO profiles (id, name, description)
VALUES (1, 'Internet only', 'Internet access, but nothing on the home network or other devices.');

INSERT INTO rules (profile_id, destination, protocol, port_from, port_to, comment)
VALUES (1, 'internet', 'any', 0, 0, '');
