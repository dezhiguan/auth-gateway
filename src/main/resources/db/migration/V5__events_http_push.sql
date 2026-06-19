ALTER TABLE event_subscriptions
    ADD COLUMN hmac_secret VARCHAR(128) NOT NULL DEFAULT '';

CREATE TABLE event_outbox (
    id BIGSERIAL PRIMARY KEY,
    event_id VARCHAR(64) UNIQUE NOT NULL,
    event_type VARCHAR(64) NOT NULL,
    subscriber VARCHAR(64) NOT NULL,
    endpoint_url VARCHAR(256) NOT NULL,
    payload JSONB NOT NULL,
    attempts INT NOT NULL DEFAULT 0,
    last_error TEXT,
    status VARCHAR(16) NOT NULL DEFAULT 'PENDING',
    created_at TIMESTAMP NOT NULL DEFAULT now(),
    delivered_at TIMESTAMP
);

CREATE INDEX idx_event_outbox_status ON event_outbox(status, created_at);

UPDATE event_subscriptions
SET hmac_secret = '<TBD-replace-on-deploy>'
WHERE subscriber = 'ragforge';
