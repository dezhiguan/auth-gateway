INSERT INTO event_subscriptions(subscriber, event_types, endpoint_url, hmac_key_id, hmac_secret, status)
VALUES
    (
        'ragforge',
        '["session.revoked","user.password.changed","consent.revoked","refresh.replay_detected"]'::jsonb,
        'http://rag-forge:8081/api/v1/events/session-revoked',
        'ragforge-hmac-key',
        '',
        'INACTIVE'
    ),
    (
        'careermate',
        '["session.revoked","user.password.changed","consent.revoked"]'::jsonb,
        'http://careermate:8080/api/v1/events/session-revoked',
        'careermate-hmac-key',
        '',
        'INACTIVE'
    )
ON CONFLICT DO NOTHING;
