-- The cap of the security log counts entries per account, event and day.
CREATE INDEX security_log_by_subject ON security_log (user_id, event, ts);
