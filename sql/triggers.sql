-- =============================================================================
-- triggers.sql -- Tamper-Resistant MySQL 8+ Audit & Append-Only Triggers
-- =============================================================================
-- Matches bank/db.py (MYSQL_AUDIT_TRIGGERS) and setup_db.py.
-- Every UPDATE to Accounts.balance appends a SHA-256 hash-chained Audit_Log
-- row, and Audit_Log is protected against UPDATE and DELETE.
-- =============================================================================

DROP TRIGGER IF EXISTS `after_failed_login`;
DROP TRIGGER IF EXISTS `after_transaction`;
DROP TRIGGER IF EXISTS `after_user_login`;
DROP TRIGGER IF EXISTS `after_accounts_balance_update`;
DROP TRIGGER IF EXISTS `prevent_audit_log_update`;
DROP TRIGGER IF EXISTS `prevent_audit_log_delete`;

DELIMITER $$

CREATE TRIGGER after_accounts_balance_update
AFTER UPDATE ON Accounts
FOR EACH ROW
BEGIN
    DECLARE v_cnt INT DEFAULT 0;
    DECLARE v_prev_uid INT DEFAULT NULL;
    DECLARE v_prev_act VARCHAR(255) DEFAULT '';
    DECLARE v_prev_time_str VARCHAR(19) DEFAULT '';
    DECLARE v_prev_prev VARCHAR(64) DEFAULT NULL;
    DECLARE v_prev_hash VARCHAR(64) DEFAULT NULL;
    DECLARE v_log_time VARCHAR(19) DEFAULT '';
    DECLARE v_action VARCHAR(255) DEFAULT '';
    DECLARE v_entry_hash VARCHAR(64) DEFAULT '';

    SELECT COUNT(*) INTO v_cnt FROM Audit_Log;
    IF v_cnt = 0 THEN
        SET v_prev_hash = REPEAT('0', 64);
    ELSE
        SELECT user_id, action, DATE_FORMAT(log_time, '%Y-%m-%d %H:%i:%s'), previous_hash, entry_hash
        INTO v_prev_uid, v_prev_act, v_prev_time_str, v_prev_prev, v_prev_hash
        FROM Audit_Log
        ORDER BY log_id DESC
        LIMIT 1
        FOR UPDATE;

        IF v_prev_prev IS NULL OR v_prev_hash IS NULL OR CHAR_LENGTH(v_prev_prev) <> 64 OR CHAR_LENGTH(v_prev_hash) <> 64 THEN
            SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Audit_Log chain is corrupted or missing hash fields';
        END IF;

        IF v_prev_hash <> LOWER(SHA2(CONCAT(v_prev_prev, '|', COALESCE(CAST(v_prev_uid AS CHAR), 'None'), '|', v_prev_act, '|', v_prev_time_str), 256)) THEN
            SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Audit_Log hash verification failed';
        END IF;
    END IF;

    SET v_log_time = DATE_FORMAT(UTC_TIMESTAMP(), '%Y-%m-%d %H:%i:%s');
    SET v_action = CONCAT('Account #', NEW.account_id, ' balance updated: Rs', CAST(OLD.balance AS CHAR), ' -> Rs', CAST(NEW.balance AS CHAR));
    SET v_entry_hash = LOWER(SHA2(CONCAT(v_prev_hash, '|', CAST(NEW.user_id AS CHAR), '|', v_action, '|', v_log_time), 256));

    INSERT INTO Audit_Log (user_id, action, log_time, previous_hash, entry_hash)
    VALUES (NEW.user_id, v_action, v_log_time, v_prev_hash, v_entry_hash);
END$$

CREATE TRIGGER prevent_audit_log_update
BEFORE UPDATE ON Audit_Log
FOR EACH ROW
BEGIN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Audit_Log is append-only: UPDATE is prohibited';
END$$

CREATE TRIGGER prevent_audit_log_delete
BEFORE DELETE ON Audit_Log
FOR EACH ROW
BEGIN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Audit_Log is append-only: DELETE is prohibited';
END$$

DELIMITER ;
