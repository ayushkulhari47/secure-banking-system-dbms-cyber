DELIMITER $$

CREATE TRIGGER after_failed_login
AFTER UPDATE ON Users
FOR EACH ROW
BEGIN
    IF NEW.failed_attempts >= 3 THEN
        UPDATE Users SET is_locked = TRUE WHERE user_id = NEW.user_id;
        INSERT INTO Alerts (user_id, alert_type, description)
        VALUES (NEW.user_id, 'Brute Force', 'Account locked after 3 failed login attempts');
    END IF;
END$$

CREATE TRIGGER after_transaction
AFTER INSERT ON Transactions
FOR EACH ROW
BEGIN
    INSERT INTO Audit_Log (user_id, action, ip_address)
    SELECT a.user_id, CONCAT('Transaction of ', NEW.amount, ' type: ', NEW.txn_type), '0.0.0.0'
    FROM Accounts a
    WHERE a.account_id = NEW.from_account;

    IF NEW.amount > 50000 THEN
        INSERT INTO Alerts (user_id, alert_type, description)
        SELECT a.user_id, 'Large Transaction', CONCAT('Suspicious large transaction of ', NEW.amount)
        FROM Accounts a
        WHERE a.account_id = NEW.from_account;
    END IF;
END$$

CREATE TRIGGER after_user_login
AFTER UPDATE ON Users
FOR EACH ROW
BEGIN
    IF NEW.failed_attempts = 0 AND OLD.failed_attempts > 0 THEN
        INSERT INTO Audit_Log (user_id, action, ip_address)
        VALUES (NEW.user_id, 'Successful Login', '0.0.0.0');
    END IF;
END$$

DELIMITER ;
