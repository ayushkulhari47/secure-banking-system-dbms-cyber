DELIMITER $$

CREATE PROCEDURE deposit(IN acc_id INT, IN amt DECIMAL(15,2))
BEGIN
    UPDATE Accounts SET balance = balance + amt WHERE account_id = acc_id;
    INSERT INTO Transactions (from_account, to_account, amount, txn_type)
    VALUES (NULL, acc_id, amt, 'deposit');
END$$

CREATE PROCEDURE withdraw(IN acc_id INT, IN amt DECIMAL(15,2))
BEGIN
    IF (SELECT balance FROM Accounts WHERE account_id = acc_id) >= amt THEN
        UPDATE Accounts SET balance = balance - amt WHERE account_id = acc_id;
        INSERT INTO Transactions (from_account, to_account, amount, txn_type)
        VALUES (acc_id, NULL, amt, 'withdraw');
    ELSE
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Insufficient balance';
    END IF;
END$$

CREATE PROCEDURE transfer(IN from_acc INT, IN to_acc INT, IN amt DECIMAL(15,2))
BEGIN
    IF (SELECT balance FROM Accounts WHERE account_id = from_acc) >= amt THEN
        UPDATE Accounts SET balance = balance - amt WHERE account_id = from_acc;
        UPDATE Accounts SET balance = balance + amt WHERE account_id = to_acc;
        INSERT INTO Transactions (from_account, to_account, amount, txn_type)
        VALUES (from_acc, to_acc, amt, 'transfer');
    ELSE
        SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Insufficient balance';
    END IF;
END$$

DELIMITER ;
