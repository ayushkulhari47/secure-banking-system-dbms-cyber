INSERT INTO Users (name, email, password_hash, role) VALUES
('Ayush Kulhari', 'ayush@bank.com', SHA2('ayush123', 256), 'admin'),
('Rahul Sharma', 'rahul@bank.com', SHA2('rahul123', 256), 'user'),
('Priya Singh', 'priya@bank.com', SHA2('priya123', 256), 'user');

INSERT INTO Accounts (user_id, balance) VALUES
(1, 50000.00),
(2, 25000.00),
(3, 15000.00);

INSERT INTO Transactions (from_account, to_account, amount, txn_type) VALUES
(2, 1, 5000.00, 'transfer'),
(1, NULL, 10000.00, 'deposit'),
(3, NULL, 2000.00, 'withdraw');

SELECT u.name, u.email, u.role, a.balance
FROM Users u
JOIN Accounts a ON u.user_id = a.user_id;

SELECT * FROM Transactions
WHERE from_account = 1 OR to_account = 1
ORDER BY txn_time DESC;

SELECT u.name, COUNT(t.txn_id) AS total_transactions, SUM(t.amount) AS total_amount
FROM Users u
JOIN Accounts a ON u.user_id = a.user_id
JOIN Transactions t ON a.account_id = t.from_account
GROUP BY u.user_id;

SELECT * FROM Users WHERE failed_attempts >= 3;

SELECT * FROM Alerts WHERE status = 'open' ORDER BY alert_time DESC;

SELECT * FROM Audit_Log ORDER BY log_time DESC LIMIT 20;

UPDATE Accounts SET balance = balance + 5000 WHERE account_id = 2;

UPDATE Accounts SET balance = balance - 2000 WHERE account_id = 3 AND balance >= 2000;
