Secure Banking System with Intrusion Detection and Audit Logging

A DBMS + Cybersecurity Project
Author: Ayush Kulhari
Course: B.Tech CSE


1. What is this project?

Imagine you have a bank app on your phone. You login, check balance, send money. Simple right? But what if someone tries to hack into your account by guessing your password again and again? Or what if someone suddenly transfers a huge amount of money suspiciously?

This project builds exactly that kind of smart banking system. It not only stores your money and transactions like a normal bank but it also watches for suspicious activity and raises an alarm automatically. No human needs to sit and monitor it. The database does it by itself.

This is why it is a DBMS plus Cybersecurity project.


2. What problems does it solve?

Problem 1 - Someone tries to guess your password multiple times
Our system detects this automatically and locks the account after 3 wrong attempts.

Problem 2 - Someone makes a suspiciously large transaction
Our system flags any transaction above Rs 50,000 as suspicious and creates an alert.

Problem 3 - No one knows what happened in the system
Our system keeps a record of every single action. Who logged in, when, what they did. This is called an audit log.

Problem 4 - Passwords stored as plain text are dangerous
Our system never stores the actual password. It stores a scrambled version called a hash. Even if someone steals the database they cannot read the passwords.


3. Database Tables

Think of tables like Excel sheets. We have 5 sheets in our database.

Users sheet - stores name, email, password hash, role and how many times login failed
Accounts sheet - stores which user owns which account and how much balance they have
Transactions sheet - stores every deposit, withdrawal and transfer ever made
Audit Log sheet - stores every action done in the system with time and user details
Alerts sheet - stores every suspicious activity that was detected


4. How the tables are connected

One user has one bank account
One user can do many transactions
Every action by a user creates a log entry
Every suspicious action creates an alert entry


5. Normalization - why we designed tables this way

Normalization just means designing tables properly so data is not repeated unnecessarily.

1NF means each cell has only one value. No lists inside a cell.
2NF means every column depends on the full primary key not just part of it.
3NF means no column depends on another non-key column.

Our database follows all three rules. This makes it clean, efficient and easy to maintain.


6. The Cyber Security Part - How intrusion detection works

This is the most important and unique part of the project.

We wrote something called SQL Triggers. A trigger is like a security camera. It watches the database and automatically does something when it sees a suspicious event.

Trigger 1 - Brute Force Login Detection
When a user enters wrong password 3 times the trigger automatically locks the account and inserts a warning into the Alerts table. No human needs to do this manually.

Trigger 2 - Large Transaction Detection
When any transaction above Rs 50,000 happens the trigger automatically inserts an alert saying this transaction looks suspicious.

Trigger 3 - Audit Logging
Every successful login and every transaction automatically creates a record in the Audit Log table. This way nothing in the system goes unrecorded.


7. Stored Procedures - making transactions safe

A stored procedure is like a saved recipe. Instead of writing the same SQL code again and again we save it once and just call it whenever needed.

We created 3 procedures:
Deposit - adds money to an account safely
Withdraw - removes money only if balance is sufficient, otherwise shows error
Transfer - moves money from one account to another safely


8. ACID Properties - why our transactions are reliable

ACID is a set of rules that makes database transactions reliable.

Atomicity means either the full transaction happens or nothing happens. Money will not disappear halfway.
Consistency means the database always stays in a valid state. Balance never goes negative.
Isolation means two transactions do not interfere with each other.
Durability means once a transaction is saved it stays saved even if the system crashes.


9. Technologies used

MySQL for the database
SQL Triggers and Stored Procedures for security logic
Python for the banking application
GitHub for storing and sharing the project


10. Testing results

We tested the system on db-fiddle for SQL and onecompiler for Python.

Login with correct password - worked perfectly
Login with wrong password 3 times - account got locked and alert was raised
Deposit money - balance updated correctly
Withdraw more than balance - system correctly showed insufficient balance error
Transfer between accounts - both balances updated correctly
View audit log - all actions were recorded


11. Conclusion

This project shows that a database system can be smart enough to protect itself. By combining SQL triggers, stored procedures, audit logging and password hashing we built a banking system that is both functional and secure.

Any student reading this project will understand how real banks protect your data and detect fraud. That is exactly what this project demonstrates.


GitHub: https://github.com/ayushkulhari47/secure-banking-system-dbms-cyber
