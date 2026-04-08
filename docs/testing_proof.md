Testing Proof - Secure Banking System

All tests were performed on db-fiddle for SQL and onecompiler for Python.

Test 1 - Users and Balances
Query used: SELECT u.name, u.email, u.role, a.balance FROM Users u JOIN Accounts a ON u.user_id = a.user_id
Result: All 3 users showing correctly with their balances
Ayush Kulhari - admin - Rs50000
Rahul Sharma - user - Rs25000
Priya Singh - user - Rs15000
Screenshot: test1.png

Test 2 - Transaction History
Query used: SELECT * FROM Transactions
Result: All 3 transactions recorded correctly
Transfer of Rs5000 from account 2 to account 1
Deposit of Rs10000 to account 1
Withdrawal of Rs2000 from account 3
Screenshot: test2.png

Test 3 - Login and Banking Menu
Result: Login worked successfully with correct credentials
Welcome message showed with correct role
All 8 menu options displayed correctly
Balance showed as Rs50000
Screenshot: test3.png

Test 4 - Brute Force Detection
Result: Wrong password attempt was detected immediately
System showed "Wrong password! Attempt 1/3"
On 3rd attempt account gets locked and alert is raised
Screenshot: test4.png

Test 5 - GitHub Repository
Result: Complete project structure visible on GitHub
docs folder, sql folder, app.py and README all present
12 commits showing project development history
Screenshot: test5.png
