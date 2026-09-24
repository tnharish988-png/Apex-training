BANK CRUD - FULL FASTAPI + MYSQL PROJECT

1. Create the project structure exactly like this:

BankCRUD/
|-- main.py
|-- database.py
|-- schema.sql
|-- requirements.txt
|-- templates/
|   |-- login.html
|   |-- admin.html
|   |-- account_details.html
|   |-- customer.html
|   `-- transactions.html
`-- static/
    |-- style.css
    `-- app.js

2. MySQL:
- Open MySQL Workbench.
- Run schema.sql.
- In database.py change:
  password = "your_password"
  to your real MySQL root password.

3. Python environment:
Windows:
  python -m venv .venv
  .venv\Scripts\activate
  pip install -r requirements.txt

4. Start:
  uvicorn main:app --reload

5. Open:
  http://127.0.0.1:8000

6. Demo admin:
  Username: admin
  Password: admin123

7. Admin functions:
- Create account
- View account details
- Update holder/phone/email/PIN
- Delete account

8. Customer functions:
- Login with account number + 4 digit PIN
- View balance
- Deposit
- Withdraw
- View full transaction history

IMPORTANT:
- pin_hash is stored in the database, but the real PIN is never displayed in the UI.
- Change the SessionMiddleware secret_key before using outside a local/demo environment.
- This is an educational project, not production banking software.
