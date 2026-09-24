
from decimal import Decimal, InvalidOperation
from hashlib import pbkdf2_hmac
from hmac import compare_digest
from secrets import token_bytes
from typing import Optional

from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

from database import get_connection


app = FastAPI(title="Bank Management System")

app.add_middleware(
    SessionMiddleware,
    secret_key="CHANGE_THIS_TO_A_LONG_RANDOM_SECRET"
)

templates = Jinja2Templates(directory="templates")

app.mount(
    "/static",
    StaticFiles(directory="static"),
    name="static"
)


# -----------------------------
# PASSWORD/PIN HELPERS
# -----------------------------

def hash_secret(value: str) -> str:
    salt = token_bytes(16)

    digest = pbkdf2_hmac(
        "sha256",
        value.encode(),
        salt,
        120_000
    )

    return f"{salt.hex()}${digest.hex()}"


def verify_secret(value: str, stored: str) -> bool:
    try:
        salt_hex, digest_hex = stored.split("$", 1)

        salt = bytes.fromhex(salt_hex)

        digest = pbkdf2_hmac(
            "sha256",
            value.encode(),
            salt,
            120_000
        )

        return compare_digest(
            digest.hex(),
            digest_hex
        )

    except (ValueError, TypeError):
        return False


def money(value: str) -> Decimal:
    try:
        amount = Decimal(value)

    except (InvalidOperation, TypeError):
        raise ValueError("Invalid amount")

    if amount <= 0:
        raise ValueError("Amount must be greater than zero")

    return amount.quantize(Decimal("0.01"))


def get_db():
    return get_connection()


# -----------------------------
# ADMIN SETUP
# -----------------------------

def setup_admin():

    conn = get_db()
    cur = conn.cursor()

    cur.execute(
        "SELECT id FROM admins WHERE username=%s",
        ("admin",)
    )

    if cur.fetchone() is None:

        cur.execute(
            """
            INSERT INTO admins(username, password_hash)
            VALUES(%s,%s)
            """,
            (
                "admin",
                hash_secret("admin123")
            )
        )

        conn.commit()

    cur.close()
    conn.close()


@app.on_event("startup")
def startup():
    setup_admin()


# -----------------------------
# AUTH
# -----------------------------

@app.get("/", response_class=HTMLResponse)
def home(request: Request):

    if request.session.get("role") == "admin":
        return RedirectResponse(
            "/admin",
            status_code=303
        )

    if request.session.get("role") == "customer":
        return RedirectResponse(
            "/customer",
            status_code=303
        )

    return templates.TemplateResponse(
        request=request,
        name="login.html",
        context={
            "error": None
        }
    )


@app.post("/login")
def login(
    request: Request,
    role: str = Form(...),
    username: str = Form(""),
    password: str = Form(""),
    account_no: str = Form(""),
    pin: str = Form("")
):

    conn = get_db()
    cur = conn.cursor(dictionary=True)

    # -----------------------------
    # ADMIN LOGIN
    # -----------------------------

    if role == "admin":

        cur.execute(
            "SELECT * FROM admins WHERE username=%s",
            (username.strip(),)
        )

        admin = cur.fetchone()

        cur.close()
        conn.close()

        if admin and verify_secret(
            password,
            admin["password_hash"]
        ):

            request.session.clear()

            request.session["role"] = "admin"
            request.session["username"] = admin["username"]

            return RedirectResponse(
                "/admin",
                status_code=303
            )

        return templates.TemplateResponse(
            request=request,
            name="login.html",
            context={
                "error": "Invalid admin username or password."
            },
            status_code=401
        )

    # -----------------------------
    # CUSTOMER LOGIN
    # -----------------------------

    if role == "customer":

        cur.execute(
            "SELECT * FROM accounts WHERE account_no=%s",
            (account_no.strip(),)
        )

        account = cur.fetchone()

        cur.close()
        conn.close()

        if account and verify_secret(
            pin,
            account["pin_hash"]
        ):

            request.session.clear()

            request.session["role"] = "customer"
            request.session["account_no"] = account["account_no"]

            return RedirectResponse(
                "/customer",
                status_code=303
            )

        return templates.TemplateResponse(
            request=request,
            name="login.html",
            context={
                "error": "Invalid account number or PIN."
            },
            status_code=401
        )

    cur.close()
    conn.close()

    return templates.TemplateResponse(
        request=request,
        name="login.html",
        context={
            "error": "Select a valid login type."
        },
        status_code=400
    )


@app.get("/logout")
def logout(request: Request):

    request.session.clear()

    return RedirectResponse(
        "/",
        status_code=303
    )


# -----------------------------
# ADMIN
# -----------------------------

def admin_required(request: Request):
    return request.session.get("role") == "admin"


@app.get("/admin", response_class=HTMLResponse)
def admin_dashboard(request: Request):

    if not admin_required(request):
        return RedirectResponse(
            "/",
            status_code=303
        )

    conn = get_db()
    cur = conn.cursor(dictionary=True)

    cur.execute(
        """
        SELECT account_no,
               account_holder,
               phone,
               email,
               balance,
               created_at
        FROM accounts
        ORDER BY created_at DESC
        """
    )

    accounts = cur.fetchall()

    cur.close()
    conn.close()

    return templates.TemplateResponse(
        request=request,
        name="admin.html",
        context={
            "accounts": accounts,
            "message": None,
            "error": None
        }
    )


@app.post("/admin/account/create")
def create_account(
    request: Request,
    account_holder: str = Form(...),
    phone: str = Form(""),
    email: str = Form(""),
    pin: str = Form(...),
    opening_balance: str = Form("0")
):

    if not admin_required(request):
        return RedirectResponse(
            "/",
            status_code=303
        )

    try:

        amount = Decimal(
            opening_balance
        ).quantize(
            Decimal("0.01")
        )

        if amount < 0:
            raise ValueError

        if len(pin) != 4 or not pin.isdigit():
            raise ValueError(
                "PIN must be exactly 4 digits."
            )

    except Exception:

        return RedirectResponse(
            "/admin?error=Invalid+input",
            status_code=303
        )

    import uuid

    account_no = (
        "AC" +
        uuid.uuid4().hex[:8].upper()
    )

    conn = get_db()
    cur = conn.cursor()

    try:

        cur.execute(
            """
            INSERT INTO accounts(
                account_no,
                account_holder,
                phone,
                email,
                pin_hash,
                balance
            )
            VALUES(%s,%s,%s,%s,%s,%s)
            """,
            (
                account_no,
                account_holder.strip(),
                phone.strip(),
                email.strip(),
                hash_secret(pin),
                amount
            )
        )

        if amount > 0:

            cur.execute(
                """
                INSERT INTO transactions(
                    account_no,
                    transaction_type,
                    amount,
                    balance_after
                )
                VALUES(%s,'DEPOSIT',%s,%s)
                """,
                (
                    account_no,
                    amount,
                    amount
                )
            )

        conn.commit()

    except Exception:

        conn.rollback()

        cur.close()
        conn.close()

        return RedirectResponse(
            "/admin?error=Account+creation+failed",
            status_code=303
        )

    cur.close()
    conn.close()

    return RedirectResponse(
        f"/admin?message=Account+created:+{account_no}",
        status_code=303
    )


@app.get(
    "/admin/account/{account_no}",
    response_class=HTMLResponse
)
def account_details(
    request: Request,
    account_no: str
):

    if not admin_required(request):
        return RedirectResponse(
            "/",
            status_code=303
        )

    conn = get_db()
    cur = conn.cursor(dictionary=True)

    cur.execute(
        """
        SELECT account_no,
               account_holder,
               phone,
               email,
               balance,
               created_at
        FROM accounts
        WHERE account_no=%s
        """,
        (account_no,)
    )

    account = cur.fetchone()

    cur.execute(
        """
        SELECT transaction_type,
               amount,
               balance_after,
               created_at
        FROM transactions
        WHERE account_no=%s
        ORDER BY id DESC
        """,
        (account_no,)
    )

    transactions = cur.fetchall()

    cur.close()
    conn.close()

    if not account:

        return RedirectResponse(
            "/admin?error=Account+not+found",
            status_code=303
        )

    return templates.TemplateResponse(
        request=request,
        name="account_details.html",
        context={
            "account": account,
            "transactions": transactions
        }
    )


@app.post("/admin/account/update/{account_no}")
def update_account(
    request: Request,
    account_no: str,
    account_holder: str = Form(...),
    phone: str = Form(""),
    email: str = Form(""),
    pin: str = Form("")
):

    if not admin_required(request):
        return RedirectResponse(
            "/",
            status_code=303
        )

    conn = get_db()
    cur = conn.cursor()

    if pin.strip():

        if len(pin) != 4 or not pin.isdigit():

            cur.close()
            conn.close()

            return RedirectResponse(
                f"/admin/account/{account_no}?error=PIN+must+be+4+digits",
                status_code=303
            )

        cur.execute(
            """
            UPDATE accounts
            SET account_holder=%s,
                phone=%s,
                email=%s,
                pin_hash=%s
            WHERE account_no=%s
            """,
            (
                account_holder.strip(),
                phone.strip(),
                email.strip(),
                hash_secret(pin),
                account_no
            )
        )

    else:

        cur.execute(
            """
            UPDATE accounts
            SET account_holder=%s,
                phone=%s,
                email=%s
            WHERE account_no=%s
            """,
            (
                account_holder.strip(),
                phone.strip(),
                email.strip(),
                account_no
            )
        )

    conn.commit()

    cur.close()
    conn.close()

    return RedirectResponse(
        f"/admin/account/{account_no}",
        status_code=303
    )


@app.post("/admin/account/delete/{account_no}")
def delete_account(
    request: Request,
    account_no: str
):

    if not admin_required(request):
        return RedirectResponse(
            "/",
            status_code=303
        )

    conn = get_db()
    cur = conn.cursor()

    cur.execute(
        "DELETE FROM accounts WHERE account_no=%s",
        (account_no,)
    )

    conn.commit()

    cur.close()
    conn.close()

    return RedirectResponse(
        "/admin?message=Account+deleted",
        status_code=303
    )


# -----------------------------
# CUSTOMER
# -----------------------------

def customer_required(request: Request):
    return request.session.get("role") == "customer"


def current_account(request: Request):

    account_no = request.session.get(
        "account_no"
    )

    if not account_no:
        return None

    conn = get_db()
    cur = conn.cursor(dictionary=True)

    cur.execute(
        """
        SELECT account_no,
               account_holder,
               phone,
               email,
               balance,
               created_at
        FROM accounts
        WHERE account_no=%s
        """,
        (account_no,)
    )

    account = cur.fetchone()

    cur.close()
    conn.close()

    return account


@app.get(
    "/customer",
    response_class=HTMLResponse
)
def customer_dashboard(request: Request):

    if not customer_required(request):
        return RedirectResponse(
            "/",
            status_code=303
        )

    account = current_account(request)

    if not account:

        request.session.clear()

        return RedirectResponse(
            "/",
            status_code=303
        )

    conn = get_db()
    cur = conn.cursor(dictionary=True)

    cur.execute(
        """
        SELECT transaction_type,
               amount,
               balance_after,
               created_at
        FROM transactions
        WHERE account_no=%s
        ORDER BY id DESC
        LIMIT 10
        """,
        (account["account_no"],)
    )

    transactions = cur.fetchall()

    cur.close()
    conn.close()

    return templates.TemplateResponse(
        request=request,
        name="customer.html",
        context={
            "account": account,
            "transactions": transactions,
            "error": None
        }
    )


@app.post("/customer/deposit")
def customer_deposit(
    request: Request,
    amount: str = Form(...)
):

    if not customer_required(request):
        return RedirectResponse(
            "/",
            status_code=303
        )

    try:

        value = money(amount)

    except ValueError:

        return RedirectResponse(
            "/customer?error=Invalid+deposit+amount",
            status_code=303
        )

    account_no = request.session["account_no"]

    conn = get_db()
    cur = conn.cursor()

    try:

        cur.execute(
            """
            SELECT balance
            FROM accounts
            WHERE account_no=%s
            FOR UPDATE
            """,
            (account_no,)
        )

        row = cur.fetchone()

        if not row:
            raise ValueError(
                "Account not found"
            )

        new_balance = (
            Decimal(str(row[0])) + value
        )

        cur.execute(
            """
            UPDATE accounts
            SET balance=%s
            WHERE account_no=%s
            """,
            (
                new_balance,
                account_no
            )
        )

        cur.execute(
            """
            INSERT INTO transactions(
                account_no,
                transaction_type,
                amount,
                balance_after
            )
            VALUES(%s,'DEPOSIT',%s,%s)
            """,
            (
                account_no,
                value,
                new_balance
            )
        )

        conn.commit()

    except Exception:

        conn.rollback()

        cur.close()
        conn.close()

        return RedirectResponse(
            "/customer?error=Deposit+failed",
            status_code=303
        )

    cur.close()
    conn.close()

    return RedirectResponse(
        "/customer?message=Deposit+successful",
        status_code=303
    )


@app.post("/customer/withdraw")
def customer_withdraw(
    request: Request,
    amount: str = Form(...)
):

    if not customer_required(request):
        return RedirectResponse(
            "/",
            status_code=303
        )

    try:

        value = money(amount)

    except ValueError:

        return RedirectResponse(
            "/customer?error=Invalid+withdrawal+amount",
            status_code=303
        )

    account_no = request.session["account_no"]

    conn = get_db()
    cur = conn.cursor()

    try:

        cur.execute(
            """
            SELECT balance
            FROM accounts
            WHERE account_no=%s
            FOR UPDATE
            """,
            (account_no,)
        )

        row = cur.fetchone()

        if not row:
            raise ValueError(
                "Account not found"
            )

        balance = Decimal(str(row[0]))

        if value > balance:

            cur.close()

            conn.rollback()
            conn.close()

            return RedirectResponse(
                "/customer?error=Insufficient+balance",
                status_code=303
            )

        new_balance = balance - value

        cur.execute(
            """
            UPDATE accounts
            SET balance=%s
            WHERE account_no=%s
            """,
            (
                new_balance,
                account_no
            )
        )

        cur.execute(
            """
            INSERT INTO transactions(
                account_no,
                transaction_type,
                amount,
                balance_after
            )
            VALUES(%s,'WITHDRAW',%s,%s)
            """,
            (
                account_no,
                value,
                new_balance
            )
        )

        conn.commit()

    except Exception:

        conn.rollback()

        cur.close()
        conn.close()

        return RedirectResponse(
            "/customer?error=Withdrawal+failed",
            status_code=303
        )

    cur.close()
    conn.close()

    return RedirectResponse(
        "/customer?message=Withdrawal+successful",
        status_code=303
    )


@app.get(
    "/customer/transactions",
    response_class=HTMLResponse
)
def customer_transactions(
    request: Request
):

    if not customer_required(request):
        return RedirectResponse(
            "/",
            status_code=303
        )

    account = current_account(request)

    if not account:

        request.session.clear()

        return RedirectResponse(
            "/",
            status_code=303
        )

    conn = get_db()
    cur = conn.cursor(dictionary=True)

    cur.execute(
        """
        SELECT transaction_type,
               amount,
               balance_after,
               created_at
        FROM transactions
        WHERE account_no=%s
        ORDER BY id DESC
        """,
        (account["account_no"],)
    )

    transactions = cur.fetchall()

    cur.close()
    conn.close()

    return templates.TemplateResponse(
        request=request,
        name="transactions.html",
        context={
            "account": account,
            "transactions": transactions
        }
    )

