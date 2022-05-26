import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    # symbol, numbers of shared, current price of each stock, total value(shares * price), current cash balance, grand total(stock value plus cash)
    # table -> symbol, current price, tot

    if request.method == "GET":
        user_id = session["user_id"]
        buy = db.execute("\
            SELECT symbol, SUM(shares) AS shares FROM balance_tb WHERE order_type = '1' AND user_id = ? GROUP BY symbol", user_id)
        sell = db.execute("\
            SELECT symbol, SUM(shares) AS shares FROM balance_tb WHERE order_type = '0' AND user_id = ? GROUP BY symbol", user_id)
        cash = db.execute("SELECT cash FROM users WHERE id = ?", user_id)

        buy_shares, sell_shares = dict(), dict()
        for d in buy:
            buy_shares[d["symbol"]] = d["shares"]
        for d in sell:
            sell_shares[d["symbol"]] = d["shares"]

        total_shares = dict()
        for symbol in buy_shares:
            if symbol not in sell_shares.keys():
                total_shares[symbol] = buy_shares[symbol]
            else:
                total_shares[symbol] = buy_shares[symbol] - sell_shares[symbol]

        for symbol in total_shares:
            current = lookup(symbol)
            current_price = current["price"]
            price = current_price * total_shares[symbol]
            total_shares[symbol] = [total_shares[symbol]]
            total_shares[symbol].append(current_price)
            total_shares[symbol].append(price)

        sum = 0
        for price in total_shares.values():
            sum += price[1]

        cash = cash[0]["cash"]

        equity = round(cash + sum, 2)
        if len(buy_shares) == 0 and len(sell_shares) == 0:
            total_shares = {"None": [0, 0, 0]}
            return render_template("index.html", total_shares=total_shares, cash=cash, equity=equity)

        return render_template("index.html", total_shares=total_shares, cash=cash, equity=equity)

    return apology("BAD GATEWAY", 403)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "GET":
        return render_template("buy.html")
    if request.method == "POST":
        buy_symbol = request.form.get("symbol")
        shares = request.form.get("shares")
        if buy_symbol == None or shares == None:
            return apology("You missed to input stock and shares.", 400)
        if not shares.isdecimal() or int(shares) <= 0 or "'" in buy_symbol or ";" in buy_symbol:
            return apology("Invalid shares or symbol", 400)

        if lookup(buy_symbol) == None:
            return apology("Wrong symbol", 400)
        # Get price and symbol from lookup
        stock = lookup(buy_symbol)
        buy_price, symbol = float(stock["price"]), stock["symbol"]
        # Calculate total price
        total_buy = round(float(buy_price)*float(shares), 2)
        # Get user_id from session
        user_id = session["user_id"]
        cash_db = db.execute("SELECT cash FROM users WHERE id = ?", user_id)
        cash = cash_db[0]["cash"]
        if total_buy > float(cash):
            return apology("Your transaction exceed your balance account", 400)
        balance = round((cash - total_buy), 2)
        now = datetime.now()
        dt = now.strftime("%d/%m/%Y %H:%M:%S")

        #db.execute("CREATE TABLE balance_tb (transaction_id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL, symbol TEXT NOT NULL, buy_price REAL DEFAULT 0.00, sell_price REAL DEFAULT 0.00, shares REAL NOT NULL, order_type INTEGER DEFAULT 1, total_buy REAL DEFAULT 0.00, total_sell REAL DEFAULT 0.00, balance REAL NOT NULL, date_time TEXT NOT NULL)")
        db.execute("INSERT INTO balance_tb (user_id, symbol, buy_price, shares, order_type,total_buy, balance, date_time) \
            VALUES(?, ?, ?, ?, ?, ?, ?, ?)", user_id, symbol, buy_price, shares, 1, total_buy, balance, dt)
        db.execute("UPDATE users SET cash = ? WHERE id = ?", balance, user_id)
        # bought = db.execute("SELECT symbol, buy_price, balance FROM balance_tb WHERE user_id = ?", user_id)
    # Get symbol from users and get number of shares from user
    # calculate number of shares * price -> update new users balance in new table
    # create paymenttb values of transaction_id unique, username char, number of shares, current_price, total_price, date_time
        # return render_template("bought.html", symbol=symbol, total_buy=total_buy)
        flash("Bought")
        return redirect("/")
    return apology("Bad Gateway", 400)


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    if request.method == "GET":
        user_id = session["user_id"]
        hist_list = db.execute("SELECT symbol, shares,\
        CASE WHEN buy_price = '0' THEN sell_price\
             ELSE buy_price\
        END AS price,\
        CASE WHEN order_type = '0' THEN 'SELL'\
            ELSE 'BUY'\
        END AS order_type,\
        date_time\
        FROM balance_tb\
        WHERE user_id = ?\
        ORDER BY transaction_id", user_id)
        return render_template("history.html", hist_list=hist_list)

    return apology("Wrong Gateway", 400)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "GET":
        return render_template("quote.html")
    # POST -> render_template quoted.html -> display table of symbol -> name/price
    if request.method == "POST":
        symbol = request.form.get("symbol")
        if lookup(symbol) == None:
            return apology("Wrong symbol", 400)
        sample = lookup(symbol)
        return render_template("quoted.html", name=sample["name"], price=sample["price"])

    return apology("Wrong Gateway", 400)


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    # store existed username and password from db
    if request.method == "GET":
        return render_template("register.html")

    if request.method == "POST":
        # get user request
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")
        username_db = db.execute("SELECT username FROM users")
        current_user = [d["username"] for d in username_db]

        if not username:
            return apology("username not found", 400)
        if username in current_user:
            return apology("Username already exist", 400)
        if not password:
            return apology("Password not found", 400)
        if not confirmation:
            return apology("Confirmation not found", 400)
        if password != confirmation:
            return apology("Password not match", 400)
        else:
            hash_password = generate_password_hash(password)
            db.execute("INSERT INTO users (username, hash) VALUES(?, ?)", username, hash_password)
            text = "You are registered"
            return render_template("register.html", username=username, password=password, text=text)
            # you are registered

    return apology("Wrong Gateway", 401)


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    # show stocks to select from Portfolio -> check box
    # fill in text field -> numbers of share to sell
    if request.method == "GET":
        user_id = session["user_id"]
        stock = db.execute("SELECT symbol, SUM(shares) AS total_shares FROM balance_tb WHERE user_id = ? GROUP BY symbol", user_id)
        symbol = [d["symbol"] for d in stock if "symbol" in d]
        return render_template("sell.html", symbol=symbol)

    if request.method == "POST":
        user_id = session["user_id"]
        sell_symbol = request.form.get("symbol")
        sell_shares = request.form.get("shares")
        stock = db.execute("SELECT symbol, SUM(shares) AS total_shares FROM balance_tb WHERE user_id = ? GROUP BY symbol", user_id)

        # check base cases
        # user not input symbol/shares
        if not sell_symbol:
            return apology("You must input stock", 400)
        if not sell_shares:
            return apology("You must input shares", 400)
        if not sell_shares.isdecimal() or int(sell_shares) <= 0 or "'" in sell_symbol or ";" in sell_symbol:
            return apology("Invalid shares or symbol", 400)
        # user not have enough shares to sell
        stockHash = dict()
        for d in stock:
            stockHash[d["symbol"]] = d["total_shares"]
        if stockHash[sell_symbol] < float(sell_shares):
            return apology("You do not have enough shares to sell", 400)

        sell_stock = lookup(sell_symbol)
        sell_price = sell_stock["price"]
        # update sell_price, shares, total_sell,
        cash_db = db.execute("SELECT cash FROM users WHERE id = ?", user_id)
        cash = cash_db[0]["cash"]
        total_sell = round(float(sell_price)*float(sell_shares), 2)
        # update balance
        balance = round((cash + total_sell), 2)
        now = datetime.now()
        dt = now.strftime("%d/%m/%Y %H:%M:%S")

        db.execute("INSERT INTO balance_tb (user_id, symbol, sell_price, shares, total_sell, balance, date_time) \
            VALUES(?, ?, ?, ?, ?, ?, ?)", user_id, sell_symbol, sell_price, sell_shares, total_sell, balance, dt)

        db.execute("UPDATE users SET cash = ? WHERE id = ?", balance, user_id)
        flash("Sold")
        return redirect("/")
    # return render_template("sold.html", sell_symbol=sell_symbol, total_sell=total_sell)
    return apology("Bad Gateway", 400)


@app.route("/password", methods=["GET", "POST"])
@login_required
def password():
    if request.method == "GET":
        return render_template("password.html")

    if request.method == "POST":
        old_password = request.form.get("old_password")
        new_password = request.form.get("new_password")
        confirmation = request.form.get("confirmation")

        if not old_password:
            return apology("Please enter your previous password", 400)
        if not new_password:
            return apology("Please enter your new password", 400)
        if not confirmation:
            return apology("Please confirm your password", 400)

        user_id = session["user_id"]
        user_data = db.execute("SELECT hash FROM users WHERE id = ?", user_id)
        hash_password = user_data[0]["hash"]
        # old_password = generate_password_hash(old_password)
        # new_password = generate_password_hash(new_password)

        if not check_password_hash(hash_password, new_password):
            return apology("Password not match your previous password", 400)
        if new_password == old_password:
            return apology("Please change your new password", 400)
        if new_password != confirmation:
            return apology("Please confirm a correct password", 400)
        db.execute("UPDATE users SET hash = ? WHERE id = ?", generate_password_hash(new_password), user_id)
    return render_template("password.html", text="You have changed the password")
