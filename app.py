import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime

from helpers import apology, login_required, lookup, usd


app = Flask(__name__)
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

db = SQL("sqlite:///finance.db")


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

    # GET all purchases in alphabetical order and grouped by stock
    purchases = db.execute(
        "SELECT stock_symbol, SUM(stock_shares) as stock_shares FROM purchases WHERE user_id = ? GROUP BY stock_symbol HAVING SUM(stock_shares) > 0 ORDER BY stock_symbol",
        session["user_id"],
    )

    current_cash_row = db.execute(
        "SELECT current_cash FROM purchases WHERE user_id = ? ORDER BY purchase_date DESC",
        session["user_id"],
    )

    if not purchases:
        current_cash_row = db.execute(
            "SELECT cash FROM users WHERE id = ?", session["user_id"]
        )
        current_cash = current_cash_row[0]["cash"]
        return render_template("index.html", current_cash=current_cash)
    else:
        current_cash = current_cash_row[0]["current_cash"]
        for purchase in purchases:
            stock = lookup(purchase["stock_symbol"])
            purchase["stock_price"] = stock["price"]

        return render_template(
            "index.html", purchases=purchases, current_cash=current_cash
        )


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    if request.method == "POST":
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")
        stock = lookup(symbol)

        if not symbol:
            return apology("must provide symbol", 400)

        if not stock:
            return apology("the symbol does not exist", 400)

        if not shares:
            return apology("must provide number of shares", 400)

        try:
            shares_numb = int(shares)
        except ValueError:
            return apology("Shares did not contain a number!", 400)

        if shares_numb < 0:
            return apology("Number of shares must be greater than 0", 400)

        # Query purchases table for user's amount of cash
        cash_row = db.execute(
            "SELECT current_cash FROM purchases WHERE user_id = ? ORDER BY purchase_date DESC",
            session["user_id"],
        )

        if cash_row:
            cash = cash_row[0]["current_cash"]
            current_cash = cash - (stock["price"] * shares_numb)
        else:
            cash_row = db.execute(
                "SELECT cash FROM users WHERE id = ?", session["user_id"]
            )
            cash = cash_row[0]["cash"]
            current_cash = cash - (stock["price"] * shares_numb)

        if (current_cash) < 0:
            return apology(
                "Cannot afford the number of shares at the current price", 400
            )

        db.execute(
            "INSERT INTO purchases (user_id, stock_symbol, stock_price, stock_shares, purchase_date, current_cash) VALUES (?, ?, ?, ?, ?, ?)",
            session["user_id"],
            stock["symbol"],
            stock["price"],
            shares_numb,
            datetime.now(),
            current_cash,
        )

        # flash(f"Bought {shares_numb} shares of {stock["symbol"]} stock!")
        # # Redirect user to home page
        # return redirect("/")

        # GET all purchases in alphabetical order and grouped by stock
        purchases = db.execute(
            "SELECT stock_symbol, stock_price, SUM(stock_shares) as stock_shares FROM purchases WHERE user_id = ? GROUP BY stock_symbol HAVING SUM(stock_shares) > 0 ORDER BY stock_symbol",
            session["user_id"],
        )

        return render_template(
            "index.html", purchases=purchases, current_cash=current_cash
        )

    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""

    purchases_row = db.execute(
        "SELECT stock_symbol, stock_shares, stock_price, purchase_date FROM purchases WHERE user_id = ?",
        session["user_id"],
    )
    return render_template("history.html", purchases=purchases_row)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    if request.method == "POST":
        if not request.form.get("username"):
            return apology("must provide username", 403)

        elif not request.form.get("password"):
            return apology("must provide password", 403)

        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        return redirect("/")

    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    session.clear()

    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""

    if request.method == "POST":
        symbol = request.form.get("symbol")
        stock = lookup(symbol)

        if not symbol:
            return apology("must provide symbol", 400)

        if not stock:
            return apology("the symbol does not exist", 400)

        return render_template("quoted.html", stock=stock)

    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    if request.method == "POST":
        if not request.form.get("username"):
            return apology("must provide username", 400)

        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        if len(rows) != 0:
            return apology("Username already exists", 400)

        if not request.form.get("password"):
            return apology("Must provide password", 400)

        if request.form.get("password") != request.form.get("confirmation"):
            return apology("Passwords do not match", 400)

        db.execute(
            "INSERT INTO users (username, hash) VALUES(?, ?)",
            request.form.get("username"),
            generate_password_hash(request.form.get("password")),
        )

        return redirect("/")

    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""

    if request.method == "POST":
        if not request.form.get("symbol"):
            return apology("Failed to select a stock", 400)

        # Ensure user does own any shares of that stock
        shares_row = db.execute(
            "SELECT SUM(stock_shares) as stock_shares FROM purchases WHERE stock_symbol LIKE ? AND user_id = ? GROUP BY stock_symbol HAVING SUM(stock_shares) > 0 ORDER BY stock_symbol",
            request.form.get("symbol"),
            session["user_id"],
        )

        symbol = request.form.get("symbol")
        if not shares_row:
            return apology(f"No {symbol} shares found", 400)

        try:
            shares_numb = int(request.form.get("shares"))
        except ValueError:
            return apology("Shares did not contain a number!", 400)

        if shares_numb < 0:
            return apology("Number of shares must be greater than 0", 400)

        if shares_numb > shares_row[-1]["stock_shares"]:
            return apology(
                "Number of shares owned is less than the desired number", 400
            )

        shares_sold = -shares_numb

        # GET stock current price
        stock = lookup(request.form.get("symbol"))
        stock_price = stock["price"]

        # GET current cash value
        current_cash_row = db.execute(
            "SELECT current_cash FROM purchases WHERE user_id = ? ORDER BY purchase_date DESC",
            session["user_id"],
        )
        available_cash = current_cash_row[0]["current_cash"] + (
            stock_price * float(shares_numb)
        )

        # Insert into table the stock with negative value since it's a sell
        db.execute(
            "INSERT INTO purchases (user_id, stock_symbol, stock_price, stock_shares, purchase_date, current_cash) VALUES (?, ?, ?, ?, ?, ?)",
            session["user_id"],
            request.form.get("symbol"),
            stock_price,
            shares_sold,
            datetime.now(),
            available_cash,
        )

        # flash(f"Sold {shares_numb} shares of {stock["symbol"]} stock!")
        # # Redirect user to home page
        # return redirect("/")

        # GET all purchases in alphabetical order and grouped by stock
        purchases = db.execute(
            "SELECT stock_symbol, stock_price, SUM(stock_shares) as stock_shares FROM purchases WHERE user_id = ? GROUP BY stock_symbol HAVING SUM(stock_shares) > 0 ORDER BY purchase_date DESC",
            session["user_id"],
        )

        purchases[0]["current_cash"] = available_cash
        print(purchases)
        return render_template("index.html", purchases=purchases)

    else:
        stock_rows = db.execute(
            "SELECT stock_symbol FROM purchases WHERE user_id = ? GROUP BY stock_symbol HAVING SUM(stock_shares) > 0 ORDER BY stock_symbol",
            session["user_id"],
        )
        return render_template("sell.html", stocks=stock_rows)


@app.route("/password", methods=["GET", "POST"])
def password():
    """Change user password"""

    if request.method == "POST":
        if not request.form.get("username"):
            return apology("must provide username", 403)

        if not request.form.get("password"):
            return apology("Must provide current password", 403)

        if not request.form.get("new_password"):
            return apology("Must provide new password", 403)

        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
            return apology("invalid username and/or password", 403)

        db.execute(
            "UPDATE users SET hash = ? WHERE username = ?",
            generate_password_hash(request.form.get("new_password")),
            request.form.get("username"),
        )

        return render_template("login.html")

    else:
        return render_template("password.html")
