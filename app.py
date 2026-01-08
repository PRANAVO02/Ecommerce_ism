from flask import Flask, request, render_template, redirect, session
from flask_mysqldb import MySQL
import logging
import config
import os

# ---------------- APP INIT ----------------
app = Flask(__name__)
app.secret_key = config.SECRET_KEY

# ---------------- ENSURE LOG DIR ----------------
if not os.path.exists("logs"):
    os.makedirs("logs")

# ---------------- LOGGING (GET + POST) ----------------
logging.basicConfig(
    filename="logs/access.log",
    level=logging.INFO,
    format="%(asctime)s IP=%(message)s"
)

@app.before_request
def log_request():
    logging.info(
        f"{request.remote_addr} "
        f"URL={request.path} "
        f"METHOD={request.method} "
        f"ARGS={dict(request.args)} "
        f"FORM={request.form.to_dict() if request.method == 'POST' else {}}"
    )

# ---------------- MYSQL CONFIG ----------------
app.config['MYSQL_HOST'] = config.MYSQL_HOST
app.config['MYSQL_USER'] = config.MYSQL_USER
app.config['MYSQL_PASSWORD'] = config.MYSQL_PASSWORD
app.config['MYSQL_DB'] = config.MYSQL_DB
mysql = MySQL(app)

# ---------------- LOGIN ----------------
@app.route('/')
def login():
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def do_login():
    u = request.form['username']
    p = request.form['password']

    cur = mysql.connection.cursor()
    # ❌ INTENTIONAL SQL INJECTION VULNERABILITY
    cur.execute(f"SELECT * FROM users WHERE username='{u}' AND password='{p}'")
    user = cur.fetchone()

    if user:
        session['uid'] = user[0]
        session['user'] = user[1]
        session['role'] = user[3]
        return redirect('/products')

    return "Login Failed"

# ---------------- PRODUCTS ----------------
@app.route('/products')
def products():
    q = request.args.get('q', '')
    cur = mysql.connection.cursor()
    # ❌ SQL Injection via search
    cur.execute(f"SELECT * FROM products WHERE name LIKE '%{q}%'")
    products = cur.fetchall()
    return render_template('products.html', products=products)

# ---------------- ADD TO CART ----------------
@app.route('/add_to_cart')
def add_to_cart():
    pid = request.args.get('id')
    price = request.args.get('price')  # ❌ trusting client price
    session['cart'] = {'pid': pid, 'price': price}
    return redirect('/cart')

# ---------------- CART ----------------
@app.route('/cart')
def cart():
    return render_template('cart.html', cart=session.get('cart'))

# ---------------- CHECKOUT ----------------
@app.route('/checkout')
def checkout():
    cur = mysql.connection.cursor()
    total = session['cart']['price']
    # ❌ no validation
    cur.execute(
        f"INSERT INTO orders(user_id,total,status) VALUES({session['uid']},{total},'PLACED')"
    )
    mysql.connection.commit()
    return "Order Placed Successfully"

# ---------------- ORDERS (IDOR) ----------------
@app.route('/orders')
def orders():
    uid = request.args.get('uid', session['uid'])
    cur = mysql.connection.cursor()
    # ❌ IDOR vulnerability
    cur.execute(f"SELECT * FROM orders WHERE user_id={uid}")
    orders = cur.fetchall()
    return render_template('orders.html', orders=orders)

# ---------------- ADMIN PANEL ----------------
@app.route('/admin')
def admin():
    cur = mysql.connection.cursor()
    # ❌ Broken access control
    cur.execute("SELECT * FROM users")
    users = cur.fetchall()
    return render_template('admin.html', users=users)

# ---------------- LOGOUT ----------------
@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

# ---------------- RUN ----------------
if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000, debug=True)
