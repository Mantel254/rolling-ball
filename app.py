from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_login import login_user, current_user, login_required, LoginManager, UserMixin
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.exc import IntegrityError
from requests.auth import HTTPBasicAuth
import requests
import json
import base64
import datetime

app = Flask(__name__)

app.secret_key = 'MY_kenya'

login_manager = LoginManager()
login_manager.init_app(app)

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://**********'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = 'your_secret_key'  # Set a secret key for session management
db = SQLAlchemy(app)

# M-Pesa API credentials
consumer_key = ''
consumer_secret = ''
shortcode = ''
passkey = ''
callback_url = ''

from sqlalchemy import Column, Integer, String, ForeignKey, Float
from sqlalchemy.orm import relationship

# Database Model
class User(UserMixin,db.Model):
    __tablename__ = 'user'

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(20), nullable=False, unique=True)
    email = Column(String(40), nullable=False, unique=True)
    password = Column(String(1000), nullable=False)
    phone = Column(String(15), nullable=False)
    first_name = Column(String(30), nullable=False)
    last_name = Column(String(30), nullable=False)
    referral_id = Column(Integer, ForeignKey('user.id'), nullable=True)  # Self-referential foreign key
    Amount = Column(Float, default=0.0)  # Field for balance amount
    status = db.Column(db.Integer, default=0)

    # Relationship for referrer
    referrer = relationship("User", remote_side=[id], backref='referrals')

# Home page (default landing page)
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/index')
def index():
    users = User.query.all()
    return render_template('index.html', users=users)

# Create a user loader callback
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/login_success')
def login_success():
    return render_template('login_success.html')

@app.route('/withdraw', methods=['POST'])
@login_required
def withdraw():
    amount = int(request.json.get('amount'))
    phone = request.json.get('phone')

    user = User.query.filter_by(id=current_user.id).first()

    # Check if amount is below minimum withdrawal
    if amount < 300:
        return jsonify({'status': 'error', 'message': 'Minimum withdrawal of Ksh 300'}), 400

    # Check if balance is sufficient
    if user.Amount < amount:
        return jsonify({'status': 'error', 'message': 'Insufficient balance'}), 400

    # Subtract amount from user balance
    user.Amount -= amount
    db.session.commit()

    return jsonify({'status': 'success', 'message': 'Successfully withdrawn'}), 200

# @app.route('/dashboard')
# @login_required  # Ensure the user is logged in
# def dashboard():
#     # Access current_user directly
#     username = current_user.username
#     return render_template('active.html', username=username)

@app.route('/dashboard')
@login_required  # Ensure that the user must be logged in to access this route
def dashboard():
    user = User.query.filter_by(username=current_user.username).first()  # Assuming `current_user` is defined and the user is logged in
    return render_template('active.html', amount=user.Amount, username=user.username)


# @app.route('/login', methods=['GET', 'POST'])
# def login():
#     if request.method == 'POST':
#         username = request.form['username']
#         password = request.form['password']

#         # Find the user by username
#         user = User.query.filter_by(username=username).first()

#         # If the user exists and the password matches
#         if user and check_password_hash(user.password, password):
#             flash(f'{user.username}, welcome back!', 'success')
            
#             # Store user information in session
#             session['user_id'] = user.id
#             session['username'] = user.username
            
#             # Check the user's status and redirect accordingly
#             if user.status == 0:
#                 return redirect(url_for('user'))  # Redirect to user.html
#             elif user.status == 1:
#                 return redirect(url_for('dashboard'))  # Redirect to active.html

#         flash('Invalid username or password!', 'danger')
#         return redirect(url_for('home'))

#     return render_template('login.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        # Store user information in session
        session['user_id'] = user.id
        session['username'] = user.username        

        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            flash(f'{user.username}, welcome back!', 'success')
            
            # Log the user in using Flask-Login
            login_user(user)  # Ensure this line is present

            # Check the user's status and redirect accordingly
            if user.status == 0:
                return redirect(url_for('user',user_id=user.id))  # Redirect to user.html
            elif user.status == 1:
                return redirect(url_for('dashboard'))  # Redirect to active.html            

            # Redirect to the dashboard after successful login
         #   return redirect(url_for('dashboard'))  # Redirect to dashboard

        flash('Invalid username or password!', 'danger')
        return redirect(url_for('home'))

    return render_template('login.html')



@app.route('/user/<int:user_id>')
def user(user_id):
    user = User.query.get(user_id)
    
    if not user:
        flash('User not found', 'danger')
        return redirect(url_for('home'))
    
    return render_template('user.html', username=user.username, email=user.email)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        username = request.form['username']
        email = request.form['email']
        phone = request.form['phone']
        password = request.form['password']
        referral_username = request.form.get('referral_id')

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        referred_by = User.query.filter_by(username=referral_username).first() if referral_username else None

        new_user = User(
            first_name=first_name,
            last_name=last_name,
            username=username,
            email=email,
            password=hashed_password,
            phone=phone,
            referral_id=referred_by.id if referred_by else None
        )
        try:
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful! Welcome!', 'success')
            return redirect(url_for('home'))
        except IntegrityError:
            db.session.rollback()
            flash('Username or email already exists. Please choose different values.', 'danger')
            return redirect(url_for('register'))

    return render_template('register.html')

@app.route('/pay', methods=['POST'])
def pay():
    amount = request.form['amount']
    phone_number = request.form['phone_number']

    # Convert phone number format if it starts with '0'
    if phone_number.startswith('0'):
        phone = '254' + phone_number[1:]

    payment_response = mpesa_stk_push(amount, phone)

    if payment_response.get('success'):
        # Retrieve the current user
        user = User.query.get(session['user_id'])

        # Update referral user's Amount if there is a referral ID
        if user.referral_id:
            referral_user = User.query.get(user.referral_id)
            if referral_user:
                referral_user.Amount += 100
                db.session.commit()

        # Update current user's status to 1 on successful payment
        user.status = 1
        db.session.commit()

        # Log the user in if not already logged in (optional)
        if not current_user.is_authenticated:
            login_user(user)  # Log in the user

        # Render the active.html page
        return render_template('active.html', username=user.username, email=user.email, amount=user.Amount)

    return render_template('payment_confirmation.html', response=payment_response)

def generate_mpesa_token():
    api_url = 'https://sandbox.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials'
    r = requests.get(api_url, auth=HTTPBasicAuth(consumer_key, consumer_secret))
    if r.status_code == 200:
        mpesa_access_token = json.loads(r.text)
        return mpesa_access_token['access_token']
    return None
    
def mpesa_stk_push(amount, phone):
    api_url = "https://sandbox.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials"
    
    try:
        r = requests.get(api_url, auth=HTTPBasicAuth(consumer_key, consumer_secret))
        r.raise_for_status()
        data = r.json()
        access_token = "Bearer " + data['access_token']
    except Exception as e:
        return {'success': False, 'message': 'Failed to generate access token', 'error': str(e)}
    
    timestamp = datetime.datetime.now().strftime('%Y%m%d%H%M%S')
    business_short_code = "174379"
    passkey = ""
    
    password = base64.b64encode((business_short_code + passkey + timestamp).encode()).decode('utf-8')

    payload = {
        "BusinessShortCode": business_short_code,
        "Password": password,
        "Timestamp": timestamp,
        "TransactionType": "CustomerPayBillOnline",
        "Amount": amount,
        "PartyA": phone,
        "PartyB": business_short_code,
        "PhoneNumber": phone,
        "CallBackURL": callback_url,
        "AccountReference": "AccountReference",
        "TransactionDesc": "Payment Description"
    }
    
    headers = {
        "Authorization": access_token,
        "Content-Type": "application/json"
    }
    
    stk_url = "https://sandbox.safaricom.co.ke/mpesa/stkpush/v1/processrequest"
    
    try:
        response = requests.post(stk_url, json=payload, headers=headers)
        response.raise_for_status()
        stk_response = response.json()
        
        if stk_response.get("ResponseCode") == "0":
            return {'success': True, 'message': 'STK push initiated successfully', 'payment_reference': stk_response.get("CheckoutRequestID")}
        else:
            return {'success': False, 'message': stk_response.get("errorMessage", "STK push failed")}
    except Exception as e:
        return {'success': False, 'message': 'STK push failed', 'error': str(e)}

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
