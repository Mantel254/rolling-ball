from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.exc import IntegrityError
import requests
from requests.auth import HTTPBasicAuth
import json
import base64
import datetime

app = Flask(__name__)

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://.......'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = 'your_secret_key'  # Set a secret key for session management
db = SQLAlchemy(app)
# M-Pesa API credentials
consumer_key = ''
consumer_secret = ''
shortcode = ''
passkey = ''
callback_url = ''


from sqlalchemy import ForeignKey
from sqlalchemy.orm import relationship

from sqlalchemy import Column, Integer, String, ForeignKey

class User(db.Model):
    __tablename__ = 'user'

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(20), nullable=False, unique=True)
    email = Column(String(40), nullable=False, unique=True)
    password = Column(String(1000), nullable=False)
    phone = Column(String(15), nullable=False)  # Added phone number field
    first_name = Column(String(30), nullable=False)  # Added first name field
    last_name = Column(String(30), nullable=False)   # Added last name field
    referral_id = Column(Integer, ForeignKey('user.id'))  # Self-referential foreign key for referrals

    # Relationship for referrer
    referrer = relationship("User", remote_side=[id], backref='referrals')
# Home page (default landing page)
@app.route('/')
def home():
    return render_template('home.html')

# Home page
@app.route('/index')
def index():
    users = User.query.all()
    return render_template('index.html', users=users)

@app.route('/login_success')
def login_success():
    return render_template('login_success.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Find the user by username
        user = User.query.filter_by(username=username).first()

        # If the user exists and the password matches
        if user and check_password_hash(user.password, password):
            # Flash a personalized welcome message
            flash(f'{user.username}, welcome back!', 'success')
            
            # Store user information in session if needed
            session['user_id'] = user.id
            session['username'] = user.username
            
            return redirect(url_for('user', user_id=user.id))
        else:
            flash('Invalid username or password!', 'danger')  # Flash error message
            return redirect(url_for('home'))

    return render_template('login.html')

@app.route('/user/<int:user_id>')
def user(user_id):
    # Fetch the user data from the database
    user = User.query.get(user_id)
    
    if not user:
        flash('User not found', 'danger')
        return redirect(url_for('home'))
    
    # Pass the user information to the template
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
        referral_username = request.form.get('referral_id')  # Optional

        # Hash the password before saving it
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

        # Check if the referral username is provided
        referred_by = User.query.filter_by(username=referral_username).first() if referral_username else None
       

        # Create a new user with the hashed password
        new_user = User(
            first_name=first_name,
            last_name=last_name,
            username=username,
            email=email,
            password=hashed_password,
            phone=phone,
            referral_id=referred_by.id if referred_by else None
        )
        print(f"Referral ID: {new_user.referral_id}")

        try:
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful! Welcome!', 'success')  # Flash success message
            return redirect(url_for('home'))
        except IntegrityError:
            db.session.rollback()  # Rollback on error
            flash('Username or email already exists. Please choose different values.', 'danger')  # Flash error message
            return redirect(url_for('register'))

    return render_template('register.html')

# Flask route to render the payment form
@app.route('/')
def indx():
    return render_template('payment_form.html')

# Flask route to handle form submission and initiate M-Pesa payment
@app.route('/pay', methods=['POST'])
def pay():
    amount = request.form['amount']
    phone_number = request.form['phone_number']
    
    # Ensure the phone number is in the correct format for M-Pesa
    if phone_number.startswith('0'):
        phone = '254' + phone_number[1:]  # Adjust to correct format
    
    # Check if access token was generated successfully
    payment_response = mpesa_stk_push(amount,phone)
    if "error" in payment_response:
        return {"error": "Failed to process payment"}
    
    # Handle response and redirect to confirmation page
    return render_template('payment_confirmation.html', response=payment_response)



# Function to generate the M-Pesa access token
def generate_mpesa_token():
    api_url = 'https://sandbox.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials'
    r = requests.get(api_url, auth=HTTPBasicAuth(consumer_key, consumer_secret))
    if r.status_code == 200:
        mpesa_access_token = json.loads(r.text)
        print("Access Token:", mpesa_access_token['access_token'])  # Debugging print
        return mpesa_access_token['access_token']
    else:
        print("Failed to generate token:", r.status_code, r.text)
        return None
    
def mpesa_stk_push(amount,phone):
    consumer_key = ""
    consumer_secret = ""
    api_url = ""
    
    # Step 1: Get the access token
    try:
        r = requests.get(api_url, auth=HTTPBasicAuth(consumer_key, consumer_secret))
        r.raise_for_status()
        data = r.json()
        access_token = "Bearer " + data['access_token']
    except Exception as e:
        return {'success': False, 'message': 'Failed to generate access token', 'error': str(e)}
    
    # Step 2: Prepare STK Push request
    timestamp = datetime.datetime.now().strftime('%Y%m%d%H%M%S')
    business_short_code = "174379"  # Your paybill/till number
    passkey = ""
    
    # Encode the password
    password = base64.b64encode((business_short_code + passkey + timestamp).encode()).decode('utf-8')

    payload = {
        "BusinessShortCode": business_short_code,
        "Password": password,
        "Timestamp": timestamp,
        "TransactionType": "CustomerPayBillOnline",
        "Amount": amount,
        "PartyA": phone,  # Customer's phone number in international format
        "PartyB": business_short_code,
        "PhoneNumber": phone,
        "CallBackURL": "https://e5b9-45-14-71-21.ngrok-free.app/api/v1/mpesa/callback",
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
            payment_reference = stk_response.get("CheckoutRequestID")  # Get payment reference
            return {'success': True, 'message': 'STK push initiated successfully', 'payment_reference': payment_reference}
        else:
            return {'success': False, 'message': stk_response.get("errorMessage", "STK push failed")}
    except Exception as e:
        return {'success': False, 'message': 'STK push failed', 'error': str(e)}



# Main entry point
if __name__ == '__main__':
    # Wrap the table creation in the app context
    with app.app_context():
        db.create_all()  # Create database tables

    # Run the Flask app
    app.run(debug=True)
