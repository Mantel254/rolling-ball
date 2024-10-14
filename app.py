from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.exc import IntegrityError

app = Flask(__name__)

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://adminuser:password123@localhost/flask_app_db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = 'your_secret_key'  # Set a secret key for session management
db = SQLAlchemy(app)

from sqlalchemy import ForeignKey
from sqlalchemy.orm import relationship

from sqlalchemy import Column, Integer, String, ForeignKey

class User(db.Model):
    __tablename__ = 'user'

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(20), nullable=False, unique=True)
    email = Column(String(40), nullable=False, unique=True)
    password = Column(String(1000), nullable=False)
    referral_id = Column(Integer, ForeignKey('user.id'))  # if you want a self-referential foreign key

    # Optional: If you want to have a relationship with the referrer
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
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password!', 'danger')  # Flash error message
            return redirect(url_for('home'))

    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        referral_id = request.form.get('referral_id')  # Use .get() for optional fields

        # Referral logic
        referred_by = User.query.filter_by(id=referral_id).first() if referral_id else None

        # Hash the password before saving it
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

        # Create a new user with the hashed password
        new_user = User(username=username, email=email, password=hashed_password, referral_id=referred_by.id if referred_by else None)

        try:
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful! Welcome!', 'success')  # Flash success message
            return redirect(url_for('index'))
        except IntegrityError:
            db.session.rollback()  # Rollback on error
            flash('Username or email already exists. Please choose different values.', 'danger')  # Flash error message
            return redirect(url_for('register'))

    return render_template('register.html')

# Main entry point
if __name__ == '__main__':
    # Wrap the table creation in the app context
    with app.app_context():
        db.create_all()  # Create database tables

    # Run the Flask app
    app.run(debug=True)
