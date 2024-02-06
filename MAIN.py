import os
import re
import math
import string
import random
import logging
import smtplib
from functools import wraps
import psycopg2
from math import ceil
from datetime import datetime
from datetime import timedelta
from collections import namedtuple
from email.mime.text import MIMEText
from flask_mail import Mail, Message
from flask import send_from_directory, jsonify
from requests import RequestException
from werkzeug.utils import secure_filename
from email.mime.multipart import MIMEMultipart
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, render_template, request, session, flash, redirect, url_for, g

app = Flask(__name__, static_folder='uploads', static_url_path='/uploads')

UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}

# Set session lifetime to 60 minutes (3600 seconds) == 1 hour
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=60)

app.config['SECRET_KEY'] = '*(SbXi=a<bV~8a4v@AWlOT-w'
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = 'intuitivers@gmail.com'
app.config['MAIL_PASSWORD'] = 'drgt nkad rddf vxhr'
app.config['MAIL_DEFAULT_SENDER'] = 'intuitivers@gmail.com'
mail = Mail(app)

# Database connection
conn = psycopg2.connect(database="rhispa", user="postgres",
                        password="perfect", host="localhost", port="5432")


# Teardown function to close the database connection
@app.teardown_appcontext
def close_db_connection(exception=None):
    db_connection = getattr(g, '_db_connection', None)
    if db_connection is not None:
        db_connection.close()


# Establish a connection to your PostgreSQL database
def get_db_connection():
    db_connection = getattr(g, '_db_connection', None)
    if db_connection is None:
        db_connection = g._db_connection = psycopg2.connect(database="rhispa", user="postgres", password="perfect",
                                                            host="localhost", port="5432")
    return db_connection


def get_old_email(user_id):
    cursor = conn.cursor()
    cursor.execute("SELECT email FROM accounts WHERE id = %s", (user_id,))
    email = cursor.fetchone()[0]
    cursor.close()
    return email


#  generate a random verification token
def generate_verification_token(length=64):
    characters = string.ascii_letters + string.digits
    return ''.join(random.choice(characters) for _ in range(length))


# def is_strong_password(password):
#    """
#    Validate if the password meets the criteria for a strong password.
#    Criteria:
#    - At least eight characters long
#    - Contains both uppercase and lowercase letters
#    - Contains at least one digit
#   - Contains at least one special character (e.g. !, @#$%^&*.)
#    """
#    # Regular expression pattern for a strong password
#    pattern = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%^*?&])[A-Za-z\d@$!%^*?&]{8,}$"
#    return bool(re.match(pattern, password))


def is_strong_password(password):
    # The Password must be at least eight characters long
    # and contain at least one space or one alphanumeric character
    return len(password) >= 8 and (
        re.search(r'\d', password) or re.search(r'[!@#$%^&*(),.?":{}|<>]', password) or ' ' in password)


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/about')
def about():
    return render_template('about.html')


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' in session:
            user_id = session['user_id']
            # Retrieve the user's role from the database
            cursor = conn.cursor()
            cursor.execute(
                "SELECT role FROM accounts WHERE id = %s", (user_id,))
            # role is the 18th column in the table accounts
            user_role = cursor.fetchone()[16]
            cursor.close()

            # Check if the user is an admin
            if user_role == 'admin':
                # If admin, proceed with the original route function
                return f(*args, **kwargs)
            else:
                flash(
                    'Access denied. You do not have permission to view this page.', 'error')
                # Redirect to a different route if not an admin
                return redirect(url_for('dashboard'))
        else:
            flash('You need to login first.', 'error')
            return redirect(url_for('login'))

    return decorated_function


@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    # Admin dashboard logic
    return render_template('admin_dashboard.html')  # the admin dashboard


def generate_security_pin(first_name, last_name, country, username):
    """Generate a security pin for account deletion.
    Extract the first letter from each field and convert to uppercase
    """
    first_letter_first_name = first_name[0].upper()
    first_letter_last_name = last_name[0].upper()
    first_letter_country = country[0].upper()
    first_letter_username = username[0].upper()

    # Combine the first letters to form the security PIN
    security_pin = f'{first_letter_first_name}{first_letter_last_name}{first_letter_country}{first_letter_username}'
    return security_pin


def send_security_pin_email(email, security_pin):
    try:
        # Create a message with the security PIN and send it to the user's email
        email_message = Message(
            'Security PIN for Account Deletion', recipients=[email])
        email_message.body = (
            f'Hello,\n\n'
            f'Your security PIN for account deletion is: {security_pin}\n\n'
            f'Please keep this PIN secure, as it will be used for account deletion purposes. If you lose this PIN, '
            f'please contact our support team for assistance. Please note that we may require additional information '
            f'to verify your identity.\n\n'
            f'Thank you for choosing us!\n\n'
            f'Best regards,\n'
            f'Perfect Company Team'
        )
        mail.send(email_message)

        return True  # Email sent successfully
    except smtplib.SMTPAuthenticationError:
        flash('Failed to authenticate with the email server. Please contact our support team for assistance.', 'error')
        return False  # Email sending failed due to authentication error
    except smtplib.SMTPException:
        flash('An error occurred while sending the email. Please contact our support team for assistance.', 'error')
        return False  # Email sending failed due to other SMTP-related issues


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        username = request.form['username']
        password = request.form['password']
        country = request.form['country']

        # Generate security PIN
        security_pin = generate_security_pin(
            first_name, last_name, country, username)

        # Validate the password strength
        if not is_strong_password(password):
            flash(
                'Password must be at least eight characters long and contain at least one uppercase, lowercase, digit,'
                'and special character.' 'error')
            return redirect(url_for('register'))

        # Hash the password using PBKDF2 with SHA-256 before storing it in the database
        hashed_password = generate_password_hash(
            password, method='pbkdf2:sha256', salt_length=8)

        # Check if the email and username already exist
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM accounts WHERE email = %s OR username = %s", (email, username))
        existing_user = cursor.fetchone()

        if existing_user:
            flash(
                'username or email address already in use.Use another email and or username', 'error')
            return redirect(url_for('register'))

        # Generate a random token for email verification
        verification_token = ''.join(random.choices(
            string.ascii_letters + string.digits, k=32))

        # Calculations of day, date, month and year of registration
        registration_date = datetime.now()
        day = registration_date.day
        month = registration_date.month
        year = registration_date.year

        # Insert the user data into the database
        cursor.execute(
            "INSERT INTO accounts (email, first_name, last_name, username, password, country, day, month, year,"
            " user_verified, security_pin) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) RETURNING id",
            (email, first_name, last_name, username, hashed_password, country, day, month, year, False,
             security_pin))
        # Get the id of the newly inserted account
        account_id = cursor.fetchone()[0]

        #  An SQL cursor named 'cursor' and a database connection named 'conn'
        cursor.execute(
            "INSERT INTO tokens (account_id, username, email, verification_token) VALUES (%s, %s, %s, %s)",
            (account_id, username, email, verification_token)
        )

        # Send an email verification message
        email_message = Message('Email Verification', recipients=[email])
        # local server is running on port 5000
        server_address = 'http://localhost:5000'
        email_message.body = (f'Click the following link to verify your email: {server_address}/verify/'
                              f'{verification_token}')
        mail.send(email_message)

        # Send security PIN email
        email_sent = send_security_pin_email(email, security_pin)

        if not email_sent:
            # Handle email sending failure
            return render_template('email_send_error.html')

        # Send a congratulatory email for social media account registration
        congratulatory_message = Message(
            'Welcome to Our Social Media Community', recipients=[email])
        congratulatory_message.body = (
            f'Hello,\n\n'
            f'Welcome to our social media community! We are delighted to have you on board. You have successfully registered '
            f'for our platform, and we can\'t wait for you to start connecting with others and exploring the exciting content '
            f'our community has to offer.\n\n'
            f'Here are a few things you can do to get started:\n'
            f'- Complete your profile: Add a profile picture and a short bio to let others know more about you.\n'
            f'- Connect with others: Find and connect with friends, family, and people with shared interests.\n'
            f'- Explore content: Dive into posts, photos, videos, and discussions shared by our vibrant community members.\n\n'
            f'If you have any questions or need assistance, feel free to reach out to our support team. Thank you for joining '
            f'us, and we hope you have a wonderful experience!\n\n'
            f'Best regards,\n'
            f'Your Social Media Community Team'
        )
        mail.send(congratulatory_message)

        conn.commit()
        cursor.close()

        return render_template('registration_success.html')

    return render_template('registration_form.html')


# Function to generate a 6-digit random token for 2FA accounts
def generate_token():
    two_fa_token = ''.join(random.choices(string.digits, k=6))
    # Print the generated token for debugging
    print(f"Generated Token: {two_fa_token}")
    return two_fa_token


# Function to insert 2FA token into the accounts table if 2FA is enabled for the user
def insert_2fa_token_to_table(user_id, token):
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    'SELECT "2fa_status" FROM accounts WHERE id = %s', (user_id,))
                enable_2fa = cursor.fetchone()

                if enable_2fa and enable_2fa[0] == 'T':
                    # Update the auth_token field and token_timestamp in the table accounts for the specific user
                    update_query = 'UPDATE accounts SET auth_token = %s, ttmp = %s WHERE id = %s'
                    token_timestamp = datetime.now()  # Get the current timestamp
                    cursor.execute(
                        update_query, (token, token_timestamp, user_id))
                    print(
                        f"Stored Token: {token} for User ID: {user_id}")  # Print the stored token and user ID for debugging
                    # Commit the changes to the database
                    conn.commit()

                else:
                    print(
                        f"2FA is not enabled for User ID: {user_id}. Token not stored.")

    except psycopg2.Error as db_error:
        print(f"Database error: {db_error}")
        flash('Database error occurred. Please try again later.', 'error')
        # handle database-specific error
    except RequestException as request_error:
        print(f"Network request error: {request_error}")
        flash('Network request error occurred. Please try again later.', 'error')
        # handle network-related error
    except ValueError as value_error:
        print(f"Value error: {value_error}")
        flash('Invalid value error occurred. Please check your input.', 'error')
        # handle value-related error
    except Exception as e:
        print(f"Unexpected error: {e}")
        flash('An unexpected error occurred. Please try again later.', 'error')
        conn.rollback()  # Rollback the transaction in case of an error


# Function to retrieve stored 2FA token from the database
def get_stored_2fa_token(user_id):
    with get_db_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT auth_token, ttmp FROM accounts WHERE id = %s", (user_id,))
            stored_token = cursor.fetchone()

    # If the stored_token is None, return an empty string to avoid NoneType errors
    return stored_token[0] if stored_token else ""


def send_2fa_token_email(email, token, username):
    # Print the token and email for debugging
    print(f"Sending token: {token} to email: {email}")
    msg = Message('Authentication Code for Your Account',
                  sender='intuitivers@gmail.com', recipients=[email])
    msg.body = (f'Hello {username},\n\n'
                f'We detected a new login attempt on your account. To continue, please enter the verification code '
                f'below:\n\n'
                f'Verification Code: {token}\n\n'
                f'Please enter this code to complete the login process. If you did not request this, '
                f'please ignore this email.\n\n'
                f'For your account security, if you did not initiate this login attempt, we recommend changing your '
                f'password immediately to prevent unauthorized access.\n\n'
                f'Thank you for using our service!\n'
                f'Best regards,\n'
                f'Perfect Company Team')
    mail.send(msg)


# Function to authenticate admins
def authenticate_admin(email, password):
    try:
        # Establish a database connection
        with get_db_connection() as conn:
            with conn.cursor() as cursor:
                # Check if the provided username and password match an admin account
                cursor.execute("SELECT * FROM accounts WHERE email = %s AND password = %s AND role = 'admin'",
                               (email, password))
                admin = cursor.fetchone()
                if admin:
                    return True
                else:
                    return False
    except psycopg2.Error as db_error:
        # Handle database errors here
        print(f"Database error: {db_error}")
        flash('Database error occurred. Please try again later.', 'error')
        return False  # Return False in case of database error
    except Exception as e:
        # Handle other unexpected errors here
        print(f"Unexpected error: {e}")
        flash('An unexpected error occurred. Please try again later.', 'error')
        return False  # Return False in case of unexpected error


@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        # that returns True if the username and password are correct for an admin
        if authenticate_admin(email, password):
            # Set the user's role in the session
            session['role'] = 'admin'
            # Redirect to the admin dashboard or any other admin-specific page
            return redirect(url_for('admin_dashboards'))
        else:
            # Handle incorrect login credentials, show an error message, etc.
            flash('Invalid email or password. Please try again.', 'error')
            return render_template('admin_login.html')

    # Render the admin login form template for GET requests
    return render_template('admin_login.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    # Check if the user's session is already active
    if 'user_id' in session:
        # User is already logged in, redirect to the dashboard
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        # Check if the 'remember_me' checkbox is checked
        remember_me = 'remember_me' in request.form

        # Check if the username exists in the database
        with get_db_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    "SELECT * FROM accounts WHERE username = %s", (username,))
                user = cursor.fetchone()

        # hashed password is the 6th column in table accounts
        if user and check_password_hash(user[5], password):
            print(f"User {username} found and password matched.")
            # Check if the user is verified

            if remember_me:
                # Set a long-duration session (for example, 30 days)
                session.permanent = True
                app.permanent_session_lifetime = timedelta(days=30)

            if user[12]:  # user_verified column is the 13th column in the table accounts
                print("User is verified.")
                # Check if 2FA is activated for the user's account
                if user[14] == 'T':  # 2fa_status column is the 15th column in the table accounts
                    print("2FA is enabled.")
                    # Generate a 6-digit token
                    token = generate_token()

                    # Print the token for debugging
                    print(f"Generated Token: {token}")

                    # Send the token to the user's email address and store it in the database
                    send_2fa_token_email(user[1],
                                         token,
                                         username)  # user[1] is the email address (2nd column in the table accounts)

                    # Insert the token into the table accounts
                    insert_2fa_token_to_table(user[0], token)

                    conn.commit()  # Commit the transaction to save the changes in the database
                    # Inside the '2FA is enabled' branch
                    print(
                        f"Setting session variables: user_id={user[0]}, username={user[4]}, email={user[1]}, "
                        f"first_name={user[2]}, last_name={user[3]}, 2fa_token={token}")
                    session['user_id'] = user[0]
                    session['username'] = user[4]
                    session['email'] = user[1]
                    session['first_name'] = user[2]
                    session['last_name'] = user[3]
                    session['2fa_token'] = token

                    # Before redirecting / rendering templates, print the session variables again to confirm their values
                    print(f"Session variables after setting: {session}")
                    # flash('enter the six digit sent to your email address to complete the login proces', 'success')
                    # Redirect to the 2FA verification page
                    return render_template('2fa_verification.html')

                elif user[14] == 'F':
                    print(f"2FA is not enabled. Token not stored.")
                    # Inside the login route, after setting session variables
                    # 2FA is not enabled, proceed to the dashboard
                    # Store user data in the session

                    session['user_id'] = user[0]
                    print(
                        f"Setting session variables: user_id={user[0]}, username={user[4]}, email={user[1]},"
                        f" first_name={user[2]}, last_name={user[3]}")
                    print(
                        f"user_id: {session['user_id']}, 2fa_token: {session.get('2fa_token')}")
                    # username is the 5th column in the table accounts
                    session['username'] = user[4]
                    # email is the 2nd column in the table accounts
                    session['email'] = user[1]
                    # first_name is the 3rd column in the table accounts
                    session['first_name'] = user[2]
                    # last_name is the 4th column in the table accounts
                    session['last_name'] = user[3]
                    print(f"Session variables after setting: {session}")
                    flash('Login successful.', 'success')
                    # Redirect to the dashboard after successful login
                    return redirect(url_for('dashboard'))

                else:
                    # 2FA is not enabled, proceed to the dashboard
                    # Store user data in the session
                    # Inside the login route, after setting session variables

                    session['user_id'] = user[0]
                    print(
                        f"user_id: {session['user_id']}, 2fa_token: {session.get('2fa_token')}")

                    # username is the 5th column in the table accounts
                    session['username'] = user[4]
                    # email is the 2nd column in the table accounts
                    session['email'] = user[1]
                    # first_name is the 3rd column in the table accounts
                    session['first_name'] = user[2]
                    # last_name is the 4th column in the table accounts
                    session['last_name'] = user[3]
                    print(f"Session variables after setting: {session}")

                    # Redirect to 2FA verification if 2FA is enabled
                    if user[14] == 'T':  # 2fa_status column is the 15th column in the table accounts
                        print("2FA is enabled. Redirecting to 2FA verification.")
                        return redirect(url_for('verify_2fa'))

                    flash('Login successful.', 'success')
                    # Redirect to the dashboard after successful login
                    return redirect(url_for('dashboard'))
            else:
                return render_template('account_not_verified.html')
        else:
            flash(
                'Not verified, check your email address, you should have a link to verify your account', 'error')
            return render_template('login_error.html')

    return render_template('login_form.html')


def get_stored_2fa_token_and_timestamp(user_id):
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cursor:
                # Retrieve auth_token and ttmp (token timestamp) from accounts table based on user_id
                cursor.execute(
                    "SELECT auth_token, ttmp FROM accounts WHERE id = %s", (user_id,))
                stored_token, token_timestamp = cursor.fetchone()
                return stored_token, token_timestamp

    except psycopg2.IntegrityError as integrity_error:
        # Handle integrity constraint violations (e.g., duplicate key) in the database
        print(f"Integrity Error: {integrity_error}")
        flash('Integrity error occurred. Please try again later.', 'error')
        return None, None

    except psycopg2.DataError as data_error:
        # Handle data-related errors (e.g., invalid data format) in the database
        print(f"Data Error: {data_error}")
        flash('Data error occurred. Please try again later.', 'error')
        return None, None

    except psycopg2.OperationalError as operational_error:
        # Handle operational errors (e.g., connection issues) with the database
        print(f"Operational Error: {operational_error}")
        flash('Operational error occurred. Please try again later.', 'error')
        return None, None

    except Exception as e:
        # Handle other unexpected errors
        print(f"Unexpected Error: {e}")
        flash('An unexpected error occurred. Please try again later.', 'error')
        return None, None


@app.route('/verify_2fa', methods=['POST'])
def verify_2fa():
    print("Verifying 2FA...")  # Print "Verifying 2FA ..." for debugging
    # Print session variables for debugging
    print(f"Session variables: {session}")
    if 'user_id' not in session or '2fa_token' not in session:
        flash('You need to be logged in to verify 2FA.', 'error')
        return redirect(url_for('login'))

    user_id = session['user_id']  # Retrieve user_id from the session
    entered_token = request.form['verification_code']
    # Retrieve stored token and timestamp from the database based on user_id
    stored_token, token_timestamp = get_stored_2fa_token_and_timestamp(user_id)

    # Print the entered token, stored token, and token timestamp for debugging
    print(f"Entered Token: {entered_token}")
    print(f"Stored Token: {stored_token}")
    print(f"Token Timestamp: {token_timestamp}")

    if stored_token and entered_token == stored_token:
        # Check if the token has expired (e.g., after 10 minutes)
        current_timestamp = datetime.now()
        token_expiration_time = token_timestamp + timedelta(minutes=2)
        if current_timestamp <= token_expiration_time:
            # Clear the stored token from the session after successful verification
            del session['2fa_token']

            flash(
                'Two-Factor Authentication verified successfully. You are now logged in.', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('The verification code has expired. Please request a new one.', 'error')
            return redirect(url_for('login'))
    else:
        flash('Invalid verification code. Please try again.', 'error')
        return redirect(url_for('login'))


@app.route('/verify/<token>', methods=['GET'])
def verify_email(token):
    cursor = conn.cursor()
    cursor.execute(
        "SELECT * FROM tokens WHERE verification_token = %s", (token,))
    token_data = cursor.fetchone()

    if token_data:
        # Check if the verification link has expired (valid for 30 minutes)
        # Verification_sent_time is in the 7th column
        verification_sent_time = token_data[6]
        current_time = datetime.now()

        # Calculate the time difference in minutes
        time_difference = (
            current_time - verification_sent_time).total_seconds() / 60

        if time_difference <= 30:  # the verification link is valid for 30 minutes
            # Update the 'user_verified' column to mark the user as verified in the table accounts
            cursor.execute(
                "UPDATE accounts SET user_verified = TRUE WHERE id = %s", (token_data[1],))

            # Delete the verification token from the table tokens after successful verification
            cursor.execute("DELETE FROM tokens WHERE id = %s",
                           (token_data[0],))
            conn.commit()
            cursor.close()
            flash('Account verified, you can now log in.')
            return redirect(url_for('login'))
        else:
            # Verification link has expired, delete the token from the table tokens
            cursor.execute("DELETE FROM tokens WHERE id = %s",
                           (token_data[0],))
            conn.commit()
            cursor.close()
            flash(
                'invalid verification token or has expired. Request a new token here.', 'error')
            return redirect(url_for('resend_verification'))
    else:
        return render_template('verification_error.html')


def get_followers_count(user_id):
    cursor = conn.cursor()
    cursor.execute(
        "SELECT COUNT(*) FROM followers WHERE following_id = %s", (user_id,))
    followers_count = cursor.fetchone()[0]
    cursor.close()
    return followers_count


def get_following_count(user_id):
    cursor = conn.cursor()
    cursor.execute(
        "SELECT COUNT(*) FROM followers WHERE follower_id = %s", (user_id,))
    following_count = cursor.fetchone()[0]
    cursor.close()
    return following_count


def format_registration_date(registration_date):
    month_name = registration_date.strftime('%B')  # Full month name
    day_with_suffix = registration_date.strftime('%d').lstrip('0').replace('0',
                                                                           '')  # Day with suffix (1st, 2nd, 3rd, etc.)
    day_name = registration_date.strftime('%A')  # Full day name
    year = registration_date.strftime('%Y')  # Year

    formatted_date = f" {day_name}, {month_name} {day_with_suffix} {year}"

    # Print the formatted date for debugging
    print("Formatted Date inside format_registration_date function:", formatted_date)

    return formatted_date


app.jinja_env.filters['format_registration_date'] = format_registration_date


@app.route('/dashboard')
def dashboard():
    if 'user_id' in session:
        user_id = session['user_id']
        # Fetch user data including role from the database based on user_id
        cursor = conn.cursor()
        cursor.execute(
            "SELECT username, profile_picture, role FROM accounts WHERE id = %s", (user_id,))
        user = cursor.fetchone()

        # Fetch the count of followers
        cursor.execute(
            "SELECT COUNT(*) FROM followers WHERE following_id = %s", (user_id,))
        followers_count = cursor.fetchone()[0]

        # Fetch the count of the following
        cursor.execute(
            "SELECT COUNT(*) FROM followers WHERE follower_id = %s", (user_id,))
        following_count = cursor.fetchone()[0]

        cursor.close()

        if user:
            username = user[0]
            profile_picture_filename = user[1] or 'default_profile_picture.jpg'
            profile_picture_url = url_for(
                'uploaded_file', filename=profile_picture_filename)
            user_role = user[2]  # Extract role from the database result

            # Print the username and role of the logged-in user
            print(f"Logged-in User's Username: {username}")
            print(f"Logged-in User's Role: {user_role}")

            # Print the usernames of followers and their profile URLs
            cursor = conn.cursor()
            cursor.execute("SELECT a.username, f.follower_id FROM accounts a "
                           "JOIN followers f ON a.id = f.follower_id "
                           "WHERE f.following_id = %s", (user_id,))
            followers_data = cursor.fetchall()
            cursor.close()
            for follower_data in followers_data:
                follower_username = follower_data[0]
                follower_id = follower_data[1]
                print(f"Follower Username: {follower_username}")
                print(
                    f"Follower Profile URL: {url_for('followers_profile', user_id=follower_id)}")

            # Pass user_id and user_role to the dashboard template
            return render_template('dashboard.html', username=username,
                                   profile_picture=profile_picture_url, followers_count=followers_count,
                                   following_count=following_count, user=user, user_id=user_id, user_role=user_role)
        else:
            flash('User not found.', 'error')
            return redirect(url_for('login'))
    else:
        flash('You need to login first.', 'error')
        return redirect(url_for('login'))


@app.route('/profile', methods=['GET'])
def profile():
    if 'user_id' in session:
        logged_in_user_id = session['user_id']
        # Get user_id from the query parameter
        user_id = request.args.get('user_id', type=int)

        if user_id is None:
            # If user_id is not provided in the query parameter, show the profile of the logged-in user
            user_id = logged_in_user_id

        # Fetch non-sensitive user data from the database based on user_id
        cursor = conn.cursor()
        cursor.execute("SELECT username, email, profile_picture,registration_date FROM accounts WHERE id = %s",
                       (user_id,))
        user = cursor.fetchone()
        cursor.close()

        if user:
            username = user[0]
            email = user[1]
            registration_date = user[3]
            profile_picture_filename = user[2] or 'default_profile_image.png'
            profile_picture_url = url_for(
                'uploaded_file', filename=profile_picture_filename)

            # Fetch followers and the following counts
            # Implement a function to get followers count
            followers_count = get_followers_count(user_id)
            # Implement a function to get the following count
            following_count = get_following_count(user_id)

            # Check if the logged-in user is following the user whose profile is being viewed
            is_following = False
            if user_id != logged_in_user_id:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM followers WHERE follower_id = %s AND following_id = %s",
                               (logged_in_user_id, user_id))
                is_following = cursor.fetchone() is not None
                cursor.close()

            print("Followers count:", followers_count)  # Print followers count
            # Print the following count
            print("Following count:", following_count)

            if user_id == logged_in_user_id:
                # If the user is viewing their own profile, show their full profile
                return render_template('profile.html', username=username,
                                       email=email, profile_picture=profile_picture_url,
                                       is_following=is_following, followers_count=followers_count,
                                       following_count=following_count, user_id=user_id,
                                       registration_date=registration_date)  # Pass registration_date to the template
            else:
                # If the user is viewing another user's profile, show the public profile template
                return render_template('public_profile.html', username=username,
                                       profile_picture=profile_picture_url, is_following=is_following,
                                       followers_count=followers_count, following_count=following_count,
                                       registration_date=registration_date)  # Pass registration_date to the template

        else:
            flash('User not found.', 'error')
            return redirect(url_for('login'))
    else:
        flash('You need to login first.', 'error')
        return redirect(url_for('login'))


@app.route('/edit_profile', methods=['GET', 'POST'])
def edit_profile():
    if 'user_id' in session:
        user_id = session['user_id']
        cursor = conn.cursor()

        if request.method == 'POST':
            # Get updated profile information from the form
            first_name = request.form['first_name']
            last_name = request.form['last_name']

            # Check which fields are included in the form submission and update only those fields
            if first_name:
                cursor.execute(
                    "UPDATE accounts SET first_name = %s WHERE id = %s", (first_name, user_id))
            if last_name:
                cursor.execute(
                    "UPDATE accounts SET last_name = %s WHERE id = %s", (last_name, user_id))

            # Commit the changes to the database
            conn.commit()

            flash('profile updated successfully', 'success')
            return redirect(url_for('account'))

        # Fetch user data from the database
        cursor.execute(
            "SELECT id, email, first_name, last_name FROM accounts WHERE id = %s", (user_id,))
        user = cursor.fetchone()
        cursor.close()

        if user:
            # Pass user data to the edit profile form
            return render_template('edit_profile_form.html', user=user)
        else:
            flash('User not found.', 'error')
            return render_template('user_not_found.html')
    else:
        return render_template('not_logged_in.html')


@app.route('/logout')
def logout():
    # Check if the user is logged in
    if 'user_id' in session:
        logged_out_userid = session.pop('user_id', None)
        logged_out_username = session.pop('username', None)
        # Print statement during debugging.
        print(
            f"User ID {logged_out_userid} and Username {logged_out_username} has been logged out.")
        flash('You have been logged out.', 'info')

    return redirect(url_for('login'))


def send_deleted_account_email(email):
    from_email = "intuitivers@gmail.com"  # email address
    password = "drgt nkad rddf vxhr"  # email password
    to_email = email

    msg = MIMEMultipart()
    msg['From'] = from_email
    msg['To'] = to_email
    msg['Subject'] = "Account Deletion"

    body = ("Your account has been successfully deleted. This email is to inform You that your account has been "
            "deleted successfully and you can register your new account again using this email: {email}.")
    msg.attach(MIMEText(body, 'plain'))

    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(from_email, password)
        text = msg.as_string()
        server.sendmail(from_email, to_email, text)
        server.quit()
        print("Email sent successfully")
    except Exception as e:
        print("Error: ", e)


@app.route('/resend_verification_email', methods=['GET', 'POST'])
def resend_verification_email():
    if request.method == 'POST':
        email = request.form['email']
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM accounts WHERE email = %s", (email,))
        user = cursor.fetchone()

        if user:
            if user[12]:  # Check if the user is already verified: user_verified is the 10th column
                return render_template('email_already_verified.html')
            else:
                # Generate a new verification token and update the verification_sent_time
                verification_token = ''.join(random.choices(
                    string.ascii_letters + string.digits, k=32))
                verification_sent_time = datetime.now()
                verification_token_expiration = verification_sent_time + timedelta(
                    minutes=10)  # Token expires after 10 minutes

                # Insert the new token into the table tokens
                cursor.execute(
                    "INSERT INTO tokens (account_id, username, email, verification_token, verification_sent_time,"
                    " verification_token_expiration) VALUES (%s, %s, %s, %s, %s, %s)",
                    (user[0], user[1], user[2], verification_token, verification_sent_time,
                     verification_token_expiration))
                conn.commit()

                # Send the new verification email
                email_message = Message(
                    'Email Verification', recipients=[email])
                server_address = 'http://localhost:5000'
                email_message.body = (f'Click the following link to verify your email: {server_address}/verify/'
                                      f'{verification_token}')
                mail.send(email_message)

                cursor.close()
                return render_template('new_verification_link_sent.html')
        else:
            cursor.close()
            flash('No user associated with the provided email address in our records.'
                  ' Please enter a valid email address', 'error')
            return redirect(url_for('resend_verification'))

    # Handle GET request
    return render_template('resend_verification_form.html')


@app.route('/resend_verification', methods=['GET', 'POST'])
def resend_verification():
    if request.method == 'POST':
        email = request.form['email']
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM accounts WHERE email = %s", (email,))
        user = cursor.fetchone()

        if user:
            if user[12]:  # Check if the user is already verified: user_verified is the 10th column
                return render_template('email_already_verified.html')

            else:
                # Generate a new verification token and update the verification_sent_time
                verification_token = ''.join(random.choices(
                    string.ascii_letters + string.digits, k=32))
                verification_sent_time = datetime.now()
                cursor.execute("UPDATE tokens SET verification_token = %s, verification_sent_time = %s "
                               "WHERE id = %s", (verification_token, verification_sent_time, user[0]))
                conn.commit()

                # Send the new verification email
                email_message = Message(
                    'Email Verification', recipients=[email])
                server_address = 'http://localhost:5000'
                email_message.body = (f'Click the following link to verify your email: {server_address}/verify/'
                                      f'{verification_token}')
                mail.send(email_message)

                cursor.close()
                return render_template('new_verification_link_sent.html')
        else:
            cursor.close()
            return render_template('email_not_found.html')

    # Handle GET request
    return render_template('resend_verification_form.html')


@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        email = request.form['email']

        cursor = conn.cursor()
        cursor.execute("SELECT * FROM accounts WHERE email = %s", (email,))
        user = cursor.fetchone()

        if user:
            if not user[12]:  # verified column is the 5th column in table accounts
                # Account is not verified, display an error message
                flash(
                    'Your account is not verified. Please verify your account to reset your password.', 'error')
                return redirect(url_for('reset_password'))

            # Generate a random token for password reset
            reset_password_token = ''.join(random.choices(
                string.ascii_letters + string.digits, k=32))

            # Get the username associated with the account
            # username is the fifth column in the table accounts
            username = user[4]

            # Store the reset token, username, email, security pin, and expiration time in the table tokens
            # Set expiration time to 0.5 hour from now
            expiration_time = datetime.now() + timedelta(minutes=30)
            cursor.execute(
                "INSERT INTO tokens (account_id, username, email, reset_password_token, "
                "reset_password_token_expiration) VALUES (%s, %s, %s, %s, %s)",
                (user[0], username, email, reset_password_token, expiration_time))
            conn.commit()
            cursor.close()

            # Send an email with the password reset link
            reset_link = f'http://localhost:5000/reset_password/{reset_password_token}'
            email_message = Message('Password Reset', recipients=[email])
            email_message.body = f'Click the following link to reset your password: {reset_link}'
            mail.send(email_message)

            flash(
                'Password reset instructions have been sent to your email. reset and log in again', 'success')
            return redirect(url_for('login'))

        else:
            return render_template('email_not_found.html')

    return render_template('reset_password_request.html')


@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password_token(token):
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM tokens WHERE reset_password_token = %s AND reset_password_token_expiration > %s",
                   (token, datetime.now()))
    token_data = cursor.fetchone()

    if token_data:
        # account_id is the 2nd column of the table tokens
        account_id = token_data[1]
        email = token_data[3]  # email is the 4th column of the table tokens

        if request.method == 'POST':
            new_password = request.form['password']
            # Hash the new password
            hashed_password = generate_password_hash(
                new_password, method='pbkdf2:sha256', salt_length=8)

            # Update the user's password in table accounts and clear the reset token
            cursor.execute(
                "UPDATE accounts SET password = %s WHERE id = %s", (hashed_password, account_id))

            cursor.execute(
                "DELETE FROM tokens WHERE reset_password_token = %s", (token,))

            conn.commit()
            cursor.close()

            # Email to inform user that the password has been reset
            email_message = Message(
                'Password Reset Successful', recipients=[email])
            email_message.body = (
                'Your password has been successfully reset. If you did not perform this action, please '
                'contact support at: intuitivers@gmail.com')
            mail.send(email_message)

            flash(
                'Password successfully reset. You can now log in with your new password.', 'success')
            return redirect(url_for('login'))

        else:
            return render_template('reset_password.html')

    else:
        return render_template('password_reset_link_expired.html')


def get_current_email(user_id):
    """
    Retrieve the current email address associated with the user ID from the database.
    :param user_id: User ID
    :return: Current email address or None if user is not found
    """
    cursor = conn.cursor()
    cursor.execute("SELECT email FROM accounts WHERE id = %s", (user_id,))
    current_email = cursor.fetchone()
    cursor.close()
    return current_email[0] if current_email else None


def email_exists(email):
    """
    Check if the given email address is already in use by another user in the database.
    :param email: Email address to check
    :return: True if email address exists, False otherwise
    """
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM accounts WHERE email = %s", (email,))
    existing_user = cursor.fetchone()
    cursor.close()
    return True if existing_user else False


def send_email(recipient, subject, body):
    msg = Message(subject, sender='intuitivers@example.com',
                  recipients=[recipient])
    msg.body = body

    try:
        mail.send(msg)
        return True  # Email sent successfully
    except Exception as e:
        # Handle email sending failure here (log the error)
        # print(f'Failed to send email: {e}')
        logging.error(f'Failed to send email: {e}')
        error_message = 'Failed to send email. Please try again later or contact support.'
        return render_template('error.html', error_message=error_message)


@app.route('/update_email', methods=['GET', 'POST'])
def update_email():
    if 'user_id' in session:
        if request.method == 'POST':
            new_email = request.form['new_email']
            # Get the old email address from the database
            old_email = get_current_email(session['user_id'])
            # Retrieve the username from the session
            username = session['username']

            # Check if the new email address is already in use by another user
            if email_exists(new_email):
                flash('Email address is already in use.', 'error')
                # Redirect to the update email form
                return redirect(url_for('update_email'))

            # Generate a new verification token
            verification_token = ''.join(random.choices(
                string.ascii_letters + string.digits, k=32))

            # Store the new email, verification token, and expiration time in table tokens
            verification_sent_time = datetime.now()
            verification_token_expiration = verification_sent_time + \
                timedelta(minutes=30)
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO tokens (account_id, username, email, verification_token, verification_sent_time, "
                "verification_token_expiration) VALUES (%s, %s, %s, %s, %s, %s)",
                (session['user_id'], session['username'], new_email, verification_token, verification_sent_time,
                 verification_token_expiration))
            conn.commit()
            cursor.close()

            # Send verification email to the new email address
            verification_link = f'http://localhost:5000/verify_new_email/{verification_token}'
            email_verification_body = f'Hello,\n\nA request has been made to update the email address associated with your account. If you made this request, please click the following link to verify your new email address: {verification_link}'
            email_verification_subject = 'Email Verification'

            send_email(new_email, email_verification_subject,
                       email_verification_body)

            # Send notification email to the old email address
            notification_body = f'Hello,\n\nYour email address associated with your account has been updated successfully. If you did not make this change, please contact support immediately.'
            notification_subject = 'Email Address Update Notification'

            send_email(old_email, notification_subject, notification_body)

            flash(
                'Verification email has been sent to your new email address. Notification email has been sent to your old email address. Check your inboxes for instructions.',
                'success')
            return redirect(url_for('update_email_success'))

        return render_template('update_email_form.html')
    else:
        flash('You need to log in first.', 'error')
        return redirect(url_for('update_email_success'))


@app.route('/update_email_success')
def update_email_success():
    flash('verify Your new email address then come back here', 'infor')
    return redirect(url_for('index'))


@app.route('/verify_new_email/<token>', methods=['GET'])
def verify_new_email(token):
    cursor = conn.cursor()
    cursor.execute(
        "SELECT * FROM tokens WHERE verification_token = %s", (token,))
    token_data = cursor.fetchone()

    if token_data:
        # Check if the verification link has expired (valid for 30 minutes)
        # Verification_sent_time is in the 6th column
        verification_sent_time = token_data[5]
        current_time = datetime.now()

        # Calculate the time difference in minutes
        time_difference = (
            current_time - verification_sent_time).total_seconds() / 60

        if time_difference > 30:
            # Verification link has expired, delete the token from the table tokens
            cursor.execute("DELETE FROM tokens WHERE id = %s",
                           (token_data[0],))
            conn.commit()
            cursor.close()

            flash(
                'Verification link has expired. Please request a new verification email.', 'error')
            return redirect(url_for('update_email'))

        else:
            # Update the 'user_verified' column to mark the user's new email as verified in the table accounts
            cursor.execute("UPDATE accounts SET user_verified = TRUE, email = %s WHERE id = %s",
                           (token_data[3], token_data[1]))
            # Delete the verification token from the table tokens after successful verification
            cursor.execute("DELETE FROM tokens WHERE id = %s",
                           (token_data[0],))
            conn.commit()
            cursor.close()

            # Constructing the confirmation email body and subject
            confirmation_email_body = (
                'Dear user,\n\n'
                'We are pleased to inform you that your email address has been successfully updated in our system. '
                'This change has been processed and verified.\n\n'
                'If you did not initiate this change, please contact our support team immediately.\n\n'
                'Best regards,\n'
                'Your App Team'
            )

            confirmation_email_subject = 'Email Address Update Confirmation'

            try:
                # Send confirmation email to the new email address
                send_email(
                    token_data[3], confirmation_email_subject, confirmation_email_body)

                # Send confirmation email to the old email address
                # Check if old and new email addresses are different
                if token_data[2] != token_data[3]:
                    send_email(
                        token_data[2], confirmation_email_subject, confirmation_email_body)

                flash(
                    'Your new email address has been verified successfully. Confirmation emails have been sent to both your old and new addresses.',
                    'success')
                return redirect(url_for('update_email_success'))
            except Exception as e:
                flash(
                    'Failed to send confirmation email. Please contact support.', 'error')
                return redirect(url_for('update_email'))

    flash('Invalid verification link. Please request a new verification email.', 'error')
    return redirect(url_for('update_email'))


# Function to check allowed file extensions
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/upload_profile_picture', methods=['POST'])
def upload_profile_picture():
    if 'user_id' in session:
        user_id = session['user_id']
        if 'profile_picture' in request.files:
            file = request.files['profile_picture']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

                # Save the file path to the user's profile picture in the database
                cursor = conn.cursor()
                # Update the 'profile_picture' column in the 'accounts' table with the uploaded profile file
                cursor.execute(
                    "UPDATE accounts SET profile_picture = %s WHERE id = %s", (filename, user_id))
                conn.commit()
                cursor.close()

                flash('Profile picture uploaded successfully.', 'success')
            else:
                flash(
                    'Invalid file format. Allowed formats: png, jpg, jpeg, gif', 'error')
        else:
            flash('No file part', 'error')
        # Redirect to the dashboard page to see the image
        return redirect(url_for('dashboard'))
    else:
        flash('You need to log in first.', 'error')
        return redirect(url_for('login'))


@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


@app.route('/upload_profile_image')
def upload_profile_image():
    return render_template('upload_profile_image.html')


@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        message = request.form['message']
        subject = request.form['subject']

        # Email your support team with the user's message
        support_email = 'intuitivers@gmail.com'  # support team's email address
        email_message = Message(
            f'{subject.upper()} from {name.title()}', recipients=[support_email])
        email_message.body = f'Name: {name.title()}\nEmail: {email.lower()}\n\nMessage:\n{message.upper()}'

        mail.send(email_message)

        flash('Message has been sent to our support team. We will get back to you soon!', 'success')
        # Redirect to the homepage page after submission
        return redirect(url_for('index'))

    return render_template('contact.html')


def get_user_posts(user_id, page=1, posts_per_page=2):
    global cursor
    try:
        cursor = conn.cursor()
        offset = (page - 1) * posts_per_page
        query = """
                SELECT posts.id, posts.title, posts.content, posts.created_at, posts.edited_at, 
                accounts.username, accounts.profile_picture, COUNT(likes.id) as num_likes
                FROM posts
                JOIN accounts ON posts.user_id = accounts.id
                LEFT JOIN likes ON posts.id = likes.post_id
                WHERE posts.user_id = %s
                GROUP BY posts.id, accounts.username, accounts.profile_picture
                ORDER BY posts.created_at DESC
                LIMIT %s OFFSET %s
                """
        cursor.execute(query, (user_id, posts_per_page, offset))
        posts = []
        for post_id, title, content, created_at, edited_at, username, profile_picture, num_likes in cursor.fetchall():
            post = {
                "id": post_id,
                "title": title,
                "content": content,
                "created_at": created_at,
                "edited_at": edited_at,
                "username": username,
                "profile_picture": profile_picture,
                "num_likes": num_likes
            }
            posts.append(post)
        return posts
    except Exception as e:
        print(f"Error: {e}")
        return []
    finally:
        cursor.close()


def get_total_user_posts(user_id):
    global cursor
    try:
        cursor = conn.cursor()
        query = "SELECT COUNT(*) FROM posts WHERE user_id = %s"
        cursor.execute(query, (user_id,))
        total_posts = cursor.fetchone()[0]
        return total_posts
    except Exception as e:
        print(f"Error: {e}")
        return 0
    finally:
        cursor.close()


def get_total_your_posts(user_id):
    global cursor
    try:
        cursor = conn.cursor()
        query = "SELECT COUNT(*) FROM posts WHERE user_id = %s"
        cursor.execute(query, (user_id,))
        total_posts = cursor.fetchone()[0]
        return total_posts
    except Exception as e:
        print(f"Error: {e}")
        return 0
    finally:
        cursor.close()


@app.route('/your_posts', methods=['GET'])
def your_posts():
    if 'user_id' in session:
        user_id = session['user_id']

        # Get page number from query parameters, default to 1 if not provided
        page = request.args.get('page', 1, type=int)
        posts_per_page = 3  # Number of posts to display per page

        # Fetch paginated posts for the logged-in user from the database
        user_posts = get_user_posts(user_id, page, posts_per_page)

        # Calculate the total number of user posts
        total_posts = get_total_your_posts(user_id)

        # Render the template with paginated user posts, total number of posts, posts per page, and pagination details
        return render_template('your_posts.html', user_posts=user_posts, total_posts=total_posts,
                               posts_per_page=posts_per_page, page=page)
    else:
        flash('You need to log in first.', 'error')
        return redirect(url_for('login'))


@app.route('/create_post', methods=['GET', 'POST'])
def create_post():
    if request.method == 'POST':
        if 'user_id' in session:
            user_id = session['user_id']
            # Retrieve user's data (email, first_name, last_name) from session
            email = session['email']
            first_name = session['first_name']
            last_name = session['last_name']
            content = request.form['content']
            title = request.form['title']

            # Insert the post into the database along with user information
            cursor = conn.cursor()
            cursor.execute("INSERT INTO posts (user_id, email, first_name, last_name, content, title)"
                           " VALUES (%s, %s, %s, %s, %s, %s)",
                           (user_id, email, first_name, last_name, content, title))
            conn.commit()
            cursor.close()

            flash('Post created successfully!', 'success')
            return redirect(url_for('view_posts'))
        else:
            flash('You need to log in first.', 'error')
            return redirect(url_for('login'))
    elif request.method == 'GET':
        # Handle GET request logic
        return render_template('create_post_form.html')


@app.route('/view_posts', methods=['GET'])
def view_posts():
    page = request.args.get('page', 1, type=int)
    posts_per_page = 2  # number of posts to display per page

    # Get a search query from URL parameters
    # Get a search query from URL parameters
    search_query = request.args.get('q', '').strip()
    # Get selected category from URL parameters
    category = request.args.get('category', 'all')

    offset = (page - 1) * posts_per_page

    # SQL query to search for posts based on selected category (title, content, or author)
    sql_condition = ""
    placeholders = []

    if category == 'title':
        sql_condition = 'LOWER(posts.title) LIKE LOWER(%s)'
        placeholders = [f'%{search_query}%']
    elif category == 'content':
        sql_condition = 'LOWER(posts.content) LIKE LOWER(%s)'
        placeholders = [f'%{search_query}%']
    elif category == 'author':
        sql_condition = 'LOWER(accounts.username) LIKE LOWER(%s)'
        placeholders = [f'%{search_query}%']
    elif category == 'all':
        sql_condition = 'LOWER(posts.title) LIKE LOWER(%s) OR LOWER(posts.content) LIKE LOWER(%s) OR LOWER(accounts.username) LIKE LOWER(%s)'
        placeholders = [f'%{search_query}%',
                        f'%{search_query}%', f'%{search_query}%']

    sql_query = f"""
        SELECT posts.id, posts.content, posts.created_at, posts.edited_at, posts.title, 
               accounts.username, accounts.profile_picture, COUNT(likes.id) as num_likes, 
               (posts.edited_at IS NOT NULL) as is_edited, posts.user_id 
        FROM posts 
        LEFT JOIN accounts ON posts.user_id = accounts.id 
        LEFT JOIN likes ON posts.id = likes.post_id 
        WHERE {sql_condition}
        GROUP BY posts.id, accounts.username, accounts.profile_picture 
        ORDER BY COALESCE(posts.edited_at, posts.created_at) DESC 
        LIMIT %s OFFSET %s
    """
    placeholders.extend([posts_per_page, offset])

    cursor = conn.cursor()
    cursor.execute(sql_query, tuple(placeholders))
    posts_data = cursor.fetchall()
    cursor.close()

    # Calculate the total number of posts that match the search criteria
    cursor = conn.cursor()
    count_query = f"""
               SELECT COUNT(DISTINCT posts.id)
               FROM posts
               LEFT JOIN accounts ON posts.user_id = accounts.id
               LEFT JOIN likes ON posts.id = likes.post_id
               WHERE {sql_condition}
           """
    cursor.execute(count_query, tuple(
        placeholders[:-2]))  # Exclude LIMIT and OFFSET from placeholders
    total_posts = cursor.fetchone()[0]
    cursor.close()

    # Calculate the total number of pages
    total_pages = ceil(total_posts / posts_per_page)

    # Check if no posts were found
    if total_posts == 0:
        no_results_message = f"No results found for '{search_query}'."
        return render_template('view_posts.html', no_results_message=no_results_message)

    # Create a message indicating the number of results
    search_results_message = f"Your search has resulted in {total_posts} result(s)."

    # Create named tuple for post-data
    Post = namedtuple('Post',
                      ['id', 'content', 'created_at', 'edited_at', 'title', 'username', 'profile_picture', 'num_likes',
                       'is_edited', 'user_id'])
    posts = [Post(id=post[0], content=post[1], created_at=post[2], edited_at=post[3], title=post[4], username=post[5],
                  profile_picture=post[6], num_likes=post[7], is_edited=post[8], user_id=post[9]) for post in
             posts_data]

    print("Total Posts:", total_posts)
    return render_template('view_posts.html', posts=posts, current_page=page,
                           total_pages=total_pages, pagination_range=range(
                               1, total_pages + 1),
                           search_query=search_query, selected_category=category,
                           search_results_message=search_results_message, total_posts=total_posts)


@app.route('/view_user_posts/<int:user_id>', methods=['GET'])
def view_user_posts(user_id):
    page = request.args.get('page', 1, type=int)
    posts_per_page = 2

    # Fetch paginated posts for the specific user
    posts = get_user_posts(user_id, page, posts_per_page)

    # Fetch the total number of posts for the user
    total_posts = get_total_user_posts(user_id)

    # Calculate total pages
    total_pages = math.ceil(total_posts / posts_per_page)

    # Fetch the user's profile picture
    cursor = conn.cursor()
    cursor.execute(
        "SELECT profile_picture FROM accounts WHERE id = %s", (user_id,))
    profile_picture = cursor.fetchone()[0]
    cursor.close()

    return render_template('user_posts.html', total_pages=total_pages, posts=posts,
                           user_id=user_id, profile_picture=profile_picture, total_posts=total_posts,
                           page=page, posts_per_page=posts_per_page)


@app.route('/like_post/<int:post_id>', methods=['POST'])
def like_post(post_id):
    if 'user_id' in session:
        user_id = session['user_id']
        new_like_status = False  # Initialize new_like_status outside the if block
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, like_status FROM likes WHERE post_id = %s AND user_id = %s", (post_id, user_id))
        existing_like = cursor.fetchone()

        # Get the post-title
        cursor.execute("SELECT title FROM posts WHERE id = %s", (post_id,))
        post_title = cursor.fetchone()[0]

        # Get the username of the user who liked the post
        cursor.execute(
            "SELECT username FROM accounts WHERE id = %s", (user_id,))
        username = cursor.fetchone()[0]

        if existing_like:
            like_id, like_status = existing_like
            # Toggle like_status (True to False or False to True)
            new_like_status = not like_status
            cursor.execute("UPDATE likes SET like_status = %s, post_title = %s, username = %s WHERE id = %s",
                           (new_like_status, post_title, username, like_id))
        else:
            cursor.execute("INSERT INTO likes (post_id, user_id, like_status, post_title, username) "
                           "VALUES (%s, %s, %s, %s, %s)", (post_id, user_id, True, post_title, username))

        conn.commit()
        cursor.close()

        # Get the updated number of likes for the post
        cursor = conn.cursor()
        cursor.execute(
            "SELECT COUNT(id) FROM likes WHERE post_id = %s AND like_status = TRUE", (post_id,))
        num_likes = cursor.fetchone()[0]
        cursor.close()

        if new_like_status:
            return jsonify({'status': 'liked', 'num_likes': num_likes})
        else:
            return jsonify({'status': 'disliked', 'num_likes': num_likes})
    else:
        return jsonify({'status': 'error', 'message': 'User not logged in'})


@app.route('/delete_post/<int:post_id>', methods=['POST'])
def delete_post(post_id):
    if 'user_id' in session:
        user_id = session['user_id']
        cursor = conn.cursor()

        # Check if the logged-in user is the owner of the post
        cursor.execute("SELECT user_id FROM posts WHERE id = %s", (post_id,))
        post_owner_id = cursor.fetchone()

        if post_owner_id and post_owner_id[0] == user_id:
            cursor.execute("DELETE FROM posts WHERE id = %s", (post_id,))
            conn.commit()
            cursor.close()

            flash('Post deleted successfully!', 'success')
        else:
            flash('You do not have permission to delete this post.', 'error')

        return redirect(url_for('dashboard'))
    else:
        flash('You need to log in first.', 'error')
        return redirect(url_for('login'))


@app.route('/edit_post/<int:post_id>', methods=['GET', 'POST'])
def edit_post(post_id):
    if 'user_id' in session:
        user_id = session['user_id']
        cursor = conn.cursor()

        if request.method == 'POST':
            new_content = request.form['content']
            new_title = request.form['title']

            # Check if the logged-in user is the owner of the post
            cursor.execute(
                "SELECT user_id FROM posts WHERE id = %s", (post_id,))
            post_owner_id = cursor.fetchone()

            if post_owner_id and post_owner_id[0] == user_id:
                edited_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

                cursor.execute(
                    "UPDATE posts SET content = %s, title = %s, edited_at = %s, is_edited = TRUE WHERE id = %s",
                    (new_content, new_title, edited_at, post_id))
                conn.commit()
                cursor.close()

                flash('Post updated successfully!', 'success')
                return redirect(url_for('view_posts'))
            else:
                flash('You do not have permission to edit this post.', 'error')
                return redirect(url_for('view_posts'))
        else:
            # Retrieve the current content and title of the post for pre-filling the edit form
            cursor.execute(
                "SELECT content, title FROM posts WHERE id = %s", (post_id,))
            post_data = cursor.fetchone()

            if post_data:
                content = post_data[0]
                title = post_data[1]
                return render_template('edit_post_form.html', post_id=post_id, content=content,
                                       title=title)
            else:
                flash('Post not found.', 'error')
                return redirect(url_for('view_posts'))
    else:
        flash('You need to log in first.', 'error')
        return redirect(url_for('login'))


@app.route('/user_posts', methods=['GET'])
def user_posts():
    if 'user_id' in session:
        user_id = session['user_id']

        # Get page number from query parameters, default to 1 if not provided
        page = request.args.get('page', 1, type=int)
        posts_per_page = 2  # Number of posts to display per page

        # Calculate the starting and ending indexes for pagination
        start_idx = (page - 1) * posts_per_page
        end_idx = start_idx + posts_per_page

        # Fetch paginated posts from the database based on user_id
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM posts WHERE user_id = %s ORDER BY created_at DESC", (user_id,))
        all_posts = cursor.fetchall()

        # Paginate the posts
        paginated_posts = all_posts[start_idx:end_idx]

        # Fetch total number of posts for the user
        total_posts = get_total_user_posts(user_id)

        cursor.close()

        return render_template('user_posts.html', posts=paginated_posts, page=page,
                               total_posts=total_posts, posts_per_page=posts_per_page)
    else:
        flash('You need to login first.', 'error')
        return redirect(url_for('login'))


@app.route('/follow/<int:user_id>', methods=['GET', 'POST'])
def follow_user(user_id):
    if 'user_id' in session:
        follower_id = session['user_id']

        # Check if the follower_id is the same as user_id
        if follower_id == user_id:
            flash('You cannot follow yourself.', 'error')
        else:
            # Check if the follow relationship already exists in the database
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM followers WHERE follower_id = %s AND following_id = %s",
                           (follower_id, user_id))
            existing_follow = cursor.fetchone()

            if not existing_follow:
                # If the relationship doesn't exist, insert a new record in the table followers
                cursor.execute("INSERT INTO followers (follower_id, following_id) VALUES (%s, %s)",
                               (follower_id, user_id))
                conn.commit()

                flash(f'You are now following user {user_id}', 'success')
            else:
                flash(f'You are already following user {user_id}', 'info')

            cursor.close()
    else:
        flash('You need to log in first.', 'error')

    # Get the post_id from the referrer URL to redirect the user back to the correct post
    return redirect(url_for('following'))


@app.route('/unfollow/<int:user_id>', methods=['GET', 'POST'])
def unfollow_user(user_id):
    if 'user_id' in session:
        follower_id = session['user_id']
        cursor = conn.cursor()

        # Check if the relationship exists in the table followers
        cursor.execute("SELECT * FROM followers WHERE follower_id = %s AND following_id = %s",
                       (follower_id, user_id))
        existing_relationship = cursor.fetchone()

        if existing_relationship:
            # Unfollow the user by removing the relationship from the table followers
            cursor.execute("DELETE FROM followers WHERE follower_id = %s AND following_id = %s",
                           (follower_id, user_id))
            conn.commit()
            cursor.close()

            flash(f'You have unfollowed user {user_id}', 'success')
        else:
            flash(f'You are not following user {user_id}', 'error')

    else:
        flash('You need to log in first.', 'error')

    return redirect(url_for('following'))


@app.route('/following')
def following():
    if 'user_id' in session:
        user_id = session['user_id']

        # Retrieve the list of users that the current user is following from the database
        cursor = conn.cursor()
        cursor.execute("SELECT a.username, a.id FROM accounts a "
                       "JOIN followers f ON a.id = f.following_id "
                       "WHERE f.follower_id = %s", (user_id,))
        following_users_data = cursor.fetchall()
        cursor.close()

        # Format the data for the following users
        following_users = [{'username': user_data[0], 'id': user_data[1]}
                           for user_data in following_users_data]

        # Print followed users' data for debugging
        print(f"User ID: {user_id}")
        print(f"Following Users' Data: {following_users}")

        # Pass the list of following users to the template for rendering
        return render_template('following.html', following_users=following_users)
    else:
        flash('You need to login first.', 'error')
        return redirect(url_for('login'))


@app.route('/followers_profile/<int:user_id>')
def followers_profile(user_id):
    cursor = conn.cursor()

    # Fetch user data based on user_id
    cursor.execute("SELECT username FROM accounts WHERE id = %s", (user_id,))
    user_data = cursor.fetchone()

    if user_data:
        username = user_data[0]

        # Fetch follower usernames from the database
        cursor.execute("SELECT a.id, a.username FROM accounts a "
                       "JOIN followers f ON a.id = f.follower_id "
                       "WHERE f.following_id = %s", (user_id,))
        followers_data = cursor.fetchall()

        # Print the fetched followers' data for debugging
        print(followers_data)

        # Create a list of dictionaries containing follower IDs and usernames
        follower_usernames = [
            {'id': follower[0], 'username': follower[1]} for follower in followers_data]

        # Check if the logged-in user is following the displayed user
        cursor.execute("SELECT COUNT(*) FROM followers WHERE follower_id = %s AND following_id = %s",
                       (session['user_id'], user_id))
        current_user_follows_this_user = cursor.fetchone()[0] > 0

        # Pass user data, follower usernames, and the follow relationship status to the template
        return render_template('followers_profile.html', username=username,
                               follower_usernames=follower_usernames,
                               current_user_follows_this_user=current_user_follows_this_user)
    else:
        flash('User not found.', 'error')
        return redirect(url_for('login'))


@app.route('/followers')
def followers():
    if 'user_id' in session:
        logged_in_user_id = session['user_id']

        # Fetch followers' data from the database
        cursor = conn.cursor()
        cursor.execute("SELECT a.username, a.id FROM accounts a "
                       "JOIN followers f ON a.id = f.follower_id "
                       "WHERE f.following_id = %s", (logged_in_user_id,))
        followers_data = cursor.fetchall()
        cursor.close()

        # Print the fetched followers' data for debugging
        print("Fetched followers' data:", followers_data)

        # Pass the list of followers to the template for rendering
        return render_template('following.html', followers=followers_data)
    else:
        flash('You need to login first.', 'error')
        return redirect(url_for('login'))


def check_if_user_is_following(follower_id, following_id):
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM followers WHERE follower_id = %s AND following_id = %s",
                   (follower_id, following_id))
    count = cursor.fetchone()[0]
    cursor.close()
    return count > 0


@app.route('/public_profile/<int:user_id>')
def public_profile(user_id):
    # Determine if the logged-in user is following the viewed profile user
    is_following = check_if_user_is_following(session.get('user_id'), user_id)

    # Determine if the viewed profile user is following the logged-in user
    is_followed = check_if_user_is_following(user_id, session.get('user_id'))

    # Retrieve user data from the database
    cursor = conn.cursor()
    cursor.execute(
        "SELECT username, profile_picture, registration_date FROM accounts WHERE id = %s", (user_id,))
    user_data = cursor.fetchone()

    if user_data:
        username = user_data[0]
        profile_picture_filename = user_data[1] or 'default_profile_image.png'
        profile_picture_url = url_for(
            'uploaded_file', filename=profile_picture_filename)
        registration_date = user_data[2]

        # Format the registration_date as desired
        formatted_registration_date = registration_date.strftime(
            "%B %Y, %d, %A")  # e.g., "November 2, 2023, Sunday"

        # Get the number of followers and following for the viewed profile user
        followers_count = get_followers_count(user_id)
        following_count = get_following_count(user_id)

        # Print the follower's username and their follower/the following counts
        print(
            f"Your follower {username} has {followers_count} followers and {following_count} following.")

        # Pass user data, formatted registration date, follow status, followers count, and following count to template
        return render_template('public_profile.html', username=username,
                               profile_picture=profile_picture_url,
                               registration_date=formatted_registration_date,
                               is_following=is_following,
                               is_followed=is_followed,
                               followers_count=followers_count,
                               following_count=following_count,
                               user_id=user_id)  # Pass user_id to the template
    else:
        flash('User not found.', 'error')
        return redirect(url_for('login'))


@app.route('/full_post/<int:post_id>', methods=['GET'])
def full_post(post_id):
    user_id = session.get('user_id')

    cursor = conn.cursor()
    cursor.execute("SELECT user_id FROM posts WHERE id = %s", (post_id,))
    post_owner_id = cursor.fetchone()

    if post_owner_id:
        # Check if the logged-in user is following the post-owner
        is_following = False
        if user_id:
            cursor.execute("SELECT * FROM followers WHERE follower_id = %s AND following_id = %s",
                           (user_id, post_owner_id[0]))
            is_following = cursor.fetchone() is not None

        # Retrieve post-details
        cursor.execute(
            "SELECT p.title, p.content, a.username, p.created_at, p.edited_at, p.is_edited, a.profile_picture "
            "FROM posts p "
            "JOIN accounts a ON p.user_id = a.id "
            "WHERE p.id = %s", (post_id,))
        post_data = cursor.fetchone()

        title = post_data[0]
        content = post_data[1]
        username = post_data[2]
        created_at = post_data[3]
        edited_at = post_data[4]
        is_edited = post_data[5]
        profile_picture = post_data[6]

        # Retrieve comments for the post
        cursor.execute("SELECT c.content, a.username FROM comments c JOIN accounts a ON c.user_id = a.id "
                       "WHERE c.post_id = %s",
                       (post_id,))
        comments_data = cursor.fetchall()

        # Fetch the total number of followers for the post-owner
        cursor.execute(
            "SELECT COUNT(*) FROM followers WHERE following_id = %s", (post_owner_id[0],))
        total_followers = cursor.fetchone()[0]

        cursor.close()

        Comment = namedtuple('Comment', ['content', 'username'])
        comments = [Comment(content=comment[0], username=comment[1])
                    for comment in comments_data]

        return render_template('full_post.html', title=title, content=content, username=username,
                               created_at=created_at, edited_at=edited_at, is_edited=is_edited,
                               profile_picture=profile_picture, post_id=post_id, user_id=user_id,
                               post_owner_id=post_owner_id[0], is_following=is_following,
                               total_followers=total_followers, comments=comments)
    else:
        cursor.close()
        flash('Post not found.', 'error')
        return redirect(url_for('view_posts'))


@app.route('/add_comment/<int:post_id>', methods=['POST'])
def add_comment(post_id):
    if 'user_id' in session:
        user_id = session['user_id']
        commenter_email = request.form['commenter_email']
        content = request.form['comment_content']

        # Fetch the username and email associated with the user_id from the database
        cursor = conn.cursor()
        cursor.execute(
            "SELECT username, email FROM accounts WHERE id = %s", (user_id,))
        user_data = cursor.fetchone()

        # Fetch the post-title associated with the post_id from the posts table
        cursor.execute("SELECT title FROM posts WHERE id = %s", (post_id,))
        post_data = cursor.fetchone()
        cursor.close()

        print("User ID:", user_id)
        print("Commenter Email:", commenter_email)
        print("Comment Content:", content)
        # Check if the provided email matches the
        if user_data and user_data[1] == commenter_email and post_data:
            # logged-in user's email and post-data exists
            commenter_username = user_data[0]
            post_title = post_data[0]
            # Print the post-title for debugging
            print("Post Title:", post_title)

            # Ensure content and post_title are not empty or None before inserting
            if content and post_title:
                cursor = conn.cursor()
                cursor.execute("INSERT INTO comments (post_id, user_id, username, email, content, post_title) "
                               "VALUES (%s, %s, %s, %s, %s, %s)",
                               (post_id, user_id, commenter_username, commenter_email, content, post_title))
                conn.commit()
                cursor.close()

                flash('Comment added successfully!', 'success')
                return redirect(url_for('full_post', post_id=post_id))
            else:
                flash('Comment content and post title are required.', 'error')
                print("Comment content or post title is empty.")
        else:
            flash('Invalid email address or post data. Please enter your own email address and '
                  'ensure the post exists.', 'error')
            print("Invalid email address or post data.")
    else:
        flash('You need to log in first.', 'error')
        print("User not logged in.")

    return redirect(url_for('full_post', post_id=post_id))


class Post:
    def __init__(self, id, title, content, profile_picture):
        """

        @type id: objects
        """
        self.id = id
        self.title = title
        self.content = content
        self.profile_picture = profile_picture


def retrieve_posts_by_user(user_id):
    # Create a cursor object using the connection
    cursor = conn.cursor()

    cursor.execute("SELECT p.id, p.title, p.content, a.profile_picture FROM posts p "
                   "JOIN accounts a ON p.user_id = a.id "
                   "WHERE p.user_id = %s", (user_id,))

    # Fetch all posts from the query result and create Post objects
    posts_data = cursor.fetchall()
    posts = [Post(id=row[0], title=row[1], content=row[2],
                  profile_picture=row[3]) for row in posts_data]
    for post in posts:
        print(
            f"Post ID: {post.id}, Title: {post.title}, Content: {post.content},"
            f" Profile Picture: {post.profile_picture}")

    # Close the cursor
    cursor.close()

    # Return the list of posts
    return posts


@app.route('/follower_posts/<int:user_id>')
def follower_posts(user_id):
    page = request.args.get('page', default=1, type=int)
    per_page = 2  # Number of posts per page

    # Retrieve posts by the user with user_id from your database
    # Implement this function based on your database schema
    posts = retrieve_posts_by_user(user_id)

    # Print some debug information
    print(f"User ID: {user_id}")
    print(f"Number of Posts: {len(posts)}")
    for post in posts:
        print(f"Post ID: {post.id}, Content: {post.content}")

        # Paginate the posts
    start_idx = (page - 1) * per_page
    end_idx = start_idx + per_page
    paginated_posts = posts[start_idx:end_idx]

    # Pass the posts data, user_id, and pagination information to the template
    return render_template('follower_posts.html', posts=paginated_posts, user_id=user_id, page=page,
                           per_page=per_page)


def retrieve_posts_by_following(user_id):
    cursor = conn.cursor()
    cursor.execute("SELECT p.id, p.title, p.content, a.profile_picture "
                   "FROM posts p "
                   "JOIN accounts a ON p.user_id = a.id "
                   "JOIN followers f ON p.user_id = f.follower_id "
                   "WHERE f.following_id = %s", (user_id,))

    posts_data = cursor.fetchall()
    posts = [Post(id=row[0], title=row[1], content=row[2],
                  profile_picture=row[3]) for row in posts_data]
    cursor.close()
    return posts


@app.route('/following_posts/<int:user_id>')
def following_posts(user_id):
    page = request.args.get('page', default=1, type=int)
    per_page = 2  # Number of posts per page

    # Retrieve posts by the user with user_id from your database
    # Implement this function based on your database schema
    posts = retrieve_posts_by_user(user_id)

    # Print some debug information
    print(f"User ID: {user_id}")
    print(f"Number of Posts: {len(posts)}")
    for post in posts:
        print(f"Post ID: {post.id}, Content: {post.content}")

        # Paginate the posts
    start_idx = (page - 1) * per_page
    end_idx = start_idx + per_page
    paginated_posts = posts[start_idx:end_idx]

    # Pass the posts data, user_id, and pagination information to the template
    return render_template('following_posts.html', posts=paginated_posts, user_id=user_id, page=page,
                           per_page=per_page)


def password_change(email, username):
    from_email = "intuitivers@gmail.com"  # email address
    password = "drgt nkad rddf vxhr"  # email password
    to_email = email

    msg = MIMEMultipart()
    msg['From'] = from_email
    msg['To'] = to_email
    msg['Subject'] = "Password changed"

    body = (f"Dear {username},\n\n"
            "We want to inform you that your password has been successfully changed. This email serves as a confirmation "
            "of the recent update. If you authorized this change, you can disregard this message.\n\n"
            "However, if you did not initiate this password change, it could indicate a security concern. We urge you to "
            "immediately contact our support team for further assistance. Your security is our top priority.\n\n"
            "Thank you for your attention and cooperation.\n\n"
            "Best regards,\n"
            "Perfect Company Team")
    msg.attach(MIMEText(body, 'plain'))

    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(from_email, password)
        text = msg.as_string()
        server.sendmail(from_email, to_email, text)
        server.quit()
        print("Email sent successfully")
    except Exception as e:
        print("Error: ", e)


@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if 'user_id' in session:
        user_id = session['user_id']
        username = session['username']
        cursor = conn.cursor()

        if request.method == 'POST':
            current_password = request.form['current_password']
            new_password = request.form['new_password']

            # Fetch the current hashed password from the database
            cursor.execute(
                "SELECT password, email FROM accounts WHERE id = %s", (user_id,))
            result = cursor.fetchone()
            stored_password, user_email = result[0], result[1]

            # Verify the current password provided by the user
            if check_password_hash(stored_password, current_password):
                # Check if the new password meets the strength requirements
                if is_strong_password(new_password):
                    # Hash the new password before updating it in the database
                    hashed_password = generate_password_hash(
                        new_password, method='pbkdf2:sha256', salt_length=8)

                    # Update the user's password in the database
                    cursor.execute(
                        "UPDATE accounts SET password = %s WHERE id = %s", (hashed_password, user_id))

                    # Clear all session data (log out user from all sessions)
                    session.clear()

                    # Commit the changes to the database
                    conn.commit()

                    # Send email notification to the user
                    password_change(user_email, username)

                    flash(
                        'Password changed successfully. You have been logged out from all sessions except the current one.',
                        'success')
                    return redirect(url_for('login'))
                else:
                    flash(
                        'Password must be at least 8 characters long and contain at '
                        'least one space and one alphanumeric character.',
                        'error')
            else:
                flash('Incorrect current password. Please try again.', 'error')

        return render_template('change_password.html')
    else:
        flash('You are not logged in. Please log in to change your password.', 'error')
        return redirect(url_for('login'))


@app.route('/settings', methods=['GET', 'POST'])
def settings():
    return render_template('settings.html')


@app.route('/account', methods=['GET', 'POST'])
def account():
    return render_template('account.html')


@app.route('/privacy')
def privacy():
    return render_template('privacy.html')


def update_2fa_status(email, status):
    conn = get_db_connection()
    with conn.cursor() as cursor:
        cursor.execute(
            'UPDATE accounts SET "2fa_status" = %s WHERE email = %s', (status, email))
    conn.commit()
    conn.close()


def check_2fa_status(email):
    email = str(email)  # Ensure email is a string
    with get_db_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                'SELECT "2fa_status", id, username FROM accounts WHERE email = %s', (email,))
            user_data = cursor.fetchone()
    if user_data:
        # 2FA status, user ID, and username
        return user_data[0], user_data[1], user_data[2]
    return None, None, None  # 2FA status, user ID, and username are None if user not found


def send_activation_email(email):
    msg = Message('2FA Activation',
                  sender='intuitivers@gmail.com', recipients=[email])
    msg.body = ('You requested to activate 2FA in your account and we did it, Now your account is protected with'
                ' additionals security layer of protection.  Yo receice this email to infrom you that your account has '
                'a 2FA enabled successfully. Thank you!')
    mail.send(msg)


@app.route('/activate_2fa', methods=['GET', 'POST'])
def activate_2fa():
    if 'user_id' not in session:
        flash('You need to be logged in to manage 2FA.', 'error')
        return redirect(url_for('login'))

    user_id = session['user_id']
    stored_email = session['email']  # Get stored email from the session
    username = session['username']

    with get_db_connection() as conn:
        with conn.cursor() as cursor:
            cursor.execute(
                'SELECT "2fa_status" FROM accounts WHERE id = %s', (user_id,))
            current_2fa_status = cursor.fetchone()[0]

    print(f'Logged-in user ID: {user_id}')
    print(f'Logged-in username: {username}')
    print(f'Stored email address: {stored_email}')

    if request.method == 'POST':
        # Get entered email from the form
        entered_email = request.form['email']
        entered_email = str(entered_email)  # Ensure entered_email is a string
        user_input = request.form['user_input'].lower()

        # Print the entered email address for 2FA activation
        print(f'Entered email address: {entered_email}')

        # Check if the entered email matches the stored email and if the entered input is valid
        if entered_email == stored_email:
            if user_input == 'deactivate' and current_2fa_status == 'T':
                update_2fa_status(stored_email, 'F')
                flash('2FA has been deactivated successfully.', 'success')

            elif user_input == 'deactivate' and current_2fa_status == 'F':
                flash('2FA is not activated yet so can not  deactivate.', 'success')

            elif user_input == 'activate' and current_2fa_status == 'T':
                flash(
                    'your account is already activated enter deactivate to deactivate it.', 'success')

            elif user_input == 'activate' and current_2fa_status == 'F':
                update_2fa_status(stored_email, 'T')
                send_activation_email(stored_email)
                flash(
                    '2FA has been activated successfully. An email has been sent to confirm.', 'success')
            else:
                flash('Invalid input or 2FA status. Please try again.', 'error')
        else:
            flash(
                'The entered email address does not match your stored email address.', 'error')

        return redirect(url_for('activate_2fa'))

    return render_template('activate_2fa.html', current_2fa_status=current_2fa_status)


def is_valid_email(email):
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    "SELECT COUNT(*) FROM accounts WHERE email = %s", (email,))
                count = cursor.fetchone()[0]
        # Return True if email exists in the database, else False
        return count > 0
    except Exception as e:
        print(f"Error validating email: {e}")
        return False


def is_valid_username(username):
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    "SELECT COUNT(*) FROM accounts WHERE username = %s", (username,))
                count = cursor.fetchone()[0]
        # Return True if username exists in the database, else False
        return count > 0
    except Exception as e:
        print(f"Error validating username: {e}")
        return False


def is_valid_password(email, password):
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    "SELECT password FROM accounts WHERE email = %s", (email,))
                stored_password = cursor.fetchone()
        # Return True if the provided password matches the stored password, else False
        return stored_password and check_password_hash(stored_password[0], password)
    except Exception as e:
        print(f"Error validating password: {e}")
        return False


def is_valid_security_pin(email, security_pin):
    try:
        with get_db_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    "SELECT security_pin FROM accounts WHERE email = %s", (email,))
                stored_security_pin = cursor.fetchone()
        # Return True if the provided security pin matches the stored security pin, else False
        return stored_security_pin and stored_security_pin[0] == security_pin
    except Exception as e:
        print(f"Error validating security pin: {e}")
        return False


@app.route('/delete_account', methods=['GET', 'POST'])
def delete_account():
    if 'user_id' not in session:
        flash('You need to be logged in to delete your account.', 'error')
        return redirect(url_for('login'))

    user_id = session['user_id']
    current_2fa_status, _, _ = check_2fa_status(session['email'])

    if current_2fa_status == 'T' and request.method == 'POST':
        entered_email = request.form.get('email')
        entered_username = request.form.get('username')
        entered_password = request.form.get('password')
        entered_security_pin = request.form.get('security_pin')

        # Print entered email for debugging
        print(f'Entered Email: {entered_email}')
        # Print entered username for debugging
        print(f'Entered Username: {entered_username}')
        # Print entered password for debugging
        print(f'Entered Password: {entered_password}')
        # Print entered security pin for debugging
        print(f'Entered Security Pin: {entered_security_pin}')

        # Validate email, username, password, and security pin
        if not is_valid_email(entered_email):
            flash('Invalid email address. Please enter a valid email.', 'error')
            return redirect(url_for('delete_account'))

        if not is_valid_username(entered_username):
            flash('Invalid username. Please enter a valid username.', 'error')
            return redirect(url_for('delete_account'))

        stored_password = is_valid_password(entered_email, entered_password)
        if not stored_password:
            flash('Invalid password. Please enter your correct password.', 'error')
            return redirect(url_for('delete_account'))
        else:
            # Print stored password for debugging
            print(f'Stored Password: {stored_password}')

        entered_security_pin_valid = is_valid_security_pin(
            entered_email, entered_security_pin)
        if not entered_security_pin_valid:
            flash('Invalid security pin. Please enter a valid security pin.', 'error')
            return redirect(url_for('delete_account'))
        else:
            # Print entered security pin for debugging
            print(f'Entered Security Pin: {entered_security_pin}')

        # Send 2FA token to user's email address
        two_fa_token = generate_token()  # Generate 2FA token
        send_2fa_token_email(session['email'], f'Your 2FA token for account deletion is: {two_fa_token}',
                             entered_username)

        # Store the token in the session for verification
        session['verification_token'] = two_fa_token
        flash('A 2FA token has been sent to your email address. Please check your email to confirm account deletion.',
              'info')
        return render_template('2fa_deletion_verification.html')

    elif current_2fa_status == 'F' and request.method == 'POST':
        # Delete the account since 2FA is not enabled
        with get_db_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    'DELETE FROM accounts WHERE id = %s', (user_id,))
                conn.commit()

        session.clear()
        flash('Your account has been deleted successfully.', 'success')
        return render_template('account_deleted_success.html')

    return render_template('confirm_delete_account.html')


def send_2fa_deletion_token_email(email, token):
    # Print the token and email for debugging
    print(f"Sending token: {token} to email: {email}")
    msg = Message('2FA Deletion Account Verification',
                  sender='intuitivers@gmail.com', recipients=[email])
    msg.body = (f'Hello,\n\n'
                f'We received a request to delete your account. To confirm this action, please enter the following '
                f'verification token within the next 2 minutes: {token}.\n\n'
                f'Please enter this token to complete the deletion process. If you did not make this request, '
                f'please ignore this email.\n\n'
                f'For your security, if you did not initiate this request, we recommend changing your password '
                f'immediately to prevent unauthorized access to your account.\n\n'
                f'Thank you for using our service!\n'
                f'Best regards,\n'
                f'Your App Name Team')
    mail.send(msg)


@app.route('/verify_2fa_deletion', methods=['POST'])
def verify_2fa_deletion():
    entered_token = request.form['verification_code']
    stored_token = session.get('verification_token')

    if stored_token and entered_token == stored_token:
        # Token is valid, proceed with account deletion
        user_id = session['user_id']
        with get_db_connection() as conn:
            with conn.cursor() as cursor:
                cursor.execute(
                    'DELETE FROM accounts WHERE id = %s', (user_id,))
                conn.commit()

        session.clear()
        flash('Your account has been deleted successfully.', 'success')
        return render_template('account_deleted_success.html')
    else:
        flash('Invalid verification code. Please try again.', 'error')
        return redirect(url_for('delete_account'))


if __name__ == '__main__':
    app.run(debug=True)
