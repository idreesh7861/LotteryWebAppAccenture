# IMPORTS
import logging
from datetime import datetime

import pyotp
from flask import Blueprint, render_template, flash, redirect, url_for, session, request
from flask_login import login_required, LoginManager, logout_user, login_user, current_user
from markupsafe import Markup

from app import db, app, logger
from models import User
from users.forms import RegisterForm, LoginForm, PasswordForm

# CONFIG
users_blueprint = Blueprint('users', __name__, template_folder='templates')


# VIEWS
# view registration
@users_blueprint.route('/register', methods=['GET', 'POST'])
def register():
    # create signup form object
    form = RegisterForm()

    # if request method is POST or form is valid
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        # if this returns a user, then the email already exists in database

        # if email already exists redirect user back to signup page with error message so user can try again
        if user:
            flash('Email address already exists')
            return render_template('users/register.html', form=form)

        # create a new user with the form data
        new_user = User(email=form.email.data,
                        firstname=form.firstname.data,
                        lastname=form.lastname.data,
                        phone=form.phone.data,
                        dob=form.dob.data,
                        postcode=form.postcode.data,
                        password=form.password.data,
                        role='user')

        # add the new user to the database
        db.session.add(new_user)
        db.session.commit()
        logger.warning('SECURITY - User registration [%s, %s]', form.email.data, request.remote_addr)
        session['email'] = new_user.email

        # sends user to register 2fa page
        return redirect(url_for('users.setup_2fa'))
    # if request method is GET or form not valid re-render signup page
    return render_template('users/register.html', form=form)


# view user login
@users_blueprint.route('/login', methods=['GET', 'POST'])
def login():
    # Set Authentication Attempts if it does not already exist for the current session
    if not session.get('authentication_attempts'):
        session['authentication_attempts'] = 0

    # Create login form obnject
    log_form = LoginForm()

    # If form is valid
    if log_form.validate_on_submit():
        # Read inputs from form
        email = log_form.email.data
        password = log_form.password.data
        pin = log_form.pin.data

        # Pull user account by email
        user = User.query.filter_by(email=email).first()

        # If any of the inputs are invalid
        if not user or not user.verify_password(
                log_form.password.data) or not user.verify_pin or not user.verify_postcode(log_form.postcode.data):
            # Log failed login attempt
            logger.warning('SECURITY - Failed Log in Attempt [%s, %s]', email, request.remote_addr)
            # Increase failed Login Attempts
            session['authentication_attempts'] += 1
            # If there are too many authentication attempts
            if session.get('authentication_attempts') >= 3:
                flash(Markup('Number of incorrect login attempts exceeded.'
                             'Please click <a href="/reset">here</a> to reset'))
                return render_template('users/login.html')
            # Print to user current attempts remaining
            attempts_remaining = 3 - session.get('authentication_attempts')
            flash(
                'Please check your login details and try again, {} login attempts remaining'.format(attempts_remaining))
            return render_template('users/login.html', log_form=log_form)
        else:
            # On Successful Login
            login_user(user)
            # Log users login Time and IP
            current_user.last_login = current_user.current_login
            current_user.current_login = datetime.now()
            current_user.last_login_ip = current_user.current_login_ip
            current_user.current_login_ip = request.remote_addr

            # Update Successful Login counter
            if current_user.successful_logins is None:
                current_user.successful_logins = 1
            else:
                current_user.successful_logins = current_user.successful_logins + 1

            # Commit Updates to database
            db.session.commit()
            # Log User's Login and redirect where necessary
            logger.warning('SECURITY - Log in [%s, %s, %s]', current_user.id, email, request.remote_addr)
            if current_user.role == "admin":
                return redirect(url_for("admin.admin"))
            else:
                return redirect(url_for("lottery.lottery"))
    return render_template('users/login.html', log_form=log_form)


@users_blueprint.route('/setup_2fa')
def setup_2fa():
    if 'email' not in session:
        return redirect(url_for('index'))
    user = User.query.filter_by(email=session['email']).first()
    if not user:
        del session['email']
        return redirect(url_for('index'))
    return render_template('users/setup_2fa.html', email=user.email, uri=user.get_2fa_uri()), 200, {
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'
    }


@users_blueprint.route('/update_password', methods=['GET', 'POST'])
@login_required
def update_password():
    form = PasswordForm()

    if form.validate_on_submit():

        # IF STATEMENT: check if current password entered by user does not match current password stored for user in the database.
        if form.current_password.data != current_user.password:
            flash('Current Password does not match records, try again')
            return render_template('users/update_password.html', form=form)
        # IF STATEMENT: check if new password entered by the user matches current password stored for user in the database.
        if form.new_password.data == current_user.password:
            flash('New Password is the same as Current Password. Enter a new password')
            return render_template('users/update_password.html', form=form)
        current_user.password = form.new_password.data
        db.session.commit()
        flash('Password changed successfully')

        return redirect(url_for('users.account'))

    return render_template('users/update_password.html', form=form)


# view user account
@users_blueprint.route('/account')
@login_required
def account():
    return render_template('users/account.html',
                           acc_no=current_user.id,
                           email=current_user.email,
                           firstname=current_user.firstname,
                           lastname=current_user.lastname,
                           phone=current_user.phone,
                           dob=current_user.dob,
                           postcode=current_user.postcode)


@users_blueprint.route('/logout')
@login_required
def logout():
    logger.warning('SECURITY - Log out [%s, %s, %s]', current_user.id, current_user.email, request.remote_addr)
    logout_user()
    return redirect(url_for('index'))


@users_blueprint.route('/reset')
def reset():
    session['authentication_attempts'] = 0
    return redirect(url_for('users.login'))


@app.errorhandler(400)
def internal_error(error):
    return render_template('400.html'), 400


@app.errorhandler(403)
def internal_error(error):
    return render_template('403.html'), 403


@app.errorhandler(404)
def internal_error(error):
    return render_template('404.html'), 404


@app.errorhandler(500)
def internal_error(error):
    return render_template('500.html'), 500


@app.errorhandler(503)
def internal_error(error):
    return render_template('503.html'), 503
