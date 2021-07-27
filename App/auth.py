from flask import Blueprint
from flask import render_template, request, redirect, flash
from werkzeug.security import generate_password_hash, check_password_hash
from app import db
from flask_login import login_user, logout_user, login_required
import models
import re

auth = Blueprint('auth', __name__)


def testPassword(Password):  # returns false if password invalid true if valid
    is_special = False  # if special characters is present
    is_letter = False  # if letter is present
    is_number = False  # if number is present

    length = len(Password)  # length of password
    if length >= 8:
        for x in range(0, length):
            current = Password[x]
            p = re.compile('[@_!#$%^&*()<>?/|}{~:]')

            if p.search(current) != None or '[' in Password or ']' in Password:
                is_special = True

            p = re.compile('([A-Za-z])')

            if p.search(current) != None:
                is_letter = True

            p = re.compile('([0-9])')

            if p.search(current) != None:
                is_number = True

    return is_letter and is_special and is_number




def hasSpace(check):
    space = False
    for x in range(0 , len(check)):
        if check[x] == ' ':
            space = True

    return space


@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')

    nameoremail = request.form.get('nameoremail')
    password = request.form.get('password')
    user = models.User.query.filter((models.User.name == nameoremail) | (models.User.email == nameoremail)).first()

    if user and check_password_hash(user.password, password):
        login_user(user)
        return redirect('/')
    else:
        flash('Incorrect username or password.')
        return redirect('/login');


@auth.route('/logout')
def logout():
    logout_user()
    return redirect('/')


@auth.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template('register.html')

    email = request.form.get('email')
    name = request.form.get('name')
    password = request.form.get('password')
    confirm = request.form.get('confirm')

    if password != confirm:
        flash('Passwords must match.');
        return redirect('/register');

    existing_user = models.User.query.filter_by(name=name).first()
    if existing_user:
        flash('A user already exists with that name.')
        return redirect('/register')

    if hasSpace(name):
        flash('Invalid username must not contain space.')
        return redirect('/register')

    if len(name) == 0:
        flash('Invalid must input username')
        return redirect('/register')

    existing_email = models.User.query.filter_by(email=email).first()
    if existing_email:
        flash('A user already exists with that email.')
        return redirect('/register')

    if hasSpace(email):
        flash('Invalid email must not contain space.')
        return redirect('/register')


    if not (testPassword(password)):
        flash('Invalid password must be 8 characters long with a letter, number, and special character.')
        return redirect('/register')

    if hasSpace(password):
        flash('Invalid password must not contain space.')
        return redirect('/register')

    hashed_password = generate_password_hash(password, method='pbkdf2:sha512')
    user = models.User(
        name=name,
        email=email,
        password=hashed_password
    )
    db.session.add(user)
    db.session.commit()

    flash('Your account was successfully registered. You may now log in.')
    return redirect('/login')
