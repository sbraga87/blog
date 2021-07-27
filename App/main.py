from flask import Blueprint
from flask import render_template, request, redirect, flash, abort
from app import db, app
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.utils import secure_filename
import models
import os

main = Blueprint('main', __name__)


@main.route('/')
def index():
    if current_user and current_user.is_authenticated:
        return redirect('/home')
    else:
        return render_template('index.html', user=None)


@main.route('/home')
@login_required
def home():
    return render_template('index.html', user=current_user)


@main.route('/search')
@login_required
def search():
    query = request.args.get('s')
    return render_template('index.html',user=current_user, query=query, user_search=get_user_search_results(query))




def get_user_search_results(query):
    q = f"%{query}%"
    return db.session.query(models.User)\
                     .filter(models.User.name.like(q))\
                     .limit(5)\
                     .all()