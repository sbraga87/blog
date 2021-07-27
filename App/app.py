from flask import Flask
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager

app = Flask(__name__)


app.config['SECRET_KEY'] = b'\x17\xc8\xaa\xe6\x82\x1f\xee$\xbb\xa0Z\xdd3S7\xc5'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:crosby87@mysql/blog'
app.config['UPLOAD_FOLDER'] = 'static/uploads'
db = SQLAlchemy(app)


from models import *
db.create_all()


from main import main as blueprint_main
from auth import auth as blueprint_auth



login_manager = LoginManager()
login_manager.login_view = 'auth.login'
login_manager.init_app(app)


@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))


if __name__ == "__main__":
    app.register_blueprint(blueprint_main)
    app.register_blueprint(blueprint_auth)

    app.run(host="0.0.0.0", port=5000, use_reloader=True)
