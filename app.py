# IMPORTS
import logging
import os
from functools import wraps

from dotenv import load_dotenv
from flask import Flask, render_template, request
from flask_login import LoginManager, current_user
from flask_qrcode import QRcode
from flask_sqlalchemy import SQLAlchemy
from flask_talisman import Talisman

# CONFIG
app = Flask(__name__)

# Load .env file and import values from .env
load_dotenv()

app.config['SECRET_KEY'] = os.getenv("SECRET_KEY")
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("SQLALCHEMY_DATABASE_URI")
app.config['SQLALCHEMY_ECHO'] = os.getenv("SQLALCHEMY_ECHO")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = os.getenv("SQLALCHEMY_TRACK_MODIFICATIONS")
app.config['RECAPTCHA_PUBLIC_KEY'] = os.getenv("RECAPTCHA_PUBLIC_KEY")
app.config['RECAPTCHA_PRIVATE_KEY'] = os.getenv("RECAPTCHA_PRIVATE_KEY")


# Set up Logger
class SecurityFilter(logging.Filter):
    def filter(self, record):
        return 'SECURITY' in record.getMessage()

logger = logging.getLogger()
logger.setLevel(logging.DEBUG)
file_handler = logging.FileHandler('lottery.log', 'a')
file_handler.setLevel(logging.WARNING)
file_handler.addFilter(SecurityFilter())
formatter = logging.Formatter('%(asctime)s : %(message)s', '%m/%d/%Y %I:%M:%S %p')
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

# initialise database
db = SQLAlchemy(app)
qrcode = QRcode(app)

# Set up Security Policy and Headers
csp = {
    'default-src': [
        '\'self\'',
        'https://cdnjs.cloudflare.com/ajax/libs/bulma/0.7.2/css/bulma.min.css'
    ],
    'frame-src': [
        '\'self\'',
        'https://www.google.com/recaptcha/',
        'https://recaptcha.google.com/recaptcha/'
    ],
    'script-src': [
        '\'self\'',
        '\'unsafe-inline\'',
        'https://www.google.com/recaptcha/',
        'https://www.gstatic.com/recaptcha/'
    ],
    'img-src': [
        'data:'
    ]
}
# Re-enable for SSL enforcement
# talisman = Talisman(app, content_security_policy=csp)

# Set up Login Manager
login_manager = LoginManager()
login_manager.login_view = 'users.login'
login_manager.init_app(app)

# Import models from user here to prevent circular import error
from models import User

@login_manager.user_loader
def load_user(id):
    return User.query.get(int(id))

# Set up Requires Roles Function
def requires_roles(*roles):
    def wrapper(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            if current_user.role not in roles:
                logger.warning('SECURITY - Unauthorised Access Attempt [%s, %s, %s, %s]', current_user.id,
                               current_user.email, current_user.role, request.remote_addr)
                return render_template('403.html')
            return f(*args, **kwargs)

        return wrapped

    return wrapper


# HOME PAGE VIEW
@app.route('/')
def index():
    return render_template('main/index.html')


# BLUEPRINTS
# import blueprints
from users.views import users_blueprint
from admin.views import admin_blueprint
from lottery.views import lottery_blueprint

#
# # register blueprints with app
app.register_blueprint(users_blueprint)
app.register_blueprint(admin_blueprint)
app.register_blueprint(lottery_blueprint)

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)
    # Re-enable for SSL enforcement
    # app.run(ssl_context=('cert.pem', 'key.pem'))
