from flask import Flask,url_for
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager
from flask_login import LoginManager
from flask_cors import CORS
import cloudinary
import cloudinary.uploader
from cloudinary.utils import cloudinary_url
from flask_migrate import Migrate
from dotenv import load_dotenv
import os
import requests
from itsdangerous import URLSafeTimedSerializer

db = SQLAlchemy()
bcrypt = Bcrypt()
load_dotenv()
app = Flask(__name__,static_folder="../build",static_url_path='/')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URI')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.getenv('APP_SECRET_KEY')

#Mail Configuration
app.config['SMTP2GO_API_KEY'] = os.getenv('SMTP2GO_API_KEY')
serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

db.init_app(app)
migrate = Migrate(app,db)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
CORS(app)
bcrypt.init_app(app)
jwt = JWTManager(app)
cloudinary.config( 
    cloud_name = "dkzfr6oay", 
    api_key = os.getenv('CLOUDINARY_API_KEY'), 
    api_secret = os.getenv('CLOUDINARY_SECRET_KEY'),
    secure=True
)

def upload_image(image_file):
    upload_result = cloudinary.uploader.upload(image_file)
    transformed_url = cloudinary.CloudinaryImage(upload_result['public_id']).build_url(
        fetch_format="auto",
        quality="auto",
        width=500,
        height=500,
        crop="auto",
        gravity="auto"
    )
    return transformed_url


def generate_reset_token(email):
    return serializer.dumps(email, salt='password-reset-salt')

def send_reset_email(user_email, token):
    reset_url = f'{os.getenv("FRONTEND_URL")}/reset_password/{token}'
    html_content = f'<p>To reset your password, click <a href="{reset_url}">here</a>.</p>'
    api_key = app.config['SMTP2GO_API_KEY']
    response = requests.post(
        "https://api.smtp2go.com/v3/email/send",
        headers={"Content-Type": "application/json"},
        json={
            "api_key": api_key,
            "to": [user_email],
            "sender": "btech15023.21@bitmesra.ac.in",
            "subject": 'Reset your Literary club account password',
            "html_body": html_content,
            "text_body": f"To reset your password, visit the following link: {reset_url}\n\nIf you did not make this request, simply ignore this email."
        }
    )
    print(response.json())
    if response.status_code != 200:
        print(f"Failed to send email: {response.json()}")
