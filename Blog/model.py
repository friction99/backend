from . import db,bcrypt
from flask_login import UserMixin
from Blog import login_manager
from datetime import datetime, timezone
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
class User(db.Model,UserMixin):
    id = db.Column(db.Integer,primary_key=True)
    fullname = db.Column(db.String(20),nullable=True)
    firstname = db.Column(db.String(20),nullable=True,unique=False)
    lastname = db.Column(db.String(20),nullable=True,unique=False)
    aboutme = db.Column(db.String(100),nullable=True,unique=False)
    email = db.Column(db.String(120),nullable=False,unique=True)
    password_hash = db.Column(db.String(60),nullable=False,unique=True)
    blogs = db.relationship('Blog',backref="writer",lazy=True)
    image_url = db.Column(db.String(255),nullable=True)
    @property
    def password(self):
        raise AttributeError("Cannot access this attribute")
    @password.setter
    def password(self,plain_text):
        self.password_hash = bcrypt.generate_password_hash(plain_text).decode('utf-8')
    def check_password(self,password):
        return bcrypt.check_password_hash(self.password_hash,password)
    
class Blog(db.Model):
    id = db.Column(db.Integer,primary_key=True)
    title = db.Column(db.String(20),nullable=False,unique=True)
    content = db.Column(db.String(2000),nullable = False)
    author = db.Column(db.Integer,db.ForeignKey('user.id'), nullable=False)
    image_url = db.Column(db.String(255),nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))  # Timestamp for creation
    updated_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))  # Timestamp for last update
    status = db.Column(db.String(20), nullable=False, default='pending')

    def to_dict(self):
        return {
            'id': self.id,
            'title': self.title,
            'content': self.content,
            'author': self.author,
            'image_url': self.image_url,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat(),
            'status': self.status
        }