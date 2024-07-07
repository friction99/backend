import re
from Blog import db, app
from flask import request, jsonify,url_for
from flask_restful import reqparse
from Blog.model import User, Blog
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from flask_login import login_user, logout_user, login_required, current_user
from Blog import upload_image
import os 
from Blog import load_dotenv
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
from itsdangerous import URLSafeTimedSerializer
from Blog import generate_reset_token,send_reset_email,serializer
sendgrid_api_key = os.getenv('SENDGRID_API_KEY')

# Argument parsers
register_post_args = reqparse.RequestParser()
register_login_args = reqparse.RequestParser()
blog_post_args = reqparse.RequestParser()

register_post_args.add_argument("email", type=str, help="An email is required", required=True)
register_post_args.add_argument("fullname", type=str, help="fullname is required", required=True)
register_post_args.add_argument("password", type=str, help="Password is required", required=True)

register_login_args.add_argument("email", type=str, help="An email is required", required=True)
register_login_args.add_argument("password", type=str, help="Password is required", required=True)

blog_post_args.add_argument("title", type=str, help="Title is required", required=True)
blog_post_args.add_argument("content", type=str, help="Content is required", required=True)

@app.route('/')
def index():
    return app.send_static_file('index.html')

@app.route('/api/blog/register', methods=['POST'])
def register():
    args = register_post_args.parse_args()
    email = args['email']
    fullname = args['fullname']
    password = args['password']
    if email is None or fullname is None or password is None:
        return jsonify({"message": "Missing required parameters"}), 400
    email_check = re.match(r'^([a-zA-Z0-9._%-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$', email)
    if not email_check:
        return jsonify({"message": "Invalid email format"}), 400
    user = User.query.filter_by(email=email).first()
    if user:
        return jsonify({"message": 'Account Already exists'}), 409
    else:
        new_User = User(email=email, fullname=fullname, password=password)
        db.session.add(new_User)
        db.session.commit()
        access_token = create_access_token(identity=new_User.fullname)
        return jsonify({
            "message": "User registered successfully",
            "user": {
                "id": new_User.id,
                "email": new_User.email,
                "username": new_User.fullname
            },
            'access_token': access_token
        }), 201

@app.route('/api/blog/login', methods=['POST'])
def login():
    args = register_login_args.parse_args()
    email = args['email']
    password = args['password']
    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({'message': 'Any User with this fullname does not exist'}), 404
    if user.check_password(password):
        access_token = create_access_token(identity=user.fullname)
        login_user(user)
        return jsonify({
            "message": "Login Successful",
            "access_token": access_token,
            "id":user.id
        }), 200
    else:
        return jsonify({'message': 'Incorrect Details'}), 401

@app.route('/api/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    return jsonify({
        'message': 'Logged out'
    }), 200

@app.route('/api/blogspot/get', methods=['GET'])
@jwt_required()
def getblogs():
    blogs = Blog.query.filter_by(status='approved').all()
    return jsonify([blog.to_dict() for blog in blogs]),200

@app.route('/api/blogspot/post', methods=['POST'])
@jwt_required()
def post_blog():
    title = request.form.get('title')
    content = request.form.get('content')
    image_file = request.files.get('image')
    
    if not title or not content:
        return jsonify({"message": "Title and content are required"}), 400

    if not image_file:
        return jsonify({"message": "Image is missing"}), 400

    # Upload and transform image
    image_url = upload_image(image_file)

    fullname = get_jwt_identity()
    user = User.query.filter_by(fullname=fullname).first()
    
    if not user:
        return jsonify({"message": "User not found"}), 404

    new_blog = Blog(title=title, content=content, author=user.id, image_url=image_url)
    
    try:
        db.session.add(new_blog)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        return jsonify({"message": "Failed to create blog post", "error": str(e)}), 500

    return jsonify({
        "message": "Blog post created successfully",
        "blog": {
            "id": new_blog.id,
            "title": new_blog.title,
            "content": new_blog.content,
            "author": new_blog.author,
            "img_url":new_blog.image_url,
            "user_id":user.id
        }
    }), 201

@app.route('/api/blog/get/<int:user_id>',methods=['GET','POST'])
def get_User(user_id):
    if (request.method == 'GET'):
        user = User.query.filter_by(id=user_id).first()
        if not user :
            return jsonify({
                'message':'No User with such id exists'
            }),404
        blogs = Blog.query.filter_by(author=user.id, status='approved').all()
        blogs_submitted = Blog.query.filter_by(author=user.id).all()  
        if not blogs : 
            return jsonify({
                "fullname":user.fullname,
                "firstname":user.firstname,
                "lastname":user.lastname,
                "aboutme":user.aboutme,
                "email":user.email,
                "img_url":user.image_url,
                "blogs_submitted":[{'id':blog.id,'title':blog.title,'content':blog.content,'image_url':blog.image_url}for blog in blogs_submitted]
            })
        return jsonify({
            "fullname":user.fullname,
            "firstname":user.firstname,
            "lastname":user.lastname,
            "aboutme":user.aboutme,
            "email":user.email,
            "img_url":user.image_url,
            "blogs_submitted":[{'id':blog.id,'title':blog.title,'content':blog.content,'image_url':blog.image_url}for blog in blogs_submitted],
            "blogs": [{'id':blog.id,'title':blog.title,'content':blog.content,'image_url':blog.image_url}for blog in blogs]
        })
    else:
        user = User.query.filter_by(id=user_id).first()
        firstname = request.form.get('firstname')
        lastname = request.form.get('lastname')
        fullname = request.form.get('fullname')
        aboutme = request.form.get('aboutme')
        email = request.form.get('email')
        image = request.files.get('image')
        if not image or not firstname or not lastname or not fullname or not aboutme or not email:
            return jsonify({
                "message": "Missing credentials"
            }), 404
        image_url = upload_image(image)
        user.image_url = image_url
        user.firstname = firstname
        user.lastname = lastname
        user.aboutme = aboutme
        user.fullname = fullname
        user.email = email

        try:
            db.session.add(user)
            db.session.commit()
            # Debug statement after committing to the database
            print("User data updated in database:", user)
        except Exception as e:
            db.session.rollback()
            print("Database update failed:", e)
            return jsonify({
                "message": "Failed to update user data"
            }), 500

        return jsonify({
            "message": "User information updated successfully",
            "User": {
                "id": user.id,
                "fullname": user.fullname,
                "firstname": user.firstname,
                "lastname": user.lastname,
                "aboutme": user.aboutme,
                "img_url": user.image_url,
                "email": user.email
            }
        }), 201
    
@app.route('/api/blogspot/pending',methods=['GET'])
@jwt_required()
def get_pending_blogs():
    current_user = get_jwt_identity();
    if current_user['role'] != 'admin':
        return jsonify({'message':'Unauthorized'}),403
    pending_blogs = Blog.query.filter_by(status='pending').all()
    return jsonify([blog.to_dict() for blog in pending_blogs]),200

@app.route('/api/blogspot/approve/<int:blog_id>',methods=['POST'])
@jwt_required()
def approve_blog(blog_id):
    current_user = get_jwt_identity();
    if current_user['role'] != 'admin':
        return jsonify({'message':'Unauthorized'}),403
    blog = Blog.query.get(blog_id)
    if blog :
        blog.status = 'approved'
        db.session.commit()
        return jsonify({'message':'Blog approved'}),200
    return jsonify({'message':'Blog not found'}),404

@app.route('/api/admin/login',methods=['POST'])
def admin_login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    print(username,password)
    if username == os.getenv('ADMIN_USERNAME') and password == os.getenv('ADMIN_PASSWORD'):
        access_token = create_access_token(identity={'role':'admin'})
        return jsonify({'access_token':access_token}),200
    else :
        return jsonify({'message' : 'Invalid creds'}),401

    
@app.route('/api/forgot_password', methods=['POST'])
def forgot_password():
    data = request.get_json()
    email = data.get('email')
    user = User.query.filter_by(email=email).first()
    if user:
        token = generate_reset_token(user.email)
        send_reset_email(user.email, token)
        return jsonify({'message': 'Password reset link sent'}), 200
    return jsonify({'message': 'Email not found'}), 404

@app.route('/api/reset_password/<token>', methods=['POST'])
def reset_password(token):
    try:
        email = serializer.loads(token, salt='password-reset-salt', max_age=600)  # Token valid for 1 hour
    except:
        return jsonify({'message': 'The reset link is invalid or has expired.'}), 400

    data = request.get_json()
    new_password = data.get('password')
    user = User.query.filter_by(email=email).first()
    if user:
        user.password = new_password
        db.session.commit()
        return jsonify({'message': 'Your password has been updated.'}), 200
    return jsonify({'message': 'User not found.'}), 404