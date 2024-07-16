import re
from sqlalchemy import or_
from Blog import db, app
from flask import request, jsonify,make_response
from flask_restful import reqparse
from Blog.model import User, Blog
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity,set_access_cookies,unset_jwt_cookies
from flask_login import login_user, logout_user, login_required, current_user
from Blog import upload_image,generate_admin_id
import os 
from Blog import load_dotenv
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
from itsdangerous import URLSafeTimedSerializer
from Blog import generate_reset_token,send_reset_email,serializer
sendgrid_api_key = os.getenv('SENDGRID_API_KEY')

# Argument parsers
register_post_args = reqparse.RequestParser()
blog_post_args = reqparse.RequestParser()

register_post_args.add_argument("email", type=str, help="An email is required", required=True)
register_post_args.add_argument("fullname", type=str, help="fullname is required", required=True)
register_post_args.add_argument("password", type=str, help="Password is required", required=True)


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
    if not email or not fullname or not password:
        return jsonify({"message": "Missing required parameters"}), 400
    email_check = re.match(r'^([a-zA-Z0-9._%-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$', email)
    if not email_check:
        return jsonify({"message": "Invalid email format"}), 400
    user = User.query.filter(or_(User.email == email, User.fullname == fullname)).first()
    if user:
        return jsonify({"message": 'An Account with same credentials already exists'}), 409
    new_User = User(email=email, fullname=fullname, password=password)
    db.session.add(new_User)
    db.session.commit()
    access_token = create_access_token(identity=new_User.fullname)
    response = make_response(jsonify({
        "message": "User registered successfully",
        "user": {
            "id": new_User.id,
            "email": new_User.email,
            "username": new_User.fullname
        }
    }), 201)
    set_access_cookies(response, access_token)
    return response

@app.route('/api/blog/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    user = User.query.filter_by(email=email).first()
    if not user or not user.check_password(password):
        return jsonify({'message': 'Invalid credentials'}), 401
    access_token = create_access_token(identity={'email': user.email, 'role': 'user'})
    response = jsonify({'message': 'Login successful','id':user.id})
    set_access_cookies(response, access_token)
    return response, 200

@app.route('/api/admin/login',methods=['POST'])
def admin_login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    if username == os.getenv('ADMIN_USERNAME') and password == os.getenv('ADMIN_PASSWORD'):
        admin_id = generate_admin_id()
        return jsonify({'message':'Login successful',"id":admin_id}),200
    else :
        return jsonify({'message' : 'Invalid creds'}),401
    
@app.route('/api/logout', methods=['POST'])
@jwt_required()
def logout():
    response = jsonify({'message': 'Logged out'})
    unset_jwt_cookies(response)
    return response, 200

@app.route('/api/blogspot/get', methods=['GET', 'OPTIONS'])
@jwt_required()
def get_blogs():
    if request.method == 'OPTIONS':
        response = make_response()
        response.headers.add('Access-Control-Allow-Methods', 'GET, OPTIONS')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        response.headers.add('Access-Control-Allow-Credentials', 'true')
        return response

    current_user = get_jwt_identity()
    print(f"Current user identity: {current_user}")

    if not current_user:
        return jsonify({'message': 'Unauthorized'}), 401

    try:
        blogs = Blog.query.filter_by(status='approved').all()
        return jsonify([blog.to_dict() for blog in blogs]), 200
    except Exception as e:
        return jsonify({"message": "Failed to fetch blogs", "error": str(e)}), 500

@app.route('/api/blogspot/post', methods=['POST', 'OPTIONS'])
@jwt_required()
def post_blog():
    if request.method == 'OPTIONS':
        response = make_response()
        response.headers.add('Access-Control-Allow-Methods', 'POST, OPTIONS')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        response.headers.add('Access-Control-Allow-Credentials', 'true')
        return response
    
    current_user = get_jwt_identity()

    if not current_user:
        return jsonify({'message': 'Unauthorized'}), 401
    # Actual POST blog logic
    try:
        title = request.form.get('title')
        content = request.form.get('content')
        image_file = request.files.get('image')

        # Validate inputs
        if not title or not content or not image_file:
            return jsonify({"message": "Title, content, and image are required"}), 400

        # Upload image and create blog entry
        image_url = upload_image(image_file)
        current_user = get_jwt_identity()
        user = User.query.filter_by(email=current_user['email']).first()

        if not user:
            return jsonify({"message": "User not found"}), 404

        new_blog = Blog(title=title, content=content, author=user.id, image_url=image_url)
        db.session.add(new_blog)
        db.session.commit()

        return jsonify({
            "message": "Blog post created successfully",
            "blog": {
                "id": new_blog.id,
                "title": new_blog.title,
                "content": new_blog.content,
                "author": new_blog.author,
                "img_url": new_blog.image_url,
                "user_id": user.id
            }
        }), 201
    except Exception as e:
        print(e)
        db.session.rollback()
        return jsonify({"message": "Failed to create blog post", "error": str(e)}), 500

@app.route('/api/blog/get',methods=['GET','POST'])
@jwt_required()
def get_User():
    current_user = get_jwt_identity()
    email = current_user['email']
    user = User.query.filter_by(email=email).first()
    if (request.method == 'GET'):
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
        firstname = request.form.get('firstname')
        lastname = request.form.get('lastname')
        fullname = request.form.get('fullname')
        aboutme = request.form.get('aboutme')
        email = request.form.get('email')
        image = request.files.get('image')
        if image :
            image_url = upload_image(image)
            user.image_url = image_url
        if firstname :
            user.firstname = firstname
        if lastname :
            user.lastname = lastname
        if aboutme :
            user.aboutme = aboutme
        if fullname :
            user.fullname = fullname
        if email :
            user.email = email

        try:
            db.session.add(user)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
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
    
@app.route('/api/blog/getAuthor/<int:id>',methods=['GET'])
def get_Author(id):
    author = User.query.filter_by(id=id).first()
    if not author:
        return jsonify({'message':'No such User exists'}),404
    return jsonify({
        'fullname':author.fullname
    })

@app.route('/api/blogspot/pending', methods=['GET', 'OPTIONS'])
def get_pending_blogs():
    pending_blogs = Blog.query.filter_by(status='pending').all()
    return jsonify([blog.to_dict() for blog in pending_blogs]), 200

@app.route('/api/blogspot/approve/<int:blog_id>', methods=['POST', 'OPTIONS'])
def approve_blog(blog_id):
    blog = Blog.query.get(blog_id)
    if blog:
        blog.status = 'approved'
        db.session.commit()
        return jsonify({'message': 'Blog approved'}), 200

    return jsonify({'message': 'Blog not found'}), 404

    
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

@app.route('/api/check-auth',methods=['GET'])
@jwt_required()
def check_auth():
    current_user = get_jwt_identity()
    return jsonify({'message':'Authenticated','user':current_user})

