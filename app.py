from flask_restful import Api
from Blog.route import app
from Blog.blog_api import BlogApi
from Blog import db
api = Api(app)
api.add_resource(BlogApi, '/api/blog/all/<int:blog_id>')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)

