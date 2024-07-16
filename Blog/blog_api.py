from flask_restful import Api, Resource, reqparse, abort, fields, marshal_with
from Blog.model import Blog
from Blog import db,app
from flask_jwt_extended import jwt_required
api = Api(app)
blog_put_args = reqparse.RequestParser()
blog_put_args.add_argument("title", type=str, help="A title for your Blog is required", required=True)
blog_put_args.add_argument("content", type=str, help="Actual content for your Blog is required", required=True)
blog_put_args.add_argument("author", type=int, help="The ID of the author is required", required=True)

blog_patch_args = reqparse.RequestParser()
blog_patch_args.add_argument("title", type=str, help="A title for your Blog is required")
blog_patch_args.add_argument("content", type=str, help="Actual content for your Blog is required")

resource_fields = {
    'id': fields.Integer,
    'title': fields.String,
    'content': fields.String,
    'author': fields.Integer
}

class BlogApi(Resource):
    @marshal_with(resource_fields)
    def get(self, blog_id):
        result = Blog.query.filter_by(id=blog_id).first()
        if not result:
            abort(404, message="No Blog with that id exists")
        return result, 200


    @marshal_with(resource_fields)
    def patch(self, blog_id):
        args = blog_patch_args.parse_args()
        result = Blog.query.filter_by(id=blog_id).first()
        if not result:
            abort(404, message="The blog you are trying to edit does not exist")
        if args['title']:
            result.title = args['title']
        if args['content']:
            result.content = args['content']
        result.status = 'pending'
        db.session.commit()
        return result, 202

    def delete(self, blog_id):
        result = Blog.query.filter_by(id=blog_id).first()
        if not result:
            abort(404, message="The blog you are trying to delete does not exist")
        db.session.delete(result)
        db.session.commit()
        return '', 204