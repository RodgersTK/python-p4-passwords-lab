#!/usr/bin/env python3

from flask import request, session
from flask_restful import Resource
from config import app, db, api
from models import User

class ClearSession(Resource):
    def delete(self):
        """Clear user session data."""
        session.clear()  # Clear all session data
        return {}, 204

class Signup(Resource):
    def post(self):
        """Register a new user."""
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')

        if username and password:
            new_user = User(username=username)
            new_user.password_hash = password  # Ensure to hash this in production
            db.session.add(new_user)
            db.session.commit()

            session['user_id'] = new_user.id
            return new_user.to_dict(), 201

        return {'error': '422 Unprocessable Entity'}, 422

class CheckSession(Resource):
    def get(self):
        """Check if the user is logged in."""
        user_id = session.get('user_id')
        if user_id:
            user = User.query.get(user_id)
            return user.to_dict(), 200
        
        return {}, 204

class Login(Resource):
    def post(self):
        """Log in a user."""
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')

        user = User.query.filter_by(username=username).first()

        if user and user.authenticate(password):
            session['user_id'] = user.id
            return user.to_dict(), 200

        return {'error': '401 Unauthorized'}, 401

class Logout(Resource):
    def delete(self):
        """Log out a user."""
        session.clear()  # Clear all session data
        return {}, 204

# Register the resources with their endpoints
api.add_resource(ClearSession, '/clear', endpoint='clear')
api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')

if __name__ == '__main__':
    app.run(port=5555, debug=True)
