#!/usr/bin/env python3

from flask import request, session
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api
from models import User, Recipe

class Signup(Resource):
    def post(self):
        json = request.get_json()
        username = json.get('username')
        password = json.get('password')
        image_url = json.get('image_url')
        bio = json.get('bio')
        if not all([username, password, image_url, bio]):
            return {'message': 'All fields must be filled'}, 422
        new_user = User(username=username, image_url=image_url, bio=bio)
        new_user.password_hash = password
        db.session.add(new_user)
        db.session.commit()
        new_user_dict = new_user.to_dict()
        return new_user_dict, 201


class CheckSession(Resource):
    def get(self):
        if session['user_id']:
            user = User.query.filter(User.id == session['user_id']).first()
            return user.to_dict(), 200
        return {'message': 'Please log in to continue'}, 401

class Login(Resource):
    def post(self):
        json = request.get_json()
        username = json.get('username')
        password = json.get('password')
        user = User.query.filter(User.username == username).first()
        if not isinstance(user, User) or not user.authenticate(password):
            return {'error': 'Incorrect username or password'}, 401
        session['user_id'] = user.id
        return user.to_dict(), 200


class Logout(Resource):
    def delete(self):
        if session['user_id']:
            session['user_id'] = ''
            return {'message': 'Logged out successfully'}, 200
        return {'message': 'Not yet logged in'}, 401

class RecipeIndex(Resource):
    def get(self):
        user = User.query.filter(User.id == session['user_id']).first()
        if user:
            recipes = [recipe.to_dict() for recipe in user.recipes]
            return recipes, 200
        return {'message': 'Please log in to continue'}, 401
    def post(self):
        json = request.get_json()
        title = json.get('title')
        instructions = json.get('instructions')
        minutes_to_complete = json.get('minutes_to_complete')
        if not session['user_id']:
            return {'error': 'Please log in to continue'}, 401
        if all([title, len(instructions)>=50, minutes_to_complete]):
            recipe = Recipe(title=title, instructions=instructions, minutes_to_complete=minutes_to_complete, user_id=session['user_id'])
            db.session.add(recipe)
            db.session.commit()
            return recipe.to_dict(), 201
        return {'error': 'Recipe invalid'}, 422

api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')


if __name__ == '__main__':
    app.run(port=5555, debug=True)