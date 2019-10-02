"""
Auth-Token
~~~~~~~~~~

Securing an Eve-powered API with Token based Authentication and
SQLAlchemy.

This snippet by Andrew Mleczko can be used freely for anything
you like. Consider it public domain.
"""


from eve import Eve
from eve.auth import TokenAuth
from src.models import User
from src.views import register_views


class TokenAuthenticate(TokenAuth):
    def check_auth(self, token, allowed_roles, resource, method):
        """First we are verifying if the token is valid. Next
        we are checking if user is authorized for given roles.
        """
        login = User.verify_auth_token(token)
        if login and allowed_roles:
            user = app.data.driver.session.query(User).get(login)
            return user.isAuthorized(allowed_roles)
        else:
            return False


if __name__ == '__main__':
    app = Eve(auth=TokenAuth)
    register_views(app)
    app.run()
