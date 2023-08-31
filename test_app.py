from flask_login import login_user
from werkzeug.security import generate_password_hash
from app import app, db, User  # replace 'your_app' with your actual app module
import unittest

class YourTestCase(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        app.config['TESTING'] = True
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'  # or your test database URI
        cls.app = app.test_client()

        with app.app_context():
            db.create_all()

    def setUp(self):
        with app.app_context():
            hashed_password = generate_password_hash('testpassword', method='sha256')
            self.user = User(username='testuser', email='test@example.com', password_hash=hashed_password)
            db.session.add(self.user)
            db.session.commit()

        login_user(self.user)

    # your test methods go here
