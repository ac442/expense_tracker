import unittest
from unittest.mock import patch, Mock, PropertyMock
from app import app

class MockUser:
    def __init__(self, user_id, authenticated=True):
        self.id = user_id
        self.authenticated = authenticated

    @property
    def is_authenticated(self):
        return self.authenticated

class TestSpendingReport(unittest.TestCase):

    def setUp(self):
        self.app = app.test_client()  # Create a test client
        self.app_context = app.app_context()  # Create an app context
        self.app_context.push()  # Push the context

    def tearDown(self):
        self.app_context.pop()  # Pop the app context

    @patch('app.current_user', new_callable=PropertyMock)  # Mock the current_user object
    @patch('app.Expense.query')  # Mock the Expense query
    def test_spending_report(self, mock_query, mock_current_user):
        # Mocking the current user's ID and authentication status
        mock_user = MockUser(user_id=1, authenticated=True)
        mock_current_user.return_value = mock_user

        # Mocking the return value of the database query
        mock_expense1 = Mock(user_id=1, source='Food', amount=50)
        mock_expense2 = Mock(user_id=1, source='Entertainment', amount=100)
        mock_query.filter_by.return_value.all.return_value = [mock_expense1, mock_expense2]

        response = self.app.get('/reports/spending')  # Use the test client to make requests
        self.assertEqual(response.status_code, 200)  # Expecting a 200 status code
        # Add more assertions based on the expected behavior

if __name__ == '__main__':
    unittest.main()
