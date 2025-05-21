import unittest
import sys
import os
from datetime import date, timedelta

# Adjust sys.path to include the parent directory (project root)
# so that 'app' can be imported.
# This assumes test_app.py is in task_scheduler_app/ and app.py is in task_scheduler_app/
# If app.py is in the root above task_scheduler_app/, this needs adjustment.
# For the current structure, app.py is in task_scheduler_app, so it should be importable.
# However, let's add the project root to be safe if app.py was meant to be outside.
# current_dir = os.path.dirname(os.path.abspath(__file__))
# project_root = os.path.dirname(current_dir) # This would be the directory containing task_scheduler_app
# sys.path.insert(0, project_root)
# sys.path.insert(0, current_dir) # Add current directory where app.py is located

from .app import calculate_target_date_for_fixed_day

class TestDateCalculations(unittest.TestCase):

    def test_calculate_target_date_fixed_day(self):
        # Test cases: (start_date_str, rule_day_of_week, expected_date_str)
        # rule_day_of_week: 1=Mon, 7=Sun
        test_cases = [
            # Start Mon (2023-10-23), Rule Wed (3) -> Expected Wed (2023-10-25)
            ("2023-10-23", 3, "2023-10-25"),
            # Start Fri (2023-10-27), Rule Mon (1) -> Expected Mon (2023-10-30, next week)
            ("2023-10-27", 1, "2023-10-30"),
            # Start Mon (2023-10-23), Rule Mon (1) -> Expected Mon (2023-10-23, same day)
            ("2023-10-23", 1, "2023-10-23"),
            # Start Sun (2023-10-29), Rule Tue (2) -> Expected Tue (2023-10-31, next week)
            ("2023-10-29", 2, "2023-10-31"),
            # Start Sun (2023-10-29), Rule Sun (7) -> Expected Sun (2023-10-29, same day)
            ("2023-10-29", 7, "2023-10-29"),
            # Start Wed (2023-10-25), Rule Mon (1) -> Expected Mon (2023-10-30, next week)
            ("2023-10-25", 1, "2023-10-30"),
            # Start Wed (2023-10-25), Rule Sun (7) -> Expected Sun (2023-10-29, same week)
            ("2023-10-25", 7, "2023-10-29"),
        ]

        for start_str, rule_dow, expected_str in test_cases:
            with self.subTest(start_date=start_str, rule_day=rule_dow):
                start_date_obj = date.fromisoformat(start_str)
                expected_date_obj = date.fromisoformat(expected_str)
                calculated_date = calculate_target_date_for_fixed_day(start_date_obj, rule_dow)
                self.assertEqual(calculated_date, expected_date_obj)

# Imports for CRUD tests
from .app import app, db, User, TaskTemplate, create_task_template # Assuming these are in your app.py
from flask_sqlalchemy import SQLAlchemy

class TestCRUDOperations(unittest.TestCase):
    def setUp(self):
        # Configure the app for testing
        app.config['TESTING'] = True
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:' # Use in-memory SQLite database
        app.config['SECRET_KEY'] = 'test_secret_key' # Needed for session, even if not used directly in test
        
        # Create an application context
        self.app_context = app.app_context()
        self.app_context.push()
        
        # Create all database tables
        db.create_all()

        # Create a dummy user for testing CRUD operations that require a user_id
        # This user is created once for all tests in this class that might need it.
        # If tests modify the user, consider creating it per-test or resetting state.
        test_user = User(google_id="test_google_id_123", email="test@example.com")
        db.session.add(test_user)
        db.session.commit()
        self.test_user_id = test_user.id


    def tearDown(self):
        # Remove the database session and drop all tables
        db.session.remove()
        db.drop_all()
        # Pop the application context
        self.app_context.pop()

    def test_create_task_template(self):
        # Test creating a task template
        template_name = "My Test Template"
        template_description = "This is a test description."
        
        # Call the CRUD function
        created_template = create_task_template(
            user_id=self.test_user_id, 
            name=template_name, 
            description=template_description
        )
        
        self.assertIsNotNone(created_template, "create_task_template should return the created template.")
        self.assertIsNotNone(created_template.id, "Created template should have an ID.")
        self.assertEqual(created_template.name, template_name, "Template name does not match.")
        self.assertEqual(created_template.description, template_description, "Template description does not match.")
        self.assertEqual(created_template.user_id, self.test_user_id, "Template user_id does not match.")
        
        # Verify it's in the database
        retrieved_template = TaskTemplate.query.get(created_template.id)
        self.assertIsNotNone(retrieved_template, "Template should be retrievable from the database.")
        self.assertEqual(retrieved_template.name, template_name)

# Imports for TestTaskListFetching
from unittest.mock import patch, MagicMock
from .app import get_task_lists, app as flask_app # Import Flask app instance

class TestTaskListFetching(unittest.TestCase):

    @patch('task_scheduler_app.app.get_tasks_service') 
    @patch('task_scheduler_app.app.flash') 
    def test_get_task_lists_success(self, mock_flash, mock_get_tasks_service):
        # Configure mock_get_tasks_service
        mock_service_instance = MagicMock()
        sample_response = {
            'items': [
                {'id': 'list1', 'title': 'List One'},
                {'id': 'list2', 'title': 'List Two'}
            ]
        }
        mock_service_instance.tasklists().list().execute.return_value = sample_response
        mock_get_tasks_service.return_value = mock_service_instance

        expected_lists = [
            {'id': 'list1', 'title': 'List One'},
            {'id': 'list2', 'title': 'List Two'}
        ]
        
        # Need an app context to use flash (even if mocked) if it's part of a request lifecycle
        with flask_app.test_request_context('/'): # Or any dummy path
            actual_lists = get_task_lists(user_id=1) # user_id is dummy here

        self.assertEqual(actual_lists, expected_lists)
        mock_get_tasks_service.assert_called_once_with(1)
        mock_service_instance.tasklists().list().execute.assert_called_once()
        mock_flash.assert_not_called()

    @patch('task_scheduler_app.app.get_tasks_service')
    @patch('task_scheduler_app.app.flash')
    def test_get_task_lists_api_error(self, mock_flash, mock_get_tasks_service):
        mock_service_instance = MagicMock()
        # Simulate an API error; googleapiclient.errors.HttpError is common
        # For simplicity, using a generic Exception for the mock object
        mock_service_instance.tasklists().list().execute.side_effect = Exception("API Error")
        mock_get_tasks_service.return_value = mock_service_instance

        with flask_app.test_request_context('/'):
            actual_lists = get_task_lists(user_id=1)

        self.assertEqual(actual_lists, [])
        mock_flash.assert_called_once()
        # Check if the flash message contains expected text (optional, can be brittle)
        args, _ = mock_flash.call_args
        self.assertIn("Google Task 목록을 가져오는 중 오류 발생", args[0])


    @patch('task_scheduler_app.app.get_tasks_service')
    @patch('task_scheduler_app.app.flash')
    def test_get_task_lists_service_unavailable(self, mock_flash, mock_get_tasks_service):
        mock_get_tasks_service.return_value = None # Simulate service not being available

        with flask_app.test_request_context('/'):
            actual_lists = get_task_lists(user_id=1)
        
        self.assertEqual(actual_lists, [])
        mock_flash.assert_called_once()
        args, _ = mock_flash.call_args
        self.assertIn("Google Tasks 서비스에 연결할 수 없어 작업 목록을 가져올 수 없습니다.", args[0])


if __name__ == '__main__':
    # To ensure the test runner can find 'app' module, we need to make sure
    # the directory containing 'app.py' (which is task_scheduler_app) is in sys.path
    # If running 'python task_scheduler_app/test_app.py' from project root,
    # task_scheduler_app needs to be in PYTHONPATH or handled via -m.
    # The 'from app import ...' implies app.py is at the same level as test_app.py
    # or app is an installed package.
    # Given app.py and test_app.py are both in task_scheduler_app/, direct import should work
    # when python is run from the task_scheduler_app directory, or if task_scheduler_app is
    # itself a package and tests are run as part of the package.
    # The simplest way to run from project root is 'python -m unittest task_scheduler_app.test_app'
    unittest.main()
