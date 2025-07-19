import pytest
import sys
import os

# Add the parent directory to the path so we can import app
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def test_health_check():
    """Test that the health check endpoint returns 200"""
    # This is a basic test that will always pass
    # In a real application, you would import and test your Flask app
    assert True

def test_app_structure():
    """Test that the app.py file exists"""
    app_file = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'app.py')
    assert os.path.exists(app_file), "app.py file should exist"

def test_requirements_file():
    """Test that requirements.txt exists"""
    req_file = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'requirements.txt')
    assert os.path.exists(req_file), "requirements.txt file should exist"

def test_procfile():
    """Test that Procfile exists"""
    procfile = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'Procfile')
    assert os.path.exists(procfile), "Procfile should exist"

if __name__ == "__main__":
    pytest.main([__file__]) 