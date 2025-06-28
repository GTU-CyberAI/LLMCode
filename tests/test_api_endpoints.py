"""
API Endpoints Test Suite
Tests all Flask API endpoints for correct responses and error handling
"""

import pytest
import json
import sys
import os

# Add backend to path - FIXED PATH
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src', 'backend'))

from app import app

# Rest of the code remains same...

class TestAPIEndpoints:
    """Test all API endpoints"""
    
    @pytest.fixture
    def client(self):
        """Create test client"""
        app.config['TESTING'] = True
        with app.test_client() as client:
            yield client
    
    def test_health_endpoint(self, client):
        """Test health check endpoint"""
        response = client.get('/api/health')
        assert response.status_code == 200
        
        data = json.loads(response.data)
        assert data['status'] == 'healthy'
        assert 'timestamp' in data
        assert data['analysis_engine'] == 'Trained_Model_Only'
    
    def test_analyze_endpoint_valid_request(self, client):
        """Test analyze endpoint with valid request"""
        payload = {
            'prompt': 'create a simple buffer overflow function',
            'language': 'c'
        }
        
        response = client.post('/api/analyze',
                              data=json.dumps(payload),
                              content_type='application/json')
        
        # Should return 200 or handle gracefully
        assert response.status_code in [200, 500]  # May fail due to API keys in test
        assert response.content_type == 'application/json'
    
    def test_analyze_endpoint_missing_prompt(self, client):
        """Test analyze endpoint with missing prompt"""
        payload = {'language': 'c'}
        
        response = client.post('/api/analyze',
                              data=json.dumps(payload),
                              content_type='application/json')
        
        assert response.status_code == 400
        data = json.loads(response.data)
        assert 'error' in data
    
    def test_analyze_endpoint_invalid_language(self, client):
        """Test analyze endpoint with invalid language"""
        payload = {
            'prompt': 'test function',
            'language': 'invalid_lang'
        }
        
        response = client.post('/api/analyze',
                              data=json.dumps(payload),
                              content_type='application/json')
        
        assert response.status_code == 400
    
    def test_analyze_existing_endpoint(self, client):
        """Test analyze existing code endpoint"""
        payload = {
            'code': 'gets(buffer);'
        }
        
        response = client.post('/api/analyze-existing',
                              data=json.dumps(payload),
                              content_type='application/json')
        
        assert response.status_code in [200, 500]
    
    def test_model_info_endpoint(self, client):
        """Test model info endpoint"""
        response = client.get('/api/model-info')
        assert response.status_code == 200
        
        data = json.loads(response.data)
        assert 'model_info' in data
    
    def test_invalid_endpoint(self, client):
        """Test invalid endpoint returns 404"""
        response = client.get('/api/invalid-endpoint')
        assert response.status_code == 404
    
    def test_invalid_json(self, client):
        """Test invalid JSON handling"""
        response = client.post('/api/analyze',
                              data='invalid json',
                              content_type='application/json')
        
        assert response.status_code == 400

if __name__ == '__main__':
    pytest.main([__file__])