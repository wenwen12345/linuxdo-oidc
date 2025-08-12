import httpx
import os
from dotenv import load_dotenv

load_dotenv()

def test_client_secret_validation():
    """测试客户端密钥验证功能"""
    base_url = "http://localhost:8000"
    
    # 测试数据
    test_data = {
        "grant_type": "authorization_code",
        "code": "test_code",
        "redirect_uri": "http://example.com/callback",
        "client_id": "test_client",
        "client_secret": "wrong_secret"
    }
    
    print("测试无效客户端密钥...")
    response = httpx.post(f"{base_url}/token", data=test_data)
    print(f"状态码: {response.status_code}")
    print(f"响应: {response.json()}")
    
    # 应该返回403错误
    assert response.status_code == 403
    assert "Invalid client credentials" in response.json()["detail"]
    print("✅ 无效密钥测试通过")
    
    # 测试正确的客户端密钥（如果设置了环境变量）
    expected_secret = os.getenv("EXPECTED_CLIENT_SECRET")
    if expected_secret:
        test_data["client_secret"] = expected_secret
        print("测试有效客户端密钥...")
        response = httpx.post(f"{base_url}/token", data=test_data)
        print(f"状态码: {response.status_code}")
        # 这里可能会因为无效的授权码而返回400，但不会是403
        assert response.status_code != 403
        print("✅ 有效密钥测试通过")
    
    print("所有测试完成！")

if __name__ == "__main__":
    test_client_secret_validation()