import requests
import json
from time import sleep

BASE_URL = "http://localhost:8000"


def print_section(title):
    print("\n" + "=" * 60)
    print(f"  {title}")
    print("=" * 60)


def test_health_check():
    print_section("Testing Health Check")
    response = requests.get(f"{BASE_URL}/health")
    print(f"Status Code: {response.status_code}")
    print(f"Response: {json.dumps(response.json(), indent=2)}")
    return response.status_code == 200


def test_root_endpoint():
    print_section("Testing Root Endpoint")
    response = requests.get(f"{BASE_URL}/")
    print(f"Status Code: {response.status_code}")
    print(f"Response: {json.dumps(response.json(), indent=2)}")
    return response.status_code == 200


def test_analyze_footprint(identifier):
    print_section(f"Testing Footprint Analysis: {identifier}")
    response = requests.post(
        f"{BASE_URL}/api/analyze",
        json={"identifier": identifier},
        headers={"Content-Type": "application/json"}
    )
    print(f"Status Code: {response.status_code}")

    if response.status_code == 200:
        data = response.json()
        print(f"\nIdentifier: {data['identifier']}")
        print(f"Risk Score: {data['risk_score']}/100 - {data['risk_status']}")
        print(f"Platform Count: {data['platform_count']}")
        print(f"Exposure Count: {data['exposure_count']}")
        print(f"Threat Level: {data['threat_level']}/10")
        print(f"\nThreats Detected:")
        for threat in data['threats']:
            print(f"  - {threat['icon']} {threat['name']}: {threat['risk']}%")
        print(f"\nTop Security Tips:")
        for i, tip in enumerate(data['security_tips'][:3], 1):
            print(f"  {i}. {tip}")
    else:
        print(f"Error: {response.text}")

    return response.status_code == 200




def test_invalid_input():
    print_section("Testing Invalid Input Handling")
    response = requests.post(
        f"{BASE_URL}/api/analyze",
        json={"identifier": ""},
        headers={"Content-Type": "application/json"}
    )
    print(f"Status Code: {response.status_code}")
    print(f"Expected: 400 (Bad Request)")
    print(f"Response: {response.json()}")
    return response.status_code == 400


def run_all_tests():
    print("\n" + "🚀" * 30)
    print("  DIGITAL FOOTPRINT VISUALIZER - API TESTS")
    print("🚀" * 30)

    tests = [
        ("Health Check", lambda: test_health_check()),
        ("Root Endpoint", lambda: test_root_endpoint()),
        ("Analyze: test@example.com", lambda: test_analyze_footprint("test@example.com")),
        ("Analyze: john.doe@email.com", lambda: test_analyze_footprint("john.doe@email.com")),
        ("Analyze: alice123", lambda: test_analyze_footprint("alice123")),
        ("Invalid Input", lambda: test_invalid_input()),
    ]

    results = []
    for test_name, test_func in tests:
        try:
            passed = test_func()
            results.append((test_name, passed))
            sleep(0.5)
        except requests.exceptions.ConnectionError:
            print(f"\n❌ ERROR: Could not connect to {BASE_URL}")
            print("Make sure the backend server is running:")
            print("  python backend.py")
            return
        except Exception as e:
            print(f"\n❌ ERROR in {test_name}: {str(e)}")
            results.append((test_name, False))

    print_section("TEST RESULTS SUMMARY")
    passed = sum(1 for _, result in results if result)
    total = len(results)

    for test_name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{status} - {test_name}")

    print(f"\n{'=' * 60}")
    print(f"  Total: {passed}/{total} tests passed")
    print(f"{'=' * 60}\n")

    if passed == total:
        print("🎉 All tests passed! Backend is working correctly.")
    else:
        print("⚠️  Some tests failed. Please check the output above.")


if __name__ == "__main__":
    run_all_tests()
