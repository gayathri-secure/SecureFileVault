
import pytest

import app.routes as routes
from app import create_app


@pytest.fixture
def client(monkeypatch):
    """Create a test client without sending real emails."""
    monkeypatch.setenv("OTP_SECRET", "test-only-secret-for-unit-tests")
    routes._OTP_STORE.clear()

    app = create_app()
    app.config["TESTING"] = True

    with app.test_client() as test_client:
        yield test_client

    routes._OTP_STORE.clear()


def request_test_otp(client, monkeypatch, email="tester@example.com"):
    """Request a predictable OTP without sending a real email."""
    monkeypatch.setattr(routes, "generate_otp", lambda: "123456")
    monkeypatch.setattr(
        routes,
        "send_otp_email",
        lambda recipient_email, otp: None,
    )

    return client.post("/api/request-otp", json={"email": email})


def verify_test_otp(client, otp="123456"):
    """Submit an OTP to the verification endpoint."""
    return client.post("/api/verify-otp", json={"otp": otp})


def test_decryption_requires_email_verification(client):
    response = client.post(
        "/api/decrypt-folder",
        json={
            "encrypted_folder": "test_encrypted",
            "output_parent": "test_output",
            "password": "test-password",
            "email": "tester@example.com",
        },
    )

    assert response.status_code == 403
    assert response.json["success"] is False


def test_request_otp_rejects_invalid_email(client):
    response = client.post(
        "/api/request-otp",
        json={"email": "not-an-email"},
    )

    assert response.status_code == 400
    assert response.json["success"] is False


def test_request_otp_rejects_missing_email(client):
    response = client.post("/api/request-otp", json={})

    assert response.status_code == 400
    assert response.json["success"] is False


def test_request_otp_succeeds_without_real_email(client, monkeypatch):
    response = request_test_otp(client, monkeypatch)

    assert response.status_code == 200
    assert response.json["success"] is True


def test_incorrect_otp_does_not_authorize_decryption(client, monkeypatch):
    request_response = request_test_otp(client, monkeypatch)
    assert request_response.status_code == 200

    response = verify_test_otp(client, otp="999999")

    assert response.status_code == 400
    assert response.json["success"] is False

    decrypt_response = client.post(
        "/api/decrypt-folder",
        json={
            "encrypted_folder": "test_encrypted",
            "output_parent": "test_output",
            "password": "test-password",
            "email": "tester@example.com",
        },
    )

    assert decrypt_response.status_code == 403



def test_verified_otp_cannot_be_used_with_different_email(
    client, monkeypatch
):
    request_response = request_test_otp(
        client,
        monkeypatch,
        email="tester@example.com",
    )
    assert request_response.status_code == 200

    verify_response = verify_test_otp(client, otp="123456")
    assert verify_response.status_code == 200

    with client.session_transaction() as sess:
        session_id = sess.get("otp_session_id")

    assert session_id is not None
    record = routes._OTP_STORE[session_id]
    assert record["email"] == "tester@example.com"
    assert record["verified"] is True

    # Check the endpoint response directly; do not call real decryption.
    monkeypatch.setattr(
        routes,
        "decrypt_folder",
        lambda **kwargs: pytest.fail(
            "Decryption ran before rejecting the mismatched email."
        ),
    )

    response = client.post(
        "/api/decrypt-folder",
        json={
            "encrypted_folder": "test_encrypted",
            "output_parent": "test_output",
            "password": "test-password",
            "email": "someone-else@example.com",
        },
    )

    assert response.status_code == 403
    assert "does not match" in response.get_json()["message"]
