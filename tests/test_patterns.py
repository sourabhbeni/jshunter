"""Tests for secret patterns.

Note: secret-looking fixtures are built via concatenation so this file
does not trip secret scanners / push protection.
"""
from jshunter.patterns import scan_text, looks_random


def rules(text):
    return {f["rule"] for f in scan_text(text)}


def test_aws_key():
    # AKIAIOSFODNN7EXAMPLE is AWS's documented example key (allowlisted)
    assert "aws-access-key-id" in rules("var k='AKIAIOSFODNN7EXAMPLE';")


def test_google_api_key():
    key = "AIzaSyD-" + "EXAMPLEKEY1234567890abcdefghiJK"
    assert "google-api-key" in rules("key=" + key)


def test_github_token():
    assert "github-token" in rules("token='" + "ghp_abcde" + "fghij1234567890ABCDEFGHIJ12" + "'")


def test_slack_token():
    assert "slack-token" in rules("t='" + "xoxb-12345" + "6789012-abcdefghij1234567890" + "'")


def test_stripe_live():
    assert "stripe-live-key" in rules("sk_live_51" + "H7xK9aBcDeFgHiJkLmNoPq")


def test_stripe_test_is_medium_not_critical():
    f = scan_text("sk_test_51" + "H7xK9aBcDeFgHiJkLmNoPq")
    assert f and f[0]["rule"] == "stripe-test-key" and f[0]["severity"] == "MEDIUM"


def test_private_key():
    header = "-----BEGIN " + "RSA PRIVATE KEY-----"
    assert "private-key-block" in rules(header + "\nMIIB...")


def test_jwt():
    jwt = "eyJhbGciOiJIUzI1NiJ9" + ".eyJzdWIiOiIxMjM0In0" + ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    assert "jwt-token" in rules(jwt)


def test_firebase():
    assert "firebase-url" in rules("https://myapp-default-rtdb.firebaseio.com/db")


def test_generic_assignment_entropy_gated():
    secret = "9f8b7a6c5d4e" + "3f2a1b9c8d7e6f5a4b3c"
    assert "generic-api-key-assignment" in rules('api_key = "' + secret + '"')
    # placeholders => not flagged
    assert "generic-api-key-assignment" not in rules('api_key = "example"')
    assert "generic-api-key-assignment" not in rules('api_key = "changeme123456789"')


def test_no_false_positive_on_plain_text():
    assert scan_text("hello world, nothing to see here") == []


def test_dedupe():
    f = scan_text("AKIAIOSFODNN7EXAMPLE and AKIAIOSFODNN7EXAMPLE again")
    assert len([x for x in f if x["rule"] == "aws-access-key-id"]) == 1


def test_looks_random_placeholders():
    assert not looks_random("example")
    assert not looks_random("xxx")
    assert looks_random("9f8b7a6c5d4e" + "3f2a1b9c8d7e6f5a4b3c")
