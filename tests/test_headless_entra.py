"""End-to-end-ish tests for the scripted Microsoft Entra login flow.

These drive ``HeadlessAuthenticator._auto_authenticate_entra`` via a
``requests.Session`` that's been replaced with a sequencing mock —
each ``.get`` / ``.post`` call returns the next pre-built response
in a queue. That covers the full sequence (initial GET → ``$Config``
extract → ``GetCredentialType`` → password POST → optional TOTP →
optional KMSI → SAMLResponse form auto-submit) without requiring a
real Entra tenant.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from openconnect_saml.headless import HeadlessAuthenticator, HeadlessAuthError

# ---------------------------------------------------------------- helpers


def _resp(
    text="",
    status=200,
    json_body=None,
    url="https://login.microsoftonline.com/x",
    cookies=None,
):
    """Build a fake ``requests.Response``."""
    r = MagicMock()
    r.status_code = status
    r.text = text
    r.content = text.encode("utf-8")
    r.url = url
    r.raise_for_status = MagicMock(return_value=None)
    # ``_extract_token`` does ``name in resp.cookies`` then ``resp.cookies[name]``
    # — back that with a real dict so the ``in`` check works.
    r.cookies = cookies if cookies is not None else {}
    if json_body is not None:
        r.json = MagicMock(return_value=json_body)
    return r


def _config_html(
    url_post="https://login.microsoftonline.com/common/login",
    s_ctx="CTXTOKEN",
    s_ft="FLOWTOKEN",
    canary="CANARY",
    session_id="SESS",
    extra="",
):
    """Render an HTML page carrying a parseable ``$Config`` block."""
    return (
        "<html><head><script>$Config = {"
        f'"urlPost":"{url_post}",'
        f'"sCtx":"{s_ctx}",'
        f'"sFT":"{s_ft}",'
        f'"canary":"{canary}",'
        f'"sessionId":"{session_id}"'
        "};</script></head><body>" + extra + "</body></html>"
    )


def _saml_form_html(action="https://vpn.example.com/+CSCOE+/saml/sp/acs"):
    """Render a SAMLResponse auto-submit form."""
    return (
        f'<html><body><form method="post" action="{action}">'
        '<input type="hidden" name="SAMLResponse" value="MOCK_SAML_RESPONSE_BASE64" />'
        '<input type="hidden" name="RelayState" value="rstate" />'
        "</form></body></html>"
    )


def _make_authenticator(*, with_totp=True, with_password=True, allowed_hosts=None):
    creds = MagicMock()
    creds.username = "alice@example.com"
    creds.password = "hunter2" if with_password else ""
    creds.totp = "123456" if with_totp else None
    auth = HeadlessAuthenticator(credentials=creds, allowed_hosts=allowed_hosts, timeout=5)
    # Replace session with a strict mock so we can sequence calls.
    auth.session = MagicMock()
    return auth


def _sequence(*responses):
    """Build a side-effect iterator that returns each response once."""
    return list(responses)


LOGIN_URL = "https://login.microsoftonline.com/common/oauth2/authorize?client_id=foo"
FINAL_URL = "https://vpn.example.com/+CSCOE+/saml/sp/acs"
COOKIE_NAME = "webvpn"


# ---------------------------------------------------------------- guardrails


class TestEntraGuardrails:
    def test_missing_password_raises(self):
        auth = _make_authenticator(with_password=False)
        with pytest.raises(HeadlessAuthError, match="needs both username AND password"):
            auth._auto_authenticate_entra(LOGIN_URL, FINAL_URL, COOKIE_NAME)

    def test_redirect_off_whitelist_refused(self):
        # User pinned only the gateway. Redirect onto evil.example.com
        # must abort BEFORE we POST creds.
        auth = _make_authenticator(allowed_hosts=["vpn.example.com"])
        # GET response lands on a host we don't trust.
        auth.session.get.side_effect = _sequence(
            _resp(_config_html(), url="https://evil.example.com/login")
        )
        with pytest.raises(HeadlessAuthError, match="Refusing to follow redirect"):
            auth._auto_authenticate_entra(LOGIN_URL, FINAL_URL, COOKIE_NAME)

    def test_url_post_outside_whitelist_refused(self):
        # The IdP page comes back from a trusted host but $Config.urlPost
        # points at evil. Don't POST creds there.
        auth = _make_authenticator(allowed_hosts=["login.microsoftonline.com"])
        auth.session.get.side_effect = _sequence(
            _resp(
                _config_html(url_post="https://attacker.example/steal"),
                url="https://login.microsoftonline.com/x",
            )
        )
        # GetCredentialType happens first and is on the trusted host —
        # let it succeed so we hit the urlPost check next.
        auth.session.post.side_effect = _sequence(
            _resp(json_body={"Credentials": {"HasPassword": True}, "FlowToken": "FT2"}),
        )
        with pytest.raises(HeadlessAuthError, match="Refusing to POST"):
            auth._auto_authenticate_entra(LOGIN_URL, FINAL_URL, COOKIE_NAME)


# ---------------------------------------------------------------- credential-type forks


class TestEntraCredentialTypeFork:
    def test_federated_tenant_errors_clearly(self):
        """Tenant federated to ADFS — GetCredentialType returns a
        ``FederationRedirectUrl``. We don't speak WS-Trust yet, so
        bail with a user-readable message rather than wandering off."""
        auth = _make_authenticator()
        auth.session.get.side_effect = _sequence(
            _resp(_config_html(), url="https://login.microsoftonline.com/x")
        )
        auth.session.post.side_effect = _sequence(
            _resp(
                json_body={
                    "Credentials": {
                        "HasPassword": False,
                        "FederationRedirectUrl": "https://adfs.contoso.com/adfs/ls/",
                    }
                }
            )
        )
        with pytest.raises(HeadlessAuthError, match="federated"):
            auth._auto_authenticate_entra(LOGIN_URL, FINAL_URL, COOKIE_NAME)

    def test_passwordless_tenant_errors_clearly(self):
        """``HasPassword=False`` typically means passwordless / FIDO2
        only. Surface that distinction so users don't think their
        password is wrong."""
        auth = _make_authenticator()
        auth.session.get.side_effect = _sequence(
            _resp(_config_html(), url="https://login.microsoftonline.com/x")
        )
        auth.session.post.side_effect = _sequence(
            _resp(json_body={"Credentials": {"HasPassword": False}})
        )
        with pytest.raises(HeadlessAuthError, match="passwordless / FIDO2"):
            auth._auto_authenticate_entra(LOGIN_URL, FINAL_URL, COOKIE_NAME)


# ---------------------------------------------------------------- happy paths


class TestEntraHappyPath:
    def test_password_only_returns_token(self):
        """No MFA, no KMSI — straight from password POST to a SAML
        form which we auto-submit and read the cookie back from."""
        auth = _make_authenticator(with_totp=False)
        # ``_check_cookies_for_token`` iterates ``self.session.cookies``
        # looking for a cookie whose ``.name`` matches; build a fake
        # cookie object with the right shape.
        fake_cookie = MagicMock()
        fake_cookie.name = COOKIE_NAME
        fake_cookie.value = "TOKENVALUE"
        auth.session.cookies = [fake_cookie]

        get_seq = _sequence(
            _resp(_config_html(), url="https://login.microsoftonline.com/x"),
        )
        post_seq = _sequence(
            # 1. GetCredentialType
            _resp(json_body={"Credentials": {"HasPassword": True}, "FlowToken": "FT2"}),
            # 2. password POST returns the SAML auto-submit form
            _resp(_saml_form_html(), url="https://login.microsoftonline.com/post"),
            # 3. SAMLResponse form POST → token surfaces on the final
            # response cookies (gateway sets it on the redirect target).
            _resp("ok", url=FINAL_URL, cookies={COOKIE_NAME: "TOKENVALUE"}),
        )
        auth.session.get.side_effect = get_seq
        auth.session.post.side_effect = post_seq
        token = auth._auto_authenticate_entra(LOGIN_URL, FINAL_URL, COOKIE_NAME)
        assert token == "TOKENVALUE"

    def test_wrong_password_errors_with_clear_message(self):
        auth = _make_authenticator(with_totp=False)
        auth.session.get.side_effect = _sequence(
            _resp(_config_html(), url="https://login.microsoftonline.com/x")
        )
        auth.session.post.side_effect = _sequence(
            _resp(json_body={"Credentials": {"HasPassword": True}, "FlowToken": "FT2"}),
            _resp(
                _config_html(extra="Your account or password is incorrect"),
                url="https://login.microsoftonline.com/x",
            ),
        )
        with pytest.raises(HeadlessAuthError, match="rejected the credentials"):
            auth._auto_authenticate_entra(LOGIN_URL, FINAL_URL, COOKIE_NAME)

    def test_mfa_without_totp_errors_clearly(self):
        """If the tenant requires TOTP and the credentials object
        doesn't carry one, we should say so rather than time out."""
        auth = _make_authenticator(with_totp=False)
        auth.session.get.side_effect = _sequence(
            _resp(_config_html(), url="https://login.microsoftonline.com/x")
        )
        auth.session.post.side_effect = _sequence(
            _resp(json_body={"Credentials": {"HasPassword": True}, "FlowToken": "FT2"}),
            _resp(
                _config_html(extra="BeginAuth challenge"),
                url="https://login.microsoftonline.com/x",
            ),
        )
        # The implementation reaches the BeginAuth-without-TOTP branch.
        with pytest.raises(HeadlessAuthError, match="MFA but no TOTP"):
            auth._auto_authenticate_entra(LOGIN_URL, FINAL_URL, COOKIE_NAME)

    def test_unscriptable_mfa_errors_clearly(self):
        """FIDO2 / push notification / 'more info required' challenges
        can't be answered from a CLI; surface that with a clean
        ``HeadlessAuthError`` rather than spinning."""
        auth = _make_authenticator(with_totp=False)
        auth.session.get.side_effect = _sequence(
            _resp(_config_html(), url="https://login.microsoftonline.com/x")
        )
        auth.session.post.side_effect = _sequence(
            _resp(json_body={"Credentials": {"HasPassword": True}, "FlowToken": "FT2"}),
            _resp(
                _config_html(extra="phoneAppNotification approval required"),
                url="https://login.microsoftonline.com/x",
            ),
        )
        with pytest.raises(HeadlessAuthError, match="interactive MFA method"):
            auth._auto_authenticate_entra(LOGIN_URL, FINAL_URL, COOKIE_NAME)
