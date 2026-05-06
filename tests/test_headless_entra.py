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
    def test_federated_tenant_routes_through_ws_trust(self):
        """Tenant federated to ADFS — ``GetCredentialType`` returns a
        ``FederationRedirectUrl``, and the v1.0 path follows WS-Trust.
        Here we only verify the federated branch *invokes* WS-Trust
        rather than bailing the way pre-v1.0 versions did. End-to-end
        WS-Trust coverage is in ``TestWsTrustFlow`` below.
        """
        auth = _make_authenticator()
        called = {}

        def fake_ws_trust(*, username, password, user_realm_login):
            called["username"] = username
            called["password"] = password
            return _resp("<html><body>no form</body></html>", url=FINAL_URL)

        auth._authenticate_via_ws_trust = fake_ws_trust
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
        with pytest.raises(HeadlessAuthError, match="no SAMLResponse form"):
            auth._auto_authenticate_entra(LOGIN_URL, FINAL_URL, COOKIE_NAME)
        assert called["username"] == "alice@example.com"
        assert called["password"] == "hunter2"

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


# ---------------------------------------------------------------- WS-Trust


def _ws_trust_rstr_with_assertion(assertion_id="A1"):
    """A minimal WS-Trust 2005 RSTR carrying a SAML 1.1 Assertion."""
    return (
        '<?xml version="1.0" encoding="utf-8"?>'
        '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">'
        "<s:Body>"
        "<wst:RequestSecurityTokenResponse "
        'xmlns:wst="http://docs.oasis-open.org/ws-sx/ws-trust/200512">'
        "<wst:RequestedSecurityToken>"
        f'<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:1.0:assertion" '
        f'AssertionID="{assertion_id}">'
        "<saml:AttributeStatement/>"
        "</saml:Assertion>"
        "</wst:RequestedSecurityToken>"
        "</wst:RequestSecurityTokenResponse>"
        "</s:Body>"
        "</s:Envelope>"
    ).encode()


def _ws_trust_soap_fault(reason="Bad credentials"):
    return (
        '<?xml version="1.0" encoding="utf-8"?>'
        '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">'
        "<s:Body>"
        "<s:Fault>"
        "<s:Code><s:Value>s:Sender</s:Value></s:Code>"
        f"<s:Reason><s:Text>{reason}</s:Text></s:Reason>"
        "</s:Fault>"
        "</s:Body>"
        "</s:Envelope>"
    ).encode()


class TestWsTrustFlow:
    """End-to-end-ish coverage for ``_authenticate_via_ws_trust``.

    Mocks the realm-discovery + WS-Trust + login.srf chain so we
    don't need a real federated tenant to hit every code path."""

    def test_happy_path_returns_login_srf_response(self):
        auth = _make_authenticator()
        wst_rstr = MagicMock()
        wst_rstr.content = _ws_trust_rstr_with_assertion()
        wst_rstr.raise_for_status = MagicMock()

        # 1. realm-discovery JSON
        # 2. final login.srf POST response (we just check it's returned)
        auth.session.get.side_effect = _sequence(
            _resp(
                json_body={
                    "AuthURL": "https://adfs.contoso.com/adfs/services/trust/2005/usernamemixed"
                }
            )
        )
        auth.session.post.side_effect = _sequence(
            wst_rstr, _resp("ok", url="https://login.microsoftonline.com/login.srf")
        )

        result = auth._authenticate_via_ws_trust(
            username="alice@example.com",
            password="pwd",
            user_realm_login="alice@example.com",
        )
        assert result.url.endswith("/login.srf")

    def test_realm_discovery_without_authurl_errors(self):
        """If realm-discovery doesn't return ``AuthURL`` we bail —
        tenant federation config is unusual in some way we can't
        script."""
        auth = _make_authenticator()
        auth.session.get.side_effect = _sequence(
            _resp(json_body={"NameSpaceType": "Managed"})  # not federated after all
        )
        with pytest.raises(HeadlessAuthError, match="WS-Trust AuthURL"):
            auth._authenticate_via_ws_trust(
                username="x",
                password="x",
                user_realm_login="x",
            )

    def test_ws_trust_authurl_outside_whitelist_refused(self):
        """A malicious realm-discovery response could point ``AuthURL``
        at an attacker-controlled endpoint — refuse to send creds
        there if the user has set ``--allowed-hosts``."""
        auth = _make_authenticator(allowed_hosts=["adfs.legit.com"])
        auth.session.get.side_effect = _sequence(
            _resp(json_body={"AuthURL": "https://attacker.example/steal"})
        )
        with pytest.raises(HeadlessAuthError, match="not in allowed_hosts"):
            auth._authenticate_via_ws_trust(
                username="x",
                password="x",
                user_realm_login="x",
            )

    def test_realm_discovery_url_outside_whitelist_refused(self):
        auth = _make_authenticator(allowed_hosts=["adfs.legit.com"])
        # The realm-discovery URL is on login.microsoftonline.com,
        # which isn't in this whitelist either — refuse before any
        # GET goes out.
        with pytest.raises(HeadlessAuthError, match="realm-discovery"):
            auth._authenticate_via_ws_trust(
                username="x",
                password="x",
                user_realm_login="x",
            )

    def test_wst_response_with_no_assertion_surfaces_fault(self):
        auth = _make_authenticator()
        fault = MagicMock()
        fault.content = _ws_trust_soap_fault(reason="Authentication failed")
        fault.raise_for_status = MagicMock()
        auth.session.get.side_effect = _sequence(
            _resp(
                json_body={
                    "AuthURL": "https://adfs.contoso.com/adfs/services/trust/2005/usernamemixed"
                }
            )
        )
        auth.session.post.side_effect = _sequence(fault)
        with pytest.raises(HeadlessAuthError, match="ADFS rejected the credentials"):
            auth._authenticate_via_ws_trust(
                username="x",
                password="x",
                user_realm_login="x",
            )

    def test_wst_response_with_invalid_xml_errors(self):
        auth = _make_authenticator()
        garbled = MagicMock()
        garbled.content = b"not even xml"
        garbled.raise_for_status = MagicMock()
        auth.session.get.side_effect = _sequence(
            _resp(
                json_body={
                    "AuthURL": "https://adfs.contoso.com/adfs/services/trust/2005/usernamemixed"
                }
            )
        )
        auth.session.post.side_effect = _sequence(garbled)
        with pytest.raises(HeadlessAuthError, match="wasn't valid XML"):
            auth._authenticate_via_ws_trust(
                username="x",
                password="x",
                user_realm_login="x",
            )


# ---------------------------------------------------------------- envelope shape


class TestWsTrustEnvelope:
    """Smoke-test the SOAP envelope so a refactor that breaks it
    (e.g. wrong namespace, missing element) is caught locally."""

    def test_envelope_carries_username_and_password(self):
        env = HeadlessAuthenticator._ws_trust_soap_envelope(
            username="alice@example.com",
            password="hunter2",
            ws_trust_url="https://adfs.example.com/adfs/services/trust/2005/usernamemixed",
        )
        assert "<o:Username>alice@example.com</o:Username>" in env
        assert "<o:Password>hunter2</o:Password>" in env
        assert "https://adfs.example.com/adfs/services/trust/2005/usernamemixed" in env

    def test_envelope_uses_microsoftonline_appliesto(self):
        """The MS-MWBF spec pins the AppliesTo URI; getting it wrong
        means MS won't accept the assertion."""
        env = HeadlessAuthenticator._ws_trust_soap_envelope(
            username="x", password="y", ws_trust_url="https://x"
        )
        assert "urn:federation:MicrosoftOnline" in env

    def test_envelope_escapes_angle_brackets_in_password(self):
        """Passwords with '<' / '>' / '&' must not break the SOAP."""
        env = HeadlessAuthenticator._ws_trust_soap_envelope(
            username="alice", password='p<>"&w', ws_trust_url="https://x"
        )
        assert "<o:Password>p&lt;&gt;&quot;&amp;w</o:Password>" in env
