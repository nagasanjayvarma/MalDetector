import os
import base64
import re
from email import policy
from email.parser import BytesParser

from flask import (
    Flask,
    render_template,
    redirect,
    url_for,
    request,
    send_from_directory,
)

from werkzeug.middleware.proxy_fix import ProxyFix
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials


# =========================================================
# OAUTH SETTINGS
# =========================================================

# Only allow HTTP OAuth for local development.
# Render uses HTTPS, so this is not enabled there.
if not os.environ.get("RENDER"):
    os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"


# =========================================================
# PROJECT PATHS
# =========================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

TEMPLATES_DIR = os.path.join(
    BASE_DIR,
    "templates"
)

STATIC_DIR = os.path.join(
    BASE_DIR,
    "static"
)

CSS_DIR = os.path.join(
    STATIC_DIR,
    "css"
)

JS_DIR = os.path.join(
    STATIC_DIR,
    "js"
)


# =========================================================
# FLASK APPLICATION
# =========================================================

app = Flask(
    __name__,
    static_folder=STATIC_DIR,
    template_folder=TEMPLATES_DIR
)

# Trust Render's HTTPS reverse proxy
app.wsgi_app = ProxyFix(
    app.wsgi_app,
    x_proto=1,
    x_host=1
)

# Flask secret key
app.secret_key = os.environ.get(
    "FLASK_SECRET_KEY",
    "maldetector-local-secret-key"
)

# Secure cookies when running on Render
if os.environ.get("RENDER"):
    app.config.update(
        SESSION_COOKIE_SECURE=True,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="None",
        SESSION_COOKIE_PATH="/"
    )


# =========================================================
# OAUTH STATE SECURITY
# =========================================================

# We do NOT depend on the Flask session for OAuth state.
#
# The OAuth state and PKCE code verifier are securely signed
# using the Flask secret key and sent through Google's OAuth
# state parameter.
#
# This avoids the production session-cookie problem that was
# causing "OAuth session expired".

oauth_state_serializer = URLSafeTimedSerializer(
    app.secret_key,
    salt="maldetector-oauth-state"
)


# =========================================================
# GOOGLE GMAIL SCOPES
# =========================================================

SCOPES = [
    "https://www.googleapis.com/auth/gmail.readonly"
]


# =========================================================
# GOOGLE OAUTH CONFIGURATION
# =========================================================

def get_google_client_config():
    """
    Uses Render environment variables in production.
    For local development, credentials.json can still be used.
    """

    client_id = os.environ.get(
        "GOOGLE_CLIENT_ID"
    )

    client_secret = os.environ.get(
        "GOOGLE_CLIENT_SECRET"
    )

    if client_id and client_secret:

        return {
            "web": {
                "client_id": client_id,
                "client_secret": client_secret,
                "auth_uri":
                    "https://accounts.google.com/o/oauth2/auth",
                "token_uri":
                    "https://oauth2.googleapis.com/token",
                "auth_provider_x509_cert_url":
                    "https://www.googleapis.com/oauth2/v1/certs"
            }
        }

    # Local development fallback
    credentials_path = os.path.join(
        BASE_DIR,
        "credentials.json"
    )

    if os.path.exists(credentials_path):

        import json

        with open(
            credentials_path,
            "r",
            encoding="utf-8"
        ) as file:

            return json.load(file)

    return None


# =========================================================
# CSS FILE
# =========================================================

@app.route("/css/<path:filename>")
def css_file(filename):

    return send_from_directory(
        CSS_DIR,
        filename
    )


# =========================================================
# JAVASCRIPT FILE
# =========================================================

@app.route("/js/<path:filename>")
def js_file(filename):

    return send_from_directory(
        JS_DIR,
        filename
    )


# =========================================================
# HOME
# =========================================================

@app.route("/")
def home():

    return render_template(
        "index.html"
    )


# =========================================================
# GMAIL LOGIN
# =========================================================

@app.route("/connect-gmail")
def connect_gmail():

    client_config = get_google_client_config()

    if not client_config:

        return (
            "Google OAuth configuration was not found."
        )

    redirect_uri = url_for(
        "oauth_callback",
        _external=True
    )

    flow = Flow.from_client_config(
        client_config,
        scopes=SCOPES,
        redirect_uri=redirect_uri
    )

    # Generate the PKCE code verifier.
    #
    # Flow.authorization_url() creates one automatically
    # when PKCE is being used.
    authorization_url, generated_state = (
        flow.authorization_url(
            access_type="offline",
            prompt="consent",
            include_granted_scopes="true"
        )
    )

    # The generated OAuth state is signed together with the
    # PKCE code verifier.
    #
    # This replaces:
    #
    # session["state"]
    # session["code_verifier"]
    #
    # which was the source of the production problem.

    signed_state = oauth_state_serializer.dumps({
        "state": generated_state,
        "code_verifier": flow.code_verifier
    })

    # Replace the state parameter in Google's authorization
    # URL with our signed state.
    #
    # authorization_url already contains ?state=...
    # so replace only that generated state value.

    from urllib.parse import (
        urlparse,
        parse_qs,
        urlencode,
        urlunparse
    )

    parsed_url = urlparse(
        authorization_url
    )

    query_params = parse_qs(
        parsed_url.query
    )

    query_params["state"] = [
        signed_state
    ]

    authorization_url = urlunparse(
        (
            parsed_url.scheme,
            parsed_url.netloc,
            parsed_url.path,
            parsed_url.params,
            urlencode(
                query_params,
                doseq=True
            ),
            parsed_url.fragment
        )
    )

    return redirect(
        authorization_url
    )


# =========================================================
# GMAIL OAUTH CALLBACK
# =========================================================

@app.route("/oauth2callback")
def oauth_callback():

    # Get Google's returned state.
    returned_state = request.args.get(
        "state"
    )

    if not returned_state:

        return (
            "OAuth state was not returned by Google."
        )

    # Verify and decode our signed OAuth state.
    try:

        oauth_data = oauth_state_serializer.loads(
            returned_state,
            max_age=600
        )

    except SignatureExpired:

        return (
            "OAuth session expired. "
            "Please connect Gmail again."
        )

    except BadSignature:

        return (
            "Invalid OAuth session. "
            "Please connect Gmail again."
        )

    except Exception as error:

        return (
            "Unable to verify OAuth session."
            "<br><br>"
            f"Error: {error}"
        )

    original_state = oauth_data.get(
        "state"
    )

    code_verifier = oauth_data.get(
        "code_verifier"
    )

    if not original_state or not code_verifier:

        return (
            "OAuth session data is incomplete. "
            "Please connect Gmail again."
        )

    client_config = get_google_client_config()

    if not client_config:

        return (
            "Google OAuth configuration was not found."
        )

    redirect_uri = url_for(
        "oauth_callback",
        _external=True
    )

    flow = Flow.from_client_config(
        client_config,
        scopes=SCOPES,
        state=original_state,
        redirect_uri=redirect_uri
    )

    # Restore the PKCE code verifier.
    flow.code_verifier = code_verifier

    try:

        flow.fetch_token(
            authorization_response=request.url
        )

    except Exception as error:

        return (
            "Unable to complete Google authentication."
            "<br><br>"
            f"Error: {error}"
        )

    credentials = flow.credentials

    # =====================================================
    # SAVE GMAIL TOKEN
    # =====================================================

    token_path = os.path.join(
        BASE_DIR,
        "token.json"
    )

    try:

        with open(
            token_path,
            "w",
            encoding="utf-8"
        ) as token:

            token.write(
                credentials.to_json()
            )

    except Exception as error:

        return (
            "Unable to save Gmail authentication."
            "<br><br>"
            f"Error: {error}"
        )

    return redirect(
        url_for("gmail")
    )


# =========================================================
# LOAD GMAIL CREDENTIALS
# =========================================================

def get_gmail_credentials():

    token_path = os.path.join(
        BASE_DIR,
        "token.json"
    )

    if not os.path.exists(
        token_path
    ):

        return None

    try:

        credentials = Credentials.from_authorized_user_file(
            token_path,
            SCOPES
        )

        return credentials

    except Exception:

        return None


# =========================================================
# GMAIL EMAIL LIST
# =========================================================

@app.route("/gmail")
def gmail():

    credentials = get_gmail_credentials()

    if not credentials:

        return redirect(
            url_for("connect_gmail")
        )

    try:

        service = build(
            "gmail",
            "v1",
            credentials=credentials
        )

        page_token = request.args.get(
            "page_token"
        )

        if page_token:

            results = service.users().messages().list(
                userId="me",
                maxResults=20,
                pageToken=page_token
            ).execute()

        else:

            results = service.users().messages().list(
                userId="me",
                maxResults=20
            ).execute()

    except Exception as error:

        return (
            "Unable to access Gmail."
            "<br><br>"
            f"Error: {error}"
        )

    messages = results.get(
        "messages",
        []
    )

    email_list = []

    for message in messages:

        try:

            message_data = service.users().messages().get(
                userId="me",
                id=message["id"],
                format="metadata",
                metadataHeaders=[
                    "From",
                    "Subject",
                    "Date"
                ]
            ).execute()

            headers = message_data[
                "payload"
            ].get(
                "headers",
                []
            )

            sender = "Unknown sender"
            subject = "No subject"
            date = ""

            for header in headers:

                name = header[
                    "name"
                ].lower()

                if name == "from":

                    sender = header[
                        "value"
                    ]

                elif name == "subject":

                    subject = header[
                        "value"
                    ]

                elif name == "date":

                    date = header[
                        "value"
                    ]

            email_list.append({
                "id": message["id"],
                "sender": sender,
                "subject": subject,
                "date": date
            })

        except Exception:

            continue

    next_page_token = results.get(
        "nextPageToken"
    )

    return render_template(
        "gmail.html",
        emails=email_list,
        next_page_token=next_page_token
    )


# =========================================================
# SELECT ONE GMAIL EMAIL
# =========================================================

@app.route("/gmail/email/<message_id>")
def select_gmail_email(message_id):

    credentials = get_gmail_credentials()

    if not credentials:

        return redirect(
            url_for("connect_gmail")
        )

    try:

        service = build(
            "gmail",
            "v1",
            credentials=credentials
        )

        message = service.users().messages().get(
            userId="me",
            id=message_id,
            format="full"
        ).execute()

    except Exception as error:

        return (
            "Unable to retrieve this email."
            "<br><br>"
            f"Error: {error}"
        )

    headers = message[
        "payload"
    ].get(
        "headers",
        []
    )

    sender = "Unknown sender"
    subject = "No subject"

    for header in headers:

        if header[
            "name"
        ].lower() == "from":

            sender = header[
                "value"
            ]

        elif header[
            "name"
        ].lower() == "subject":

            subject = header[
                "value"
            ]

    body = extract_email_body(
        message["payload"]
    )

    if not body:

        body = (
            "Email body could not be extracted."
        )

    return render_template(
        "analyze.html",
        sender=sender,
        subject=subject,
        email_body=body
    )


# =========================================================
# EXTRACT GMAIL EMAIL BODY
# =========================================================

def extract_email_body(payload):

    body = ""

    if "parts" in payload:

        for part in payload["parts"]:

            mime_type = part.get(
                "mimeType",
                ""
            )

            if mime_type == "text/plain":

                data = part.get(
                    "body",
                    {}
                ).get(
                    "data"
                )

                if data:

                    body = base64.urlsafe_b64decode(
                        data
                    ).decode(
                        "utf-8",
                        errors="replace"
                    )

                if body:

                    break

            elif mime_type.startswith(
                "multipart/"
            ):

                body = extract_email_body(
                    part
                )

                if body:

                    break

    else:

        data = payload.get(
            "body",
            {}
        ).get(
            "data"
        )

        if data:

            body = base64.urlsafe_b64decode(
                data
            ).decode(
                "utf-8",
                errors="replace"
            )

    return body


# =========================================================
# UPLOAD .EML FILE
# =========================================================

@app.route(
    "/upload-email",
    methods=["POST"]
)
def upload_email():

    uploaded_file = request.files.get(
        "email_file"
    )

    if not uploaded_file:

        return "No file selected."

    if uploaded_file.filename == "":

        return "No file selected."

    if not uploaded_file.filename.lower().endswith(
        ".eml"
    ):

        return "Only .eml files are allowed."

    try:

        email_data = uploaded_file.read()

        msg = BytesParser(
            policy=policy.default
        ).parsebytes(
            email_data
        )

    except Exception as error:

        return (
            "Unable to read the .eml file."
            "<br><br>"
            f"Error: {error}"
        )

    sender = msg.get(
        "From",
        "Unknown sender"
    )

    subject = msg.get(
        "Subject",
        "No subject"
    )

    body = ""

    if msg.is_multipart():

        for part in msg.walk():

            if part.get_content_type() == "text/plain":

                try:

                    body = part.get_content()

                except Exception:

                    body = ""

                if body:

                    break

    else:

        try:

            body = msg.get_content()

        except Exception:

            body = ""

    if not body:

        body = (
            "Email body could not be extracted."
        )

    return render_template(
        "analyze.html",
        sender=sender,
        subject=subject,
        email_body=body
    )


# =========================================================
# ANALYZE EMAIL
# =========================================================

@app.route(
    "/analyze",
    methods=["POST"]
)
def analyze():

    email_text = request.form.get(
        "email_body",
        ""
    )

    sender = request.form.get(
        "sender",
        "Unknown sender"
    )

    subject = request.form.get(
        "subject",
        "No subject"
    )

    score = 0
    reasons = []

    text = email_text.lower()


    # =====================================================
    # URGENCY DETECTION
    # =====================================================

    urgency_words = [
        "urgent",
        "immediately",
        "limited time",
        "act now",
        "expires",
        "deadline",
        "hurry",
        "last chance"
    ]

    for word in urgency_words:

        if word in text:

            score += 8

            reasons.append(
                f"Urgency detected: '{word}'"
            )


    # =====================================================
    # PAYMENT DETECTION
    # =====================================================

    payment_words = [
        "payment",
        "pay",
        "invoice",
        "money",
        "price",
        "₹",
        "inr",
        "bank account",
        "credit card",
        "debit card"
    ]

    for word in payment_words:

        if word in text:

            score += 7

            reasons.append(
                f"Payment-related content detected: '{word}'"
            )


    # =====================================================
    # ACCOUNT / CREDENTIAL DETECTION
    # =====================================================

    credential_words = [
        "password",
        "verify your account",
        "login",
        "sign in",
        "username",
        "otp",
        "verification code",
        "credentials"
    ]

    for word in credential_words:

        if word in text:

            score += 10

            reasons.append(
                f"Credential-related content detected: '{word}'"
            )


    # =====================================================
    # SUSPICIOUS LINK DETECTION
    # =====================================================

    urls = re.findall(
        r"https?://[^\s]+",
        email_text
    )

    if urls:

        score += 10

        reasons.append(
            f"Email contains {len(urls)} link(s)"
        )


    # =====================================================
    # LINK SHORTENER DETECTION
    # =====================================================

    shorteners = [
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "goo.gl",
        "ow.ly",
        "is.gd"
    ]

    for shortener in shorteners:

        if shortener in text:

            score += 15

            reasons.append(
                f"URL shortener detected: '{shortener}'"
            )


    # =====================================================
    # THREAT / MALWARE WORDS
    # =====================================================

    malware_words = [
        "malware",
        "virus",
        "trojan",
        "ransomware",
        "infected",
        "suspicious attachment",
        "download attachment"
    ]

    for word in malware_words:

        if word in text:

            score += 12

            reasons.append(
                f"Malware-related content detected: '{word}'"
            )


    # =====================================================
    # THREAT LEVEL
    # =====================================================

    score = min(
        score,
        100
    )

    if score <= 24:

        level_class = "low"
        threat_name = "Low Risk"

        threat_description = (
            "The email contains few or no suspicious "
            "indicators based on the current detection rules. "
            "It appears relatively safe, but always verify "
            "unexpected emails before interacting with them."
        )

    elif score <= 49:

        level_class = "suspicious"
        threat_name = "Suspicious"

        threat_description = (
            "The email contains several indicators that "
            "deserve caution. Avoid clicking links or "
            "providing sensitive information until the "
            "sender and request have been verified."
        )

    elif score <= 74:

        level_class = "high"
        threat_name = "High Risk"

        threat_description = (
            "Multiple suspicious characteristics were detected. "
            "This email may be attempting phishing, credential "
            "theft, financial fraud, or another malicious action."
        )

    else:

        level_class = "critical"
        threat_name = "Critical Threat"

        threat_description = (
            "The email contains strong indicators associated "
            "with phishing or malicious activity. Do not click "
            "links, open unexpected attachments, or provide "
            "credentials or financial information."
        )


    # =====================================================
    # RESULTS PAGE
    # =====================================================

    return render_template(
        "results.html",
        sender=sender,
        subject=subject,
        email_body=email_text,
        score=score,
        level_class=level_class,
        threat_name=threat_name,
        threat_description=threat_description,
        reasons=reasons
    )


# =========================================================
# RUN APPLICATION
# =========================================================

if __name__ == "__main__":

    print()
    print("======================================")
    print("       MalDetector Starting...")
    print("======================================")
    print()

    print("Project folder:")
    print(BASE_DIR)
    print()

    print("Templates folder:")
    print(TEMPLATES_DIR)
    print()

    print("Static folder:")
    print(STATIC_DIR)
    print()

    print("CSS folder:")
    print(CSS_DIR)
    print()

    print("CSS file:")
    print(
        os.path.join(
            CSS_DIR,
            "style.css"
        )
    )

    print()

    print("CSS file exists:")
    print(
        os.path.exists(
            os.path.join(
                CSS_DIR,
                "style.css"
            )
        )
    )

    print()

    print("======================================")
    print()

    app.run(
        debug=True
    )
