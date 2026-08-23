import os
import base64
import re

from email import policy
from email.parser import BytesParser

# Allow OAuth to work on local Flask HTTP server
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

from flask import (
    Flask,
    render_template,
    redirect,
    url_for,
    session,
    request,
    send_from_directory,
)

from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials


# =========================================================
# PROJECT PATHS
# =========================================================

BASE_DIR = os.path.dirname(
    os.path.abspath(__file__)
)

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

app.secret_key = "maldetector-secret-key"


# =========================================================
# GOOGLE GMAIL SCOPES
# =========================================================

SCOPES = [
    "https://www.googleapis.com/auth/gmail.readonly"
]


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

    credentials_path = os.path.join(
        BASE_DIR,
        "credentials.json"
    )

    if not os.path.exists(credentials_path):

        return (
            "credentials.json was not found. "
            "Please place your Google OAuth credentials "
            "file in the project folder."
        )

    flow = Flow.from_client_secrets_file(
        credentials_path,
        scopes=SCOPES,
        redirect_uri=url_for(
            "oauth_callback",
            _external=True
        )
    )

    authorization_url, state = flow.authorization_url(
        access_type="offline",
        prompt="consent",
        include_granted_scopes="true"
    )

    session["state"] = state
    session["code_verifier"] = flow.code_verifier

    return redirect(
        authorization_url
    )


# =========================================================
# GMAIL OAUTH CALLBACK
# =========================================================

@app.route("/oauth2callback")
def oauth_callback():

    state = session.get("state")
    code_verifier = session.get("code_verifier")

    credentials_path = os.path.join(
        BASE_DIR,
        "credentials.json"
    )

    if not os.path.exists(credentials_path):

        return (
            "credentials.json was not found."
        )

    flow = Flow.from_client_secrets_file(
        credentials_path,
        scopes=SCOPES,
        state=state,
        redirect_uri=url_for(
            "oauth_callback",
            _external=True
        )
    )

    flow.code_verifier = code_verifier

    flow.fetch_token(
        authorization_response=request.url
    )

    credentials = flow.credentials

    token_path = os.path.join(
        BASE_DIR,
        "token.json"
    )

    with open(
        token_path,
        "w"
    ) as token:

        token.write(
            credentials.to_json()
        )

    return redirect(
        url_for("gmail")
    )


# =========================================================
# GMAIL EMAIL LIST
# =========================================================

@app.route("/gmail")
def gmail():

    token_path = os.path.join(
        BASE_DIR,
        "token.json"
    )

    if not os.path.exists(token_path):

        return redirect(
            url_for("connect_gmail")
        )

    try:

        credentials = Credentials.from_authorized_user_file(
            token_path,
            SCOPES
        )

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
            "Unable to access Gmail.<br><br>"
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

@app.route(
    "/gmail/email/<message_id>"
)
def select_gmail_email(message_id):

    token_path = os.path.join(
        BASE_DIR,
        "token.json"
    )

    if not os.path.exists(token_path):

        return redirect(
            url_for("connect_gmail")
        )

    try:

        credentials = Credentials.from_authorized_user_file(
            token_path,
            SCOPES
        )

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
            "Unable to retrieve this email.<br><br>"
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

    # =====================================================
    # IMPORTANT:
    # Selected Gmail email now opens the SEPARATE
    # ANALYZE PAGE instead of index.html
    # =====================================================

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

            # Plain text email
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

            # Multipart email
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

        return (
            "No file selected."
        )

    if uploaded_file.filename == "":

        return (
            "No file selected."
        )

    if not uploaded_file.filename.lower().endswith(
        ".eml"
    ):

        return (
            "Only .eml files are allowed."
        )

    try:

        email_data = uploaded_file.read()

        msg = BytesParser(
            policy=policy.default
        ).parsebytes(
            email_data
        )

    except Exception as error:

        return (
            "Unable to read the .eml file.<br><br>"
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

    # =====================================================
    # MULTIPART EMAIL
    # =====================================================

    if msg.is_multipart():

        for part in msg.walk():

            if part.get_content_type() == "text/plain":

                try:

                    body = part.get_content()

                except Exception:

                    body = ""

                if body:

                    break

    # =====================================================
    # NORMAL EMAIL
    # =====================================================

    else:

        try:

            body = msg.get_content()

        except Exception:

            body = ""

    if not body:

        body = (
            "Email body could not be extracted."
        )

    # =====================================================
    # UPLOADED EMAIL ALSO OPENS THE SEPARATE
    # ANALYZE PAGE
    # =====================================================

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


    # =====================================================
    # LEVEL CLASS + NAME + DESCRIPTION
    # =====================================================

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

    print(
        "======================================"
    )

    print(
        "       MalDetector Starting..."
    )

    print(
        "======================================"
    )

    print()

    print(
        "Project folder:"
    )

    print(
        BASE_DIR
    )

    print()

    print(
        "Templates folder:"
    )

    print(
        TEMPLATES_DIR
    )

    print()

    print(
        "Static folder:"
    )

    print(
        STATIC_DIR
    )

    print()

    print(
        "CSS folder:"
    )

    print(
        CSS_DIR
    )

    print()

    print(
        "CSS file:"
    )

    print(
        os.path.join(
            CSS_DIR,
            "style.css"
        )
    )

    print()

    print(
        "CSS file exists:"
    )

    print(
        os.path.exists(
            os.path.join(
                CSS_DIR,
                "style.css"
            )
        )
    )

    print()

    print(
        "======================================"
    )

    print()

    app.run(
        debug=True
    )