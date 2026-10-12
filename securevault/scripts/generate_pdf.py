#!/usr/bin/env python3
"""
scripts/generate_pdf.py
Generates a comprehensive, beautifully styled PDF guide for SecureVault:
- What it is
- How it works
- The 5 core security mechanisms (plus bonus controls)
- How to make it work (setup, run, test)
- How to explain it in a viva/exam with Q&A
"""

import os
from pathlib import Path
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
    KeepTogether,
    HRFlowable,
)
from reportlab.pdfgen import canvas

class NumberedCanvas(canvas.Canvas):
    """Canvas that computes total pages dynamically for a 'Page X of Y' footer."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, total_pages):
        self.saveState()
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor("#64748b"))

        # Running header (pages > 1)
        if self._pageNumber > 1:
            self.drawString(54, 11 * inch - 36, "SecureVault — Comprehensive Project Documentation & Viva Guide")
            self.setStrokeColor(colors.HexColor("#cbd5e1"))
            self.setLineWidth(0.5)
            self.line(54, 11 * inch - 42, 8.5 * inch - 54, 11 * inch - 42)

        # Running footer
        page_str = f"Page {self._pageNumber} of {total_pages}"
        self.drawRightString(8.5 * inch - 54, 32, page_str)
        self.drawString(54, 32, "Confidential — Academic Cybersecurity Project & Defense Architecture")
        self.setStrokeColor(colors.HexColor("#cbd5e1"))
        self.setLineWidth(0.5)
        self.line(54, 44, 8.5 * inch - 54, 44)

        self.restoreState()


def build_pdf(filename: str):
    doc = SimpleDocTemplate(
        filename,
        pagesize=letter,
        leftMargin=54,
        rightMargin=54,
        topMargin=54,
        bottomMargin=54,
    )

    styles = getSampleStyleSheet()

    # Custom color palette
    c_primary = colors.HexColor("#0f172a")     # Dark Slate
    c_accent = colors.HexColor("#0284c7")      # Vibrant Cyan/Blue
    c_secondary = colors.HexColor("#334155")   # Medium Slate
    c_text = colors.HexColor("#1e293b")        # Deep charcoal
    c_bg_box = colors.HexColor("#f8fafc")      # Off-white / light slate
    c_border = colors.HexColor("#cbd5e1")      # Border gray
    c_tag_bg = colors.HexColor("#e0f2fe")      # Cyan tag bg
    c_tag_text = colors.HexColor("#0369a1")

    # Typography styles
    styles.add(ParagraphStyle(
        "CoverTitle",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=24,
        leading=28,
        textColor=c_primary,
        alignment=0,
        spaceAfter=6,
    ))
    styles.add(ParagraphStyle(
        "CoverSubtitle",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=12,
        leading=16,
        textColor=c_accent,
        spaceAfter=15,
    ))
    styles.add(ParagraphStyle(
        "H1_Custom",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=15,
        leading=19,
        textColor=c_primary,
        spaceBefore=14,
        spaceAfter=6,
        keepWithNext=True,
    ))
    styles.add(ParagraphStyle(
        "H2_Custom",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=12,
        leading=16,
        textColor=c_accent,
        spaceBefore=10,
        spaceAfter=4,
        keepWithNext=True,
    ))
    styles.add(ParagraphStyle(
        "Body_Custom",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9.5,
        leading=13.5,
        textColor=c_text,
        spaceAfter=6,
    ))
    styles.add(ParagraphStyle(
        "Body_Bold",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=9.5,
        leading=13.5,
        textColor=c_text,
        spaceAfter=6,
    ))
    styles.add(ParagraphStyle(
        "CalloutText",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=13,
        textColor=c_text,
    ))
    styles.add(ParagraphStyle(
        "CodeText",
        parent=styles["Normal"],
        fontName="Courier",
        fontSize=8.5,
        leading=11,
        textColor=colors.HexColor("#0f172a"),
    ))
    styles.add(ParagraphStyle(
        "QA_Q",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=10,
        leading=14,
        textColor=c_primary,
        spaceBefore=8,
        spaceAfter=2,
        keepWithNext=True,
    ))
    styles.add(ParagraphStyle(
        "QA_A",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=9,
        leading=13,
        textColor=colors.HexColor("#334155"),
        spaceAfter=8,
    ))

    story = []

    def make_callout(text: str, title: str = "KEY TAKEAWAY", bg_color=c_bg_box, border_color=c_accent):
        content = [
            Paragraph(f"<b>{title}:</b> {text}", styles["CalloutText"])
        ]
        t = Table([[content]], colWidths=[504])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), bg_color),
            ("BOX", (0, 0), (-1, -1), 1, border_color),
            ("LINEBEFORE", (0, 0), (-1, -1), 3.5, border_color),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("LEFTPADDING", (0, 0), (-1, -1), 10),
            ("RIGHTPADDING", (0, 0), (-1, -1), 10),
        ]))
        return t

    # =========================================================================
    # COVER / HEADER
    # =========================================================================
    story.append(Spacer(1, 10))
    story.append(Paragraph("SecureVault: Encrypted Note & Credential Keeper", styles["CoverTitle"]))
    story.append(Paragraph("Complete Technical Architecture, Security Specifications, Setup & Viva Defense Guide", styles["CoverSubtitle"]))
    story.append(HRFlowable(width="100%", thickness=1.5, color=c_accent, spaceBefore=0, spaceAfter=12))

    # Meta Table
    meta_data = [
        [
            Paragraph("<b>Project:</b> SecureVault", styles["Body_Custom"]),
            Paragraph("<b>Stack:</b> Python 3.10+, Flask 3.x, SQLite (No ORM)", styles["Body_Custom"]),
        ],
        [
            Paragraph("<b>Domain:</b> Full-Stack Cyber Defense", styles["Body_Custom"]),
            Paragraph("<b>Crypto:</b> AES-256-GCM + HKDF-SHA256 + scrypt", styles["Body_Custom"]),
        ],
    ]
    meta_table = Table(meta_data, colWidths=[252, 252])
    meta_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f1f5f9")),
        ("BOX", (0, 0), (-1, -1), 0.5, c_border),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 10))

    # =========================================================================
    # SECTION 1: WHAT THIS IS & PURPOSE
    # =========================================================================
    story.append(Paragraph("1. Executive Summary & Purpose", styles["H1_Custom"]))
    story.append(Paragraph(
        "<b>SecureVault</b> is an academic-grade, secure web application designed to store confidential notes and sensitive login credentials. "
        "Unlike commercial applications that obscure cryptographic primitives behind heavy abstractions, SecureVault was purposefully built to "
        "<b>demonstrate transparent, auditable, defense-in-depth cybersecurity controls</b>.",
        styles["Body_Custom"]
    ))
    story.append(Paragraph(
        "All sensitive data stored in the database is encrypted at rest using individual authenticated ciphertexts. Passwords are never stored in plaintext, "
        "and every layer of the HTTP request lifecycle enforces rigorous defensive controls against injection, cross-site request forgery, cross-site scripting, "
        "session hijacking, and automated brute-force attacks.",
        styles["Body_Custom"]
    ))

    # =========================================================================
    # SECTION 2: HOW IT WORKS (ARCHITECTURE & WORKFLOW)
    # =========================================================================
    story.append(Paragraph("2. System Architecture & Workflow", styles["H1_Custom"]))
    story.append(Paragraph(
        "SecureVault is structured following the Flask Application Factory pattern, using raw SQLite queries with strict parameterized inputs. "
        "The cryptographic workflow follows a zero-plaintext at rest model:",
        styles["Body_Custom"]
    ))

    flow_data = [
        ["Phase", "Component", "Security Operation & Data Flow"],
        ["Registration", "app/auth.py", "Enforces password complexity (10-128 chars, upper, lower, digit, symbol). Generates 16 random salt bytes and stores salted password hash via scrypt."],
        ["Key Derivation", "app/crypto.py", "HKDF-SHA256 extracts a unique 256-bit AES user key using the 32-byte master key (.env) + that user's 16-byte key salt."],
        ["Data Storage", "app/vault.py", "AES-256-GCM encrypts each field with a fresh 12-byte random nonce and associated data 'user:<id>'. Stores base64(nonce || ciphertext || tag)."],
        ["Data Retrieval", "app/vault.py", "Queries fetch raw rows by 'user_id = ?'. AES-256-GCM decrypts payload in server memory. Passwords remain masked as '••••••••' by default."],
        ["Password Reveal", "app/vault.py", "Dedicated reveal endpoint decrypts on demand with rate limiting (30/min). Frontend reveals plaintext for exactly 10s then auto-masks."],
    ]
    flow_table = Table(flow_data, colWidths=[80, 84, 340])
    flow_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), c_primary),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8.5),
        ("GRID", (0, 0), (-1, -1), 0.5, c_border),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(flow_table)
    story.append(Spacer(1, 10))

    # =========================================================================
    # SECTION 3: THE FIVE CORE SECURITY MEASURES
    # =========================================================================
    story.append(Paragraph("3. The Five Core Security Mechanisms (In Depth)", styles["H1_Custom"]))

    # Mechanism 1
    story.append(Paragraph("Mechanism 1: AES-256-GCM Encryption at Rest (app/crypto.py)", styles["H2_Custom"]))
    story.append(Paragraph(
        "• <b>Master Key:</b> A 32-byte cryptographically secure random key stored in <code>.env</code> (never in SQLite, never committed to git).<br/>"
        "• <b>Per-User Key Isolation:</b> Derives a dedicated 256-bit AES key per user using <code>HKDF-SHA256</code> with user-specific 16-byte random salt and context <code>info=b'securevault-user-key-v1'</code>.<br/>"
        "• <b>Authenticated Cipher:</b> Uses AES in Galois/Counter Mode (GCM). Generates a fresh 12-byte random nonce for <i>every single field</i>.<br/>"
        "• <b>Cryptographic Binding:</b> Associated Authenticated Data (AAD) binds the ciphertext to <code>user:{user_id}</code>, preventing cross-tenant ciphertext swapping.<br/>"
        "• <b>Tamper Detection:</b> Any alteration of ciphertext bytes fails GCM tag authentication, throwing an exception and logging an audit event.",
        styles["Body_Custom"]
    ))
    story.append(make_callout(
        "Threat Mitigated: Database Exfiltration & Storage Tampering. If an attacker dumps the SQLite file, they obtain only high-entropy random-looking ciphertext blobs.",
        "THREAT MITIGATED"
    ))
    story.append(Spacer(1, 8))

    # Mechanism 2
    story.append(Paragraph("Mechanism 2: Salted Password Hashing & Timing Mitigation (app/auth.py)", styles["H2_Custom"]))
    story.append(Paragraph(
        "• <b>scrypt Hashing:</b> Uses werkzeug's <code>scrypt</code> implementation (memory-hard, resistant to GPU/ASIC cracking) with fallback to PBKDF2:SHA256 (600,000 iterations).<br/>"
        "• <b>Strict Password Policy:</b> Minimum 10 characters, at least 1 uppercase, 1 lowercase, 1 digit, 1 special symbol, max 128 characters.<br/>"
        "• <b>Constant-Time Dummy Verification:</b> When a non-existent username attempts login, the server still verifies against a pre-computed dummy hash. Returns identical generic 'Invalid username or password' responses to prevent timing enumeration.<br/>"
        "• <b>Account Lockout:</b> 5 consecutive failed login attempts trigger an automatic 5-minute lockout.",
        styles["Body_Custom"]
    ))
    story.append(make_callout(
        "Threat Mitigated: User Enumeration & Offline Hash Cracking. Eliminates response-timing discrepancy between valid and invalid usernames.",
        "THREAT MITIGATED"
    ))
    story.append(Spacer(1, 8))

    # Mechanism 3
    story.append(Paragraph("Mechanism 3: Tiered IP-Based Rate Limiting (app/security.py)", styles["H2_Custom"]))
    story.append(Paragraph(
        "• <b>Flask-Limiter Keying:</b> Rate limits are strictly tied to remote client IP addresses (<code>get_remote_address</code>).<br/>"
        "• <b>Granular Throttling:</b> <code>POST /login</code>: 5/minute; <code>POST /register</code>: 5/hour; <code>/reveal</code>: 30/minute; default: 200/hour.<br/>"
        "• <b>Graceful 429 Responses:</b> Returns sanitized HTTP 429 JSON/HTML and logs an immutable <code>rate_limited</code> audit event.",
        styles["Body_Custom"]
    ))
    story.append(make_callout(
        "Threat Mitigated: Automated Credential Stuffing & Denial of Service (DoS). Throttles password-guessing bots to an infeasible rate.",
        "THREAT MITIGATED"
    ))
    story.append(Spacer(1, 8))

    # Mechanism 4
    story.append(Paragraph("Mechanism 4: SQL Injection & Cross-Site Scripting (XSS) Defenses", styles["H2_Custom"]))
    story.append(Paragraph(
        "• <b>100% Parameterized SQL:</b> Raw SQLite queries strictly use <code>?</code> placeholders. String concatenation and f-strings in SQL are completely forbidden.<br/>"
        "• <b>Strict Content Security Policy (CSP):</b> Outbound headers enforce <code>default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'; frame-ancestors 'none'</code>.<br/>"
        "• <b>Safe DOM Manipulation:</b> Frontend uses <code>textContent</code> and <code>createElement</code> exclusively. <code>innerHTML</code>, <code>outerHTML</code>, <code>eval()</code>, and inline handlers (<code>onclick</code>) are strictly absent.<br/>"
        "• <b>Defensive Headers:</b> <code>X-Content-Type-Options: nosniff</code>, <code>X-Frame-Options: DENY</code>, <code>Referrer-Policy: no-referrer</code>.",
        styles["Body_Custom"]
    ))
    story.append(make_callout(
        "Threat Mitigated: SQL Injection, Stored/Reflected XSS, and Clickjacking. Payloads like ' OR 1=1-- or <script>alert(1)</script> are treated as inert strings.",
        "THREAT MITIGATED"
    ))
    story.append(Spacer(1, 8))

    # Mechanism 5
    story.append(Paragraph("Mechanism 5: Hardened Session Management & CSRF Defense", styles["H2_Custom"]))
    story.append(Paragraph(
        "• <b>Cookie Hardening:</b> Signed Flask cookies with <code>HttpOnly=True</code>, <code>SameSite='Lax'</code>, and configurable <code>COOKIE_SECURE</code>.<br/>"
        "• <b>Idle Timeout (15 Mins):</b> Sliding inactivity window tracked server-side and client-side with countdown and 60-second warning banner.<br/>"
        "• <b>Session Fixation Defense:</b> <code>session.clear()</code> is executed on successful login before assigning fresh session keys.<br/>"
        "• <b>Per-Session Anti-CSRF Token:</b> Every state-changing request (POST/PUT/DELETE) must send a valid CSRF token, compared via constant-time <code>hmac.compare_digest</code>.",
        styles["Body_Custom"]
    ))
    story.append(make_callout(
        "Threat Mitigated: Cross-Site Request Forgery (CSRF), Session Fixation, and Session Hijacking via Malicious Scripts.",
        "THREAT MITIGATED"
    ))
    story.append(Spacer(1, 8))

    # Bonus mechanisms
    story.append(Paragraph("Bonus Defensive Controls", styles["H2_Custom"]))
    story.append(Paragraph(
        "• <b>Insecure Direct Object Reference (IDOR) Protection:</b> Every record lookup includes <code>AND user_id = ?</code>. Accessing another user's note or credential returns <b>404 Not Found</b> (never 403), preventing attackers from enumerating valid resource IDs.<br/>"
        "• <b>Append-Only Audit Log:</b> Tracks <code>register</code>, <code>login_success</code>, <code>login_failed</code>, <code>account_locked</code>, <code>credential_revealed</code>, etc., with client IP and UTC timestamp without leaking secrets.<br/>"
        "• <b>Sanitized Error Pages:</b> HTTP errors (400, 401, 403, 404, 405, 413, 429, 500) return sanitized error views; Werkzeug debuggers and stack traces are suppressed.",
        styles["Body_Custom"]
    ))

    # =========================================================================
    # SECTION 4: HOW TO MAKE IT WORK
    # =========================================================================
    story.append(PageBreak())
    story.append(Paragraph("4. How to Make It Work (Setup, Run & Verify)", styles["H1_Custom"]))
    story.append(Paragraph(
        "The project is structured to run out of the box with zero external internet dependencies during runtime (no CDN scripts, no external fonts).",
        styles["Body_Custom"]
    ))

    setup_code = (
        "# 1. Navigate to the project directory\n"
        "cd /Users/advaitkubal/Desktop/cyber/securevault\n\n"
        "# 2. Activate virtual environment\n"
        "source venv/bin/activate\n\n"
        "# 3. Run the application\n"
        "python run.py\n"
        "# --> Starts server at http://127.0.0.1:5000 (debug OFF)\n\n"
        "# 4. Run the security verification test suite\n"
        "pytest -v tests/test_security.py\n\n"
        "# 5. Inspect raw encrypted database records (Viva Demo Script)\n"
        "python scripts/show_db.py"
    )
    t_code = Table([[Paragraph(setup_code.replace("\n", "<br/>").replace(" ", "&nbsp;"), styles["CodeText"])]], colWidths=[504])
    t_code.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#0f172a")),
        ("TEXTCOLOR", (0, 0), (-1, -1), colors.HexColor("#38bdf8")),
        ("BOX", (0, 0), (-1, -1), 1, colors.HexColor("#334155")),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("LEFTPADDING", (0, 0), (-1, -1), 12),
        ("RIGHTPADDING", (0, 0), (-1, -1), 12),
    ]))
    story.append(t_code)
    story.append(Spacer(1, 10))

    # =========================================================================
    # SECTION 5: HOW TO EXPLAIN IT IN A VIVA / EXAM
    # =========================================================================
    story.append(Paragraph("5. How to Explain It in a Viva / Evaluation", styles["H1_Custom"]))
    story.append(Paragraph(
        "Use this structured framework when presenting SecureVault to an evaluator, professor, or interviewer.",
        styles["Body_Custom"]
    ))

    # The 2-Minute Pitch
    story.append(Paragraph("The 2-Minute Elevator Pitch", styles["H2_Custom"]))
    story.append(Paragraph(
        "<i>\"SecureVault is an encrypted note and credential keeper designed to demonstrate end-to-end defense-in-depth principles. "
        "Unlike standard web applications where database administrators or attackers with SQL dump access can read plaintext secrets, "
        "SecureVault enforces zero plaintext at rest using authenticated AES-256-GCM. We derive per-user keys using HKDF-SHA256, hash passwords "
        "using memory-hard scrypt, mitigate timing attacks using constant-time dummy verifications, protect against brute-force using tiered rate limiting "
        "and account lockouts, eliminate injection via 100% parameterized queries, and protect sessions with strict sliding idle timeouts and CSRF tokens. "
        "The application has 15 automated security tests verifying each defense mechanism.\"</i>",
        styles["Body_Custom"]
    ))
    story.append(Spacer(1, 8))

    # Step-by-Step Viva Demo Workflow
    story.append(Paragraph("5-Minute Live Demonstration Checklist", styles["H2_Custom"]))
    demo_steps = [
        ["Step", "Action", "What to Point Out to the Professor"],
        ["1", "Go to /register and type a weak password", "Show the live complexity checklist dynamically rejecting passwords lacking uppercase/numbers/symbols."],
        ["2", "Submit compliant registration & log in", "Explain that passwords are saved as scrypt salted hashes, and a unique 16-byte HKDF salt is created."],
        ["3", "Add a secret note & credential", "Show that passwords are saved encrypted and masked in the UI with dots (••••••••)."],
        ["4", "Click 'Reveal' on credential", "Show the 10-second countdown timer before the password automatically re-masks itself."],
        ["5", "Click 'View Ciphertext' / 'Raw'", "Show the raw base64 string. Explain the payload format: nonce + ciphertext + GCM tag."],
        ["6", "Run 'python scripts/show_db.py'", "Show the terminal output proving SQLite has zero plaintext secrets and passwords are only scrypt hashes."],
        ["7", "Try SQL injection on login: ' OR '1'='1", "Show that the attempt returns 401 without error 500, proving parameterized queries work."],
        ["8", "Try XSS payload: <script>alert(1)</script>", "Show that it renders safely as plain text because of textContent and strict CSP headers."],
        ["9", "Trigger Rate Limiting (6 rapid logins)", "Show the application returning HTTP 429 Too Many Requests and logging an audit event."],
    ]
    t_demo = Table(demo_steps, colWidths=[30, 160, 314])
    t_demo.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), c_primary),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.5, c_border),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
        ("TOPPADDING", (0, 0), (-1, -1), 3.5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3.5),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(t_demo)
    story.append(Spacer(1, 10))

    # Anticipated Viva Q&A
    story.append(KeepTogether([
        Paragraph("Top 8 Anticipated Viva Questions & Model Answers", styles["H2_Custom"]),
        Paragraph("<b>Q1: Why did you choose AES-GCM over AES-CBC?</b>", styles["QA_Q"]),
        Paragraph("<b>A:</b> AES-CBC only provides confidentiality, making it vulnerable to padding oracle attacks and bit-flipping if unauthenticated. AES-GCM is an Authenticated Encryption with Associated Data (AEAD) mode that provides both confidentiality and cryptographic integrity. If any ciphertext byte is tampered with, GCM tag verification fails immediately.", styles["QA_A"]),

        Paragraph("<b>Q2: What is HKDF and why derive per-user keys instead of using the master key directly?</b>", styles["QA_Q"]),
        Paragraph("<b>A:</b> HKDF (HMAC-based Key Derivation Function, RFC 5869) extracts and expands entropy. Deriving per-user keys ensures cryptographic domain separation. Even if one user's derived key were ever compromised, other users' data remains completely secure.", styles["QA_A"]),

        Paragraph("<b>Q3: How do you prevent timing attacks during user login?</b>", styles["QA_Q"]),
        Paragraph("<b>A:</b> When an unregistered username is entered, we still run <code>check_password_hash()</code> against a pre-computed dummy hash. This ensures the server takes the exact same mathematical computation time regardless of whether a username exists, defeating user enumeration.", styles["QA_A"]),

        Paragraph("<b>Q4: Why return 404 instead of 403 when User B tries to access User A's note (IDOR)?</b>", styles["QA_Q"]),
        Paragraph("<b>A:</b> Returning 403 confirms to an attacker that the resource exists (ID enumeration). Returning 404 treats unauthorized records as non-existent, revealing zero intelligence about valid ID ranges.", styles["QA_A"]),

        Paragraph("<b>Q5: Why did you not use an ORM like SQLAlchemy?</b>", styles["QA_Q"]),
        Paragraph("<b>A:</b> ORMs can hide query mechanics and introduce complex dependencies. In cybersecurity evaluations, writing parameterized SQL statements by hand with explicit <code>?</code> placeholders proves an exact understanding of SQL injection prevention at the transport layer.", styles["QA_A"]),

        Paragraph("<b>Q6: How does your Content Security Policy (CSP) prevent XSS?</b>", styles["QA_Q"]),
        Paragraph("<b>A:</b> Our CSP specifies <code>default-src 'self'; script-src 'self'; object-src 'none'</code>. Browsers strictly refuse to execute inline scripts (<code>&lt;script&gt;</code> tags or <code>onclick</code> attributes) or scripts loaded from untrusted domains, neutralizing injected scripts.", styles["QA_A"]),

        Paragraph("<b>Q7: How is session fixation mitigated?</b>", styles["QA_Q"]),
        Paragraph("<b>A:</b> Upon successful login, the application explicitly calls <code>session.clear()</code> before establishing fresh user authentication keys. This destroys any pre-existing session token an attacker might have attempted to fixate.", styles["QA_A"]),

        Paragraph("<b>Q8: What are the main real-world limitations and future improvements?</b>", styles["QA_Q"]),
        Paragraph("<b>A:</b> In a production enterprise system, the master key would reside in a Hardware Security Module (HSM) or Cloud KMS (AWS KMS / HashiCorp Vault) rather than a local <code>.env</code> file. Additional improvements include TOTP two-factor authentication, Redis-backed rate limiting, and automated key rotation.", styles["QA_A"]),
    ]))

    doc.build(story, canvasmaker=NumberedCanvas)
    return filename

if __name__ == "__main__":
    out_dir = Path("/Users/advaitkubal/Desktop/cyber")
    out_pdf = out_dir / "SecureVault_Project_Guide.pdf"
    build_pdf(str(out_pdf))
    print(f"Successfully generated PDF at: {out_pdf}")
