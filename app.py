"""
AWS Internal Audit Dashboard
Streamlit-based web UI with authentication, multi-account AWS auditing,
admin panel, user profiles, and audit history.

Run with:  streamlit run app.py
"""

import streamlit as st
import os
import io
import threading
import uuid
import time
import pandas as pd
from datetime import datetime

import pyotp
import qrcode

from auth import AuthManager, SECURITY_QUESTIONS, password_strength, validate_password


def _fmt_dt(val):
    """Format a datetime value (object or string) for display."""
    if val is None:
        return "N/A"
    if isinstance(val, datetime):
        return val.strftime("%Y-%m-%d %H:%M")
    return str(val)[:16]
from auditor import run_audit_steps, QUOTA_REGIONS, REGION_NAMES
from report_generator import generate_report, generate_optimization_report
from optimizer import run_optimization_scan

REPORTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports")
auth = AuthManager()


# ═════════════════════════════════════════════════════════════════════════
# BACKGROUND JOB MANAGER
# ═════════════════════════════════════════════════════════════════════════
@st.cache_resource
def _get_jobs_store():
    """Shared job store that survives Streamlit reruns and module reimports."""
    return {"jobs": {}, "lock": threading.Lock()}

def _jobs_dict():
    return _get_jobs_store()["jobs"]

def _jobs_lock():
    return _get_jobs_store()["lock"]


def _start_job(job_type, user_id, label, accounts, **kwargs):
    """Start a background audit or optimization job."""
    job_id = str(uuid.uuid4())[:8]
    job = {
        "id": job_id,
        "type": job_type,
        "user_id": user_id,
        "label": label,
        "status": "running",
        "steps": {},
        "current_account": "",
        "current_step_label": "Starting...",
        "results": [],
        "start_time": datetime.utcnow(),
        "end_time": None,
        "error": None,
        "accounts_total": len(accounts),
        "accounts_done": 0,
        "extra": kwargs,
    }
    with _jobs_lock():
        _jobs_dict()[job_id] = job

    if job_type == "audit":
        thread = threading.Thread(target=_run_audit_job, args=(job_id, accounts), daemon=True)
    else:
        thread = threading.Thread(target=_run_optimization_job, args=(job_id, accounts), daemon=True)
    thread.start()
    return job_id


AUDIT_STEP_LABELS = {
    "connect": "Connecting to AWS",
    "billing": "Step 1: Billing (Cost + Forecast)",
    "payment": "Step 2: Payments (Outstanding)",
    "bills": "Step 3a: Bills (Service x Region)",
    "regions": "Step 3b: Scanning ALL Regions",
    "organization": "Step 4: Organization Verification",
    "quotas": "Step 5: Service Quotas",
}

OPT_STEP_LABELS = {
    "connect": "Connecting to AWS",
    "s3_security": "Checking S3 Bucket Security",
    "iam_security": "Checking IAM Security Posture",
    "regions": "Scanning All Regions",
}


def _run_audit_job(job_id, accounts):
    """Background worker for audit jobs."""
    job = _jobs_dict()[job_id]
    year = job["extra"].get("year")
    month = job["extra"].get("month")
    user_id = job["user_id"]
    results = []

    try:
        for acct_idx, acct in enumerate(accounts):
            job["current_account"] = acct["label"]
            job["accounts_done"] = acct_idx
            job["current_step_label"] = f"Auditing {acct['label']} ({acct_idx+1}/{len(accounts)})"

            final_audit = None
            try:
                for step_name, status, data in run_audit_steps(
                    acct["access_key"], acct["secret_key"], acct["label"],
                    year=year, month=month,
                ):
                    if step_name == "complete":
                        final_audit = data
                        continue
                    sl = AUDIT_STEP_LABELS.get(step_name, step_name)
                    job["steps"][f"{acct['label']}|{sl}"] = status
                    if status == "running":
                        job["current_step_label"] = f"{acct['label']}: {sl}..."
                    elif status == "done":
                        job["current_step_label"] = f"{acct['label']}: {sl} - Done"
                    elif status == "error":
                        job["current_step_label"] = f"{acct['label']}: {sl} - Error"
            except Exception as e:
                final_audit = {
                    "account_label": acct["label"], "account_id": "ERROR", "arn": "",
                    "audit_timestamp": datetime.utcnow().isoformat() + "Z",
                    "billing": None, "payment": None, "bills": None,
                    "regions": None, "organization": None, "quotas": None,
                    "errors": [f"Fatal: {e}"],
                }
            if final_audit:
                results.append(final_audit)

        job["results"] = results
        job["accounts_done"] = len(accounts)
        job["end_time"] = datetime.utcnow()

        # Check if any account had errors
        has_errors = any(a.get("errors") for a in results)
        all_failed = all(a.get("account_id") == "ERROR" for a in results) if results else True
        if all_failed:
            job["status"] = "error"
            job["error"] = "All accounts failed"
            job["current_step_label"] = "All accounts failed"
        elif has_errors:
            job["status"] = "done"
            job["current_step_label"] = f"Completed with errors ({len(results)} account(s))"
        else:
            job["status"] = "done"
            job["current_step_label"] = f"Completed successfully ({len(results)} account(s))"

        # Auto-save report and audit log
        try:
            save_dir = os.path.join(REPORTS_DIR, f"user_{user_id}")
            _, saved_path = generate_report(results, save_dir=save_dir, year=year, month=month)
            account_names = ", ".join(a.get("account_label", "") for a in results)
            t_cost = t_res = t_err = 0
            t_reg = set()
            for a in results:
                b = a.get("billing") or {}
                rd = a.get("regions") or {}
                ar = rd.get("regions", {}) if isinstance(rd, dict) else {}
                try:
                    t_cost += float(b.get("last_month_total_cost", "0").replace("Error:", "0"))
                except (ValueError, AttributeError):
                    pass
                t_res += rd.get("total_resources", 0) if isinstance(rd, dict) else 0
                t_reg.update(ar.keys())
                t_err += len(a.get("errors", []))
            auth.save_audit_log(
                user_id=user_id, accounts_audited=account_names,
                total_accounts=len(results), audit_year=year, audit_month=month,
                total_cost=t_cost, total_resources=t_res,
                active_regions=len(t_reg), errors=t_err, report_path=saved_path,
            )
        except Exception:
            pass

    except Exception as e:
        job["status"] = "error"
        job["error"] = str(e)
        job["current_step_label"] = f"Fatal error: {str(e)[:100]}"
        job["end_time"] = datetime.utcnow()
        job["results"] = results


def _run_optimization_job(job_id, accounts):
    """Background worker for optimization jobs."""
    job = _jobs_dict()[job_id]
    user_id = job["user_id"]
    results = []

    try:
        for acct_idx, acct in enumerate(accounts):
            job["current_account"] = acct["label"]
            job["accounts_done"] = acct_idx
            job["current_step_label"] = f"Scanning {acct['label']} ({acct_idx+1}/{len(accounts)})"

            final_result = None
            try:
                for step_name, status, data in run_optimization_scan(
                    acct["access_key"], acct["secret_key"], acct["label"],
                ):
                    if step_name == "complete":
                        final_result = data
                        continue
                    sl = OPT_STEP_LABELS.get(step_name, step_name)
                    job["steps"][f"{acct['label']}|{sl}"] = status
                    if status == "running":
                        job["current_step_label"] = f"{acct['label']}: {sl}..."
                    elif status == "done":
                        job["current_step_label"] = f"{acct['label']}: {sl} - Done"
                    elif status == "error":
                        job["current_step_label"] = f"{acct['label']}: {sl} - Error"
            except Exception as e:
                final_result = {
                    "account_label": acct["label"], "account_id": "ERROR",
                    "scan_timestamp": datetime.utcnow().isoformat() + "Z",
                    "findings": [],
                    "summary": {"total_findings": 0, "estimated_monthly_waste": 0,
                                "estimated_annual_waste": 0, "by_category": {},
                                "by_severity": {}, "error": str(e)},
                }
            if final_result:
                results.append(final_result)

        job["results"] = results
        job["accounts_done"] = len(accounts)
        job["end_time"] = datetime.utcnow()

        # Check if any account had errors
        all_failed = all(a.get("account_id") == "ERROR" for a in results) if results else True
        has_errors = any(a.get("summary", {}).get("error") for a in results)
        if all_failed:
            job["status"] = "error"
            job["error"] = "All accounts failed"
            job["current_step_label"] = "All accounts failed"
        elif has_errors:
            job["status"] = "done"
            job["current_step_label"] = f"Completed with errors ({len(results)} account(s))"
        else:
            job["status"] = "done"
            job["current_step_label"] = f"Completed successfully ({len(results)} account(s))"

        # Auto-save report and optimization log
        try:
            save_dir = os.path.join(REPORTS_DIR, f"user_{user_id}")
            report_bytes, saved_path = generate_optimization_report(results, save_dir=save_dir)
            account_names = ", ".join(r.get("account_label", "") for r in results)
            total_findings = sum(len(r.get("findings", [])) for r in results)
            now = datetime.utcnow()
            auth.save_audit_log(
                user_id=user_id,
                accounts_audited=f"[Optimization] {account_names}",
                total_accounts=len(results),
                audit_year=now.year, audit_month=now.month,
                total_cost=0, total_resources=total_findings,
                active_regions=0, errors=0, report_path=saved_path,
            )
        except Exception:
            pass

    except Exception as e:
        job["status"] = "error"
        job["error"] = str(e)
        job["current_step_label"] = f"Fatal error: {str(e)[:100]}"
        job["end_time"] = datetime.utcnow()
        job["results"] = results


def _get_user_jobs(user_id):
    """Get all jobs for a user, sorted by start_time desc."""
    with _jobs_lock():
        jobs = [j for j in _jobs_dict().values() if j["user_id"] == user_id]
    return sorted(jobs, key=lambda x: x["start_time"], reverse=True)


def _dismiss_job(job_id):
    """Remove a completed job from the list."""
    with _jobs_lock():
        _jobs_dict().pop(job_id, None)


def _user_reports_dir(user_id=None):
    """Get per-user report directory."""
    if user_id is None:
        user_id = st.session_state.get("user", {}).get("id")
    if user_id:
        return os.path.join(REPORTS_DIR, f"user_{user_id}")
    return REPORTS_DIR


def _get_visible_report_dirs():
    """Get report directories visible to current user (own + company members)."""
    user = st.session_state.get("user")
    if not user:
        return []
    dirs = [_user_reports_dir(user["id"])]
    company = auth.get_user_company(user["id"])
    if company:
        member_ids = auth.get_company_member_ids(company["id"])
        for mid in member_ids:
            if mid != user["id"]:
                d = _user_reports_dir(mid)
                if d not in dirs:
                    dirs.append(d)
    return dirs

# ═════════════════════════════════════════════════════════════════════════
# PAGE CONFIG
# ═════════════════════════════════════════════════════════════════════════
st.set_page_config(
    page_title="AWS Internal Audit",
    page_icon="https://upload.wikimedia.org/wikipedia/commons/9/93/Amazon_Web_Services_Logo.svg",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ═════════════════════════════════════════════════════════════════════════
# CSS
# ═════════════════════════════════════════════════════════════════════════
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap');

    /* ── Global ── */
    .block-container { padding-top: 1rem; max-width: 1200px; }
    #MainMenu, footer, header { visibility: hidden; }

    /* ── Auth Pages ── */
    .auth-logo { text-align: center; margin-bottom: 2rem; }
    .auth-logo .logo-icon {
        width: 72px; height: 72px;
        background: linear-gradient(135deg, #6366f1, #8b5cf6);
        border-radius: 20px; display: inline-flex;
        align-items: center; justify-content: center;
        font-size: 30px; color: white; margin-bottom: 1rem;
        box-shadow: 0 8px 32px rgba(99,102,241,0.35);
    }
    .auth-logo h2 { margin: 0; font-size: 1.5rem; font-weight: 800; }
    .auth-logo p { margin: 0.4rem 0 0 0; color: #94a3b8; font-size: 0.9rem; }

    /* ── Header Banner ── */
    .main-header {
        background: linear-gradient(135deg, #1e1b4b 0%, #312e81 40%, #4c1d95 100%);
        color: white; padding: 1.5rem 2rem; border-radius: 16px;
        margin-bottom: 1.5rem; position: relative; overflow: hidden;
        display: flex; justify-content: space-between; align-items: center;
    }
    .main-header h1 { margin: 0; font-size: 1.5rem; font-weight: 800; position: relative; z-index: 1; }
    .main-header p { margin: 0.3rem 0 0 0; font-size: 0.85rem; opacity: 0.7; position: relative; z-index: 1; }
    .user-badge { display: flex; align-items: center; gap: 0.8rem; z-index: 1; position: relative; }
    .user-avatar {
        width: 40px; height: 40px; border-radius: 12px;
        display: flex; align-items: center; justify-content: center;
        font-size: 0.95rem; font-weight: 700; color: white;
        border: 2px solid rgba(255,255,255,0.25);
    }
    .user-info { text-align: right; }
    .user-info .uname { font-weight: 600; font-size: 0.9rem; }
    .user-info .urole { font-size: 0.7rem; opacity: 0.6; text-transform: uppercase; letter-spacing: 1px; }

    /* ── Status Cards ── */
    .status-card {
        background: #131320; border: 1px solid #1e1e35;
        border-radius: 14px; padding: 1.2rem 1.3rem;
        margin-bottom: 0.8rem; border-left: 4px solid #6366f1;
    }
    .status-card.success { border-left-color: #10b981; }
    .status-card.warning { border-left-color: #f59e0b; }
    .status-card.error { border-left-color: #ef4444; }
    .status-card .card-label {
        font-size: 0.7rem; color: #94a3b8; text-transform: uppercase;
        font-weight: 700; letter-spacing: 1px; margin-bottom: 0.4rem;
    }
    .status-card .card-value { font-size: 1.5rem; font-weight: 800; color: #e2e8f0; }
    .status-card .card-sub { font-size: 0.78rem; color: #64748b; margin-top: 0.3rem; }

    /* ── Glow Cards ── */
    .glow-card {
        background: #131320; border: 1px solid #1e1e35;
        border-radius: 16px; padding: 1.5rem; text-align: center;
    }
    .glow-card .glow-icon { font-size: 2rem; margin-bottom: 0.6rem; }
    .glow-card .glow-value { font-size: 1.6rem; font-weight: 800; color: #e2e8f0; }
    .glow-card .glow-label {
        font-size: 0.72rem; color: #94a3b8; text-transform: uppercase;
        font-weight: 600; letter-spacing: 1px; margin-top: 0.4rem;
    }

    /* ── Account Badge ── */
    .acct-badge {
        background: #131320; border: 1px solid #1e1e35;
        border-radius: 10px; padding: 0.7rem 0.9rem; margin-bottom: 0.5rem;
    }
    .acct-badge .acct-name { font-weight: 600; color: #a78bfa; font-size: 0.9rem; }
    .acct-badge .acct-key { font-size: 0.75rem; color: #64748b; font-family: monospace; }

    /* ── Pills ── */
    .pill {
        display: inline-block; padding: 0.22rem 0.7rem; border-radius: 20px;
        font-size: 0.72rem; font-weight: 700; margin: 0.15rem 0.1rem;
    }
    .pill-green { background: rgba(16,185,129,0.15); color: #34d399; }
    .pill-red { background: rgba(239,68,68,0.15); color: #f87171; }
    .pill-blue { background: rgba(99,102,241,0.15); color: #818cf8; }
    .pill-orange { background: rgba(245,158,11,0.15); color: #fbbf24; }
    .pill-purple { background: rgba(139,92,246,0.15); color: #a78bfa; }

    /* ── Steps ── */
    .step-row { display: flex; align-items: center; gap: 0.6rem; padding: 0.4rem 0; }
    .step-icon { font-size: 1rem; width: 1.3rem; text-align: center; }
    .step-done .step-text { color: #34d399; font-weight: 500; }
    .step-error .step-text { color: #f87171; font-weight: 500; }
    .step-running .step-text { color: #818cf8; font-weight: 500; }

    /* ── Divider ── */
    .divider { height: 1px; margin: 1.5rem 0; background: linear-gradient(90deg, transparent, #2e2e50, transparent); }

    /* ── Timeline ── */
    .timeline-item {
        position: relative; padding-left: 28px; padding-bottom: 1.2rem;
        border-left: 2px solid #2e2e50; margin-left: 8px;
    }
    .timeline-item::before {
        content: ''; position: absolute; left: -6px; top: 4px;
        width: 10px; height: 10px; border-radius: 50%; background: #6366f1;
    }
    .timeline-item .tl-time { font-size: 0.72rem; color: #64748b; font-weight: 600; }
    .timeline-item .tl-text { font-size: 0.88rem; color: #cbd5e1; margin-top: 4px; }

    /* ── Quick Stats Bar ── */
    .quick-stats {
        display: flex; gap: 2rem; padding: 1rem 1.5rem;
        background: #131320; border: 1px solid #1e1e35;
        border-radius: 14px; margin-bottom: 1.5rem;
    }
    .quick-stat { display: flex; align-items: center; gap: 0.5rem; }
    .quick-stat .qs-dot { width: 8px; height: 8px; border-radius: 50%; }
    .quick-stat .qs-label { font-size: 0.75rem; color: #94a3b8; }
    .quick-stat .qs-value { font-size: 0.88rem; font-weight: 700; color: #e2e8f0; }

    /* ── Sidebar ── */
    section[data-testid="stSidebar"] { background: #0d0d18 !important; }
    /* Prevent sidebar from being collapsed */
    button[data-testid="stSidebarCollapseButton"],
    button[data-testid="baseButton-headerNoPadding"],
    [data-testid="stSidebar"] button[kind="headerNoPadding"],
    [data-testid="collapsedControl"],
    section[data-testid="stSidebar"] > div > button:first-child,
    .stSidebarCollapse,
    div[data-testid="stSidebarCollapsedControl"] { display: none !important; }
    section[data-testid="stSidebar"] { min-width: 280px !important; max-width: 280px !important; transform: none !important; }
    /* Force sidebar visible even after collapse */
    section[data-testid="stSidebar"][aria-expanded="false"] {
        display: block !important; width: 280px !important;
        min-width: 280px !important; transform: none !important;
        margin-left: 0 !important; visibility: visible !important;
    }

    /* ── Sidebar Job Items ── */
    .job-item {
        background: #131320; border: 1px solid #1e1e35;
        border-radius: 10px; padding: 0.6rem 0.8rem; margin-bottom: 0.5rem;
        cursor: pointer; transition: border-color 0.2s;
    }
    .job-item:hover { border-color: #6366f1; }
    .job-item.job-running { border-left: 3px solid #818cf8; }
    .job-item.job-done { border-left: 3px solid #10b981; }
    .job-item.job-error { border-left: 3px solid #ef4444; }
    .job-item .job-title { font-size: 0.8rem; font-weight: 600; color: #e2e8f0; }
    .job-item .job-status { font-size: 0.7rem; color: #94a3b8; margin-top: 2px; }
    .job-item .job-step { font-size: 0.68rem; color: #64748b; margin-top: 2px;
        white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }

    @keyframes pulse-dot { 0%, 100% { opacity: 1; } 50% { opacity: 0.4; } }
    .pulse-dot {
        display: inline-block; width: 7px; height: 7px; border-radius: 50%;
        background: #818cf8; margin-right: 5px;
        animation: pulse-dot 1.5s ease-in-out infinite;
    }
</style>
""", unsafe_allow_html=True)


# ═════════════════════════════════════════════════════════════════════════
# SESSION STATE
# ═════════════════════════════════════════════════════════════════════════
defaults = {
    "authenticated": False,
    "user": None,
    "auth_page": "login",
    "accounts": [],
    "audit_results": [],
    "nav_page": "dashboard",
    "forgot_step": 1,
    "forgot_email": "",
    "forgot_method": "security",
    "optimization_results": [],
    "pending_2fa_user": None,
    "pending_2fa_msg": "",
    "setup_2fa_user": None,
    "viewing_job_id": None,
    "balloons_shown_jobs": set(),
}
for k, v in defaults.items():
    if k not in st.session_state:
        st.session_state[k] = v


# ═════════════════════════════════════════════════════════════════════════
# AUTH PAGES
# ═════════════════════════════════════════════════════════════════════════

def _auth_header(subtitle=""):
    st.markdown(
        '<div class="auth-logo">'
        '<div class="logo-icon">&#9741;</div>'
        '<h2>AWS Internal Audit</h2>'
        f'<p>{subtitle}</p>'
        '</div>',
        unsafe_allow_html=True,
    )


# ── LOGIN ─────────────────────────────────────────────────────────────

def login_page():
    col1, col2, col3 = st.columns([1, 1.2, 1])
    with col2:
        # ── 2FA Verification Step ──
        if st.session_state.pending_2fa_user is not None:
            _auth_header("Two-Factor Authentication")
            st.info("Enter the 6-digit code from your authenticator app.")

            with st.form("totp_form"):
                totp_code = st.text_input("Authentication Code", placeholder="Enter 6-digit code",
                                          max_chars=6)
                verify_btn = st.form_submit_button("Verify", type="primary",
                                                    width='stretch')
                if verify_btn:
                    if not totp_code:
                        st.error("Please enter the authentication code.")
                    else:
                        user = st.session_state.pending_2fa_user
                        if auth.verify_totp(user["id"], totp_code):
                            st.session_state.authenticated = True
                            st.session_state.user = user
                            st.session_state.pending_2fa_user = None
                            st.success("Login successful!")
                            st.rerun()
                        else:
                            st.error("Invalid authentication code. Please try again.")

            if st.button("Back to Login", width='stretch'):
                st.session_state.pending_2fa_user = None
                st.rerun()
            return

        # ── Normal Login ──
        _auth_header("Sign in to your account")

        username = st.text_input("Username or Email", placeholder="Enter your username",
                                 key="login_username")
        password = st.text_input("Password", type="password", placeholder="Enter your password",
                                 key="login_password")
        login_btn = st.button("Sign In", type="primary", width='stretch')

        if login_btn:
            if not username or not password:
                st.error("Please fill in all fields.")
            else:
                ok, user, msg = auth.login(username, password)
                if ok:
                    # Check if 2FA is enabled
                    totp_enabled, _ = auth.is_totp_enabled_by_username(username)
                    if totp_enabled:
                        st.session_state.pending_2fa_user = user
                        st.session_state.pending_2fa_msg = msg
                        st.rerun()
                    else:
                        # 2FA not set up — force setup before allowing login
                        st.session_state.setup_2fa_user = user
                        st.rerun()
                else:
                    st.error(msg)

        # Links
        link_col1, link_col2 = st.columns(2)
        with link_col1:
            if st.button("Forgot Password?", width='stretch'):
                st.session_state.auth_page = "forgot"
                st.session_state.forgot_step = 1
                st.rerun()
        with link_col2:
            if st.button("Create Account", width='stretch'):
                st.session_state.auth_page = "register"
                st.rerun()

        st.markdown(
            '<p style="text-align:center;color:#999;font-size:0.75rem;margin-top:1.5rem;">'
            'Open Source AWS Audit Tool v2.0'
            '</p>',
            unsafe_allow_html=True,
        )


# ── REGISTER ──────────────────────────────────────────────────────────

def register_page():
    col1, col2, col3 = st.columns([1, 1.5, 1])
    with col2:
        _auth_header("Create a new account")

        full_name = st.text_input("Full Name", placeholder="John Doe", key="reg_fullname")
        r_col1, r_col2 = st.columns(2)
        with r_col1:
            username = st.text_input("Username", placeholder="johndoe",
                                     help="3-30 chars: letters, numbers, _ . -", key="reg_username")
        with r_col2:
            email = st.text_input("Email", placeholder="john@company.com", key="reg_email")

        password = st.text_input("Password", type="password",
                                 placeholder="Min 8 chars, upper, lower, digit, special",
                                 key="reg_password")
        confirm_password = st.text_input("Confirm Password", type="password",
                                         placeholder="Re-enter your password",
                                         key="reg_confirm_password")

        st.markdown("---")
        st.markdown("**Security Question** (for password recovery)")
        security_q = st.selectbox("Choose a question", SECURITY_QUESTIONS, key="reg_security_q")
        security_a = st.text_input("Your Answer", placeholder="Answer is case-insensitive",
                                   help="This will be used to verify your identity during password reset",
                                   key="reg_security_a")

        register_btn = st.button("Create Account", type="primary", width='stretch')

        if register_btn:
            if not all([full_name, username, email, password, confirm_password, security_a]):
                st.error("All fields are required.")
            elif password != confirm_password:
                st.error("Passwords do not match.")
            else:
                ok, msg = auth.register(
                    username, email, password, full_name, security_q, security_a
                )
                if ok:
                    # Auto-login and go to 2FA setup
                    login_ok, new_user, _ = auth.login(username, password)
                    if login_ok:
                        st.session_state.setup_2fa_user = new_user
                        st.success(msg + " Setting up 2FA...")
                        st.rerun()
                    else:
                        st.success(msg + " Please login to set up 2FA.")
                        st.session_state.auth_page = "login"
                        st.rerun()
                else:
                    st.error(msg)

        # Password strength preview
        st.markdown("**Password Requirements:**")
        st.markdown(
            '<span class="pill pill-blue">8+ chars</span>'
            '<span class="pill pill-blue">Uppercase</span>'
            '<span class="pill pill-blue">Lowercase</span>'
            '<span class="pill pill-blue">Digit</span>'
            '<span class="pill pill-blue">Special char</span>',
            unsafe_allow_html=True,
        )

        st.markdown('<div class="divider"></div>', unsafe_allow_html=True)
        if st.button("Back to Login", width='stretch'):
            st.session_state.auth_page = "login"
            st.rerun()


# ── MANDATORY 2FA SETUP ──────────────────────────────────────────────

def setup_2fa_page():
    """Force new users to set up 2FA before they can use the app."""
    user = st.session_state.setup_2fa_user
    if not user:
        st.session_state.auth_page = "login"
        st.rerun()
        return

    col1, col2, col3 = st.columns([1, 1.5, 1])
    with col2:
        _auth_header("Set Up Two-Factor Authentication")
        st.warning("2FA is mandatory. You must set it up before you can access the dashboard.")

        # Generate TOTP secret if not already done
        if "setup_totp_secret" not in st.session_state:
            secret = auth.generate_totp_secret(user["id"])
            st.session_state.setup_totp_secret = secret
        else:
            secret = st.session_state.setup_totp_secret

        if not secret:
            st.error("Failed to generate 2FA secret. Please try again.")
            if st.button("Back to Login", width='stretch'):
                st.session_state.setup_2fa_user = None
                st.session_state.auth_page = "login"
                st.rerun()
            return

        # Show QR code
        totp_uri, totp_secret_display = auth.get_totp_uri(user["id"])
        if totp_uri:
            st.markdown("**Step 1:** Scan this QR code with your authenticator app (Google Authenticator, Authy, etc.)")
            qr = qrcode.QRCode(version=1, error_correction=qrcode.constants.ERROR_CORRECT_L,
                                box_size=10, border=4)
            qr.add_data(totp_uri)
            qr.make(fit=True)
            img = qr.make_image(fill_color="black", back_color="white")
            buf = io.BytesIO()
            img.save(buf, format="PNG")
            buf.seek(0)
            st.image(buf.getvalue(), width=250)

            with st.expander("Can't scan? Enter this key manually"):
                st.code(totp_secret_display, language=None)

            st.markdown("**Step 2:** Enter the 6-digit code from your app to verify")

            with st.form("setup_2fa_form"):
                totp_code = st.text_input("Authentication Code", placeholder="Enter 6-digit code",
                                          max_chars=6)
                verify_btn = st.form_submit_button("Enable 2FA & Login", type="primary",
                                                    width='stretch')
                if verify_btn:
                    if not totp_code or len(totp_code) != 6:
                        st.error("Please enter a valid 6-digit code.")
                    else:
                        if auth.enable_totp(user["id"], totp_code):
                            st.session_state.authenticated = True
                            st.session_state.user = user
                            st.session_state.setup_2fa_user = None
                            if "setup_totp_secret" in st.session_state:
                                del st.session_state["setup_totp_secret"]
                            st.success("2FA enabled! Welcome!")
                            st.rerun()
                        else:
                            st.error("Invalid code. Please check your authenticator app and try again.")

        st.markdown('<div class="divider"></div>', unsafe_allow_html=True)
        if st.button("Cancel & Back to Login", width='stretch'):
            st.session_state.setup_2fa_user = None
            if "setup_totp_secret" in st.session_state:
                del st.session_state["setup_totp_secret"]
            st.session_state.auth_page = "login"
            st.rerun()


# ── FORGOT PASSWORD ───────────────────────────────────────────────────

def forgot_password_page():
    col1, col2, col3 = st.columns([1, 1.3, 1])
    with col2:
        _auth_header("Reset your password")

        step = st.session_state.forgot_step

        # Step 1: Enter email & choose method
        if step == 1:
            st.markdown("**Step 1:** Enter your registered email")
            with st.form("forgot_step1"):
                email = st.text_input("Email Address", placeholder="your@email.com")
                method = st.radio(
                    "Reset Method",
                    ["Security Question", "Email OTP"],
                    horizontal=True,
                    help="Security Question is always available. Email OTP requires SMTP configuration.",
                )
                next_btn = st.form_submit_button("Continue", type="primary",
                                                 width='stretch')
                if next_btn:
                    if not email:
                        st.error("Please enter your email.")
                    else:
                        if method == "Security Question":
                            q = auth.get_security_question(email)
                            if q:
                                st.session_state.forgot_email = email
                                st.session_state.forgot_method = "security"
                                st.session_state.forgot_step = 2
                                st.rerun()
                            else:
                                st.error("Email not found in our records.")
                        else:
                            ok, msg = auth.send_reset_email(email)
                            if ok:
                                st.session_state.forgot_email = email
                                st.session_state.forgot_method = "otp"
                                st.session_state.forgot_step = 2
                                st.success(msg)
                                st.rerun()
                            else:
                                st.error(msg)

        # Step 2: Verify identity
        elif step == 2:
            email = st.session_state.forgot_email

            if st.session_state.forgot_method == "security":
                q = auth.get_security_question(email)
                st.markdown(f"**Step 2:** Answer your security question")
                st.info(f"**Question:** {q}")
                with st.form("forgot_step2_sq"):
                    answer = st.text_input("Your Answer", placeholder="Type your answer")
                    verify_btn = st.form_submit_button("Verify", type="primary",
                                                       width='stretch')
                    if verify_btn:
                        if auth.verify_security_answer(email, answer):
                            st.session_state.forgot_step = 3
                            st.rerun()
                        else:
                            st.error("Incorrect answer. Please try again.")
            else:
                st.markdown("**Step 2:** Enter the OTP sent to your email")
                with st.form("forgot_step2_otp"):
                    otp = st.text_input("6-Digit OTP", placeholder="123456", max_chars=6)
                    verify_btn = st.form_submit_button("Verify OTP", type="primary",
                                                       width='stretch')
                    if verify_btn:
                        ok, msg = auth.verify_otp(email, otp)
                        if ok:
                            st.session_state.forgot_step = 3
                            st.rerun()
                        else:
                            st.error(msg)

                if st.button("Resend OTP"):
                    ok, msg = auth.send_reset_email(email)
                    if ok:
                        st.success(msg)
                    else:
                        st.error(msg)

        # Step 3: Set new password
        elif step == 3:
            st.markdown("**Step 3:** Set your new password")
            with st.form("forgot_step3"):
                new_pw = st.text_input("New Password", type="password",
                                       placeholder="Enter new password")
                confirm_pw = st.text_input("Confirm Password", type="password",
                                           placeholder="Re-enter password")
                reset_btn = st.form_submit_button("Reset Password", type="primary",
                                                   width='stretch')
                if reset_btn:
                    if new_pw != confirm_pw:
                        st.error("Passwords do not match.")
                    else:
                        ok, msg = auth.reset_password(
                            st.session_state.forgot_email, new_pw
                        )
                        if ok:
                            st.success(msg)
                            st.session_state.auth_page = "login"
                            st.session_state.forgot_step = 1
                            st.rerun()
                        else:
                            st.error(msg)

        # Progress indicator
        st.markdown('<div class="divider"></div>', unsafe_allow_html=True)
        p1 = "pill-green" if step >= 1 else "pill-blue"
        p2 = "pill-green" if step >= 2 else "pill-blue"
        p3 = "pill-green" if step >= 3 else "pill-blue"
        st.markdown(
            f'<span class="pill {p1}">1. Email</span> '
            f'<span class="pill {p2}">2. Verify</span> '
            f'<span class="pill {p3}">3. New Password</span>',
            unsafe_allow_html=True,
        )

        st.markdown("")
        if st.button("Back to Login", width='stretch'):
            st.session_state.auth_page = "login"
            st.session_state.forgot_step = 1
            st.rerun()


# ═════════════════════════════════════════════════════════════════════════
# MAIN DASHBOARD (protected)
# ═════════════════════════════════════════════════════════════════════════

def dashboard_page():
    user = st.session_state.user
    avatar_color = user.get("avatar_color", "#2F5496")
    initials = "".join([w[0].upper() for w in (user.get("full_name") or user["username"]).split()[:2]])

    # ── Sidebar ──────────────────────────────────────────────────────
    with st.sidebar:
        # User info
        company = auth.get_user_company(user["id"])
        company_name = company["name"] if company else ""
        st.markdown(
            f'<div style="text-align:center;padding:1.2rem 0;">'
            f'<div style="width:60px;height:60px;border-radius:16px;'
            f'background:linear-gradient(135deg, {avatar_color}, {avatar_color}cc);'
            f'display:inline-flex;align-items:center;'
            f'justify-content:center;font-size:1.3rem;font-weight:800;color:white;'
            f'margin-bottom:0.6rem;box-shadow:0 4px 15px {avatar_color}66;">{initials}</div>'
            f'<div style="font-weight:700;font-size:1rem;color:#e2e8f0;">'
            f'{user.get("full_name") or user["username"]}</div>'
            f'<div style="font-size:0.7rem;color:#a78bfa;text-transform:uppercase;'
            f'letter-spacing:1.5px;font-weight:600;margin-top:2px;">'
            f'{user["role"]}</div>'
            f'{"<div style=font-size:0.72rem;color:#64748b;margin-top:4px;>" + company_name + "</div>" if company_name else ""}'
            f'</div>',
            unsafe_allow_html=True,
        )

        st.markdown('<div class="divider"></div>', unsafe_allow_html=True)

        # Navigation
        st.markdown("### Navigation")
        nav_items = [
            ("Dashboard", "dashboard"),
            ("AWS Accounts", "accounts"),
            ("Optimization", "optimization"),
            ("Audit History", "history"),
            ("Company", "company"),
            ("Profile", "profile"),
        ]
        if user["role"] == "admin":
            nav_items.append(("Admin Panel", "admin"))

        for label, page_key in nav_items:
            is_active = st.session_state.nav_page == page_key
            if st.button(label, width='stretch',
                         type="primary" if is_active else "secondary"):
                st.session_state.nav_page = page_key
                st.rerun()

        st.markdown('<div class="divider"></div>', unsafe_allow_html=True)

        if st.button("Logout", width='stretch'):
            for key in list(st.session_state.keys()):
                del st.session_state[key]
            st.rerun()

        # ── Running / Recent Jobs ─────────────────────────────────────
        user_jobs = _get_user_jobs(user["id"])
        if user_jobs:
            st.markdown('<div class="divider"></div>', unsafe_allow_html=True)
            running_jobs = [j for j in user_jobs if j["status"] == "running"]
            failed_jobs = [j for j in user_jobs if j["status"] == "error"]
            done_jobs = [j for j in user_jobs if j["status"] == "done"]

            if running_jobs:
                st.markdown(f"### Running Jobs ({len(running_jobs)})")
                for j in running_jobs:
                    type_icon = "&#9741;" if j["type"] == "audit" else "&#9889;"
                    st.markdown(
                        f'<div class="job-item job-running">'
                        f'<div class="job-title">{type_icon} {j["label"]}</div>'
                        f'<div class="job-status"><span class="pulse-dot"></span>'
                        f'{j["accounts_done"]}/{j["accounts_total"]} accounts</div>'
                        f'<div class="job-step">{j["current_step_label"]}</div>'
                        f'</div>',
                        unsafe_allow_html=True,
                    )
                    if st.button("View Progress", key=f"view_{j['id']}", width='stretch'):
                        st.session_state.viewing_job_id = j["id"]
                        st.session_state.nav_page = "job_view"
                        st.rerun()

            if failed_jobs:
                st.markdown(f"### Failed Jobs ({len(failed_jobs)})")
                for j in failed_jobs:
                    type_icon = "&#9741;" if j["type"] == "audit" else "&#9889;"
                    err_msg = j.get("error", "Unknown error")[:50]
                    st.markdown(
                        f'<div class="job-item job-error">'
                        f'<div class="job-title">{type_icon} {j["label"]}</div>'
                        f'<div class="job-status">&#10008; Failed</div>'
                        f'<div class="job-step">{err_msg}</div>'
                        f'</div>',
                        unsafe_allow_html=True,
                    )
                    c1, c2 = st.columns(2)
                    with c1:
                        if st.button("View", key=f"viewfail_{j['id']}", width='stretch'):
                            st.session_state.viewing_job_id = j["id"]
                            st.session_state.nav_page = "job_view"
                            st.rerun()
                    with c2:
                        if st.button("Dismiss", key=f"dismissfail_{j['id']}", width='stretch'):
                            _dismiss_job(j["id"])
                            st.rerun()

            if done_jobs:
                st.markdown(f"### Completed Jobs ({len(done_jobs)})")
                for j in done_jobs[:5]:
                    type_icon = "&#9741;" if j["type"] == "audit" else "&#9889;"
                    elapsed = ""
                    if j["end_time"] and j["start_time"]:
                        secs = int((j["end_time"] - j["start_time"]).total_seconds())
                        elapsed = f" ({secs}s)"
                    st.markdown(
                        f'<div class="job-item job-done">'
                        f'<div class="job-title">{type_icon} {j["label"]}</div>'
                        f'<div class="job-status">&#10004; Done{elapsed} &mdash; '
                        f'{j["accounts_total"]} account(s)</div>'
                        f'</div>',
                        unsafe_allow_html=True,
                    )
                    c1, c2 = st.columns(2)
                    with c1:
                        if st.button("Load", key=f"load_{j['id']}", width='stretch'):
                            if j["type"] == "audit":
                                st.session_state.audit_results = j["results"]
                                st.session_state.nav_page = "dashboard"
                            else:
                                st.session_state.optimization_results = j["results"]
                                st.session_state.nav_page = "optimization"
                            st.balloons()
                            st.rerun()
                    with c2:
                        if st.button("Dismiss", key=f"dismiss_{j['id']}", width='stretch'):
                            _dismiss_job(j["id"])
                            st.rerun()

    # ── Route to page ────────────────────────────────────────────────
    page = st.session_state.nav_page
    if page == "dashboard":
        _render_dashboard()
    elif page == "accounts":
        _render_accounts_page()
    elif page == "optimization":
        _render_optimization()
    elif page == "profile":
        _render_profile()
    elif page == "history":
        _render_history()
    elif page == "company":
        _render_company()
    elif page == "job_view":
        _render_job_view()
    elif page == "admin" and user["role"] == "admin":
        _render_admin()
    else:
        _render_dashboard()


def _back_to_dashboard(key):
    """Render a back to dashboard button."""
    if st.button("← Back to Dashboard", key=key):
        st.session_state.nav_page = "dashboard"
        st.rerun()


# ═════════════════════════════════════════════════════════════════════════
# JOB VIEW PAGE
# ═════════════════════════════════════════════════════════════════════════

def _render_job_view():
    job_id = st.session_state.get("viewing_job_id")
    job = _jobs_dict().get(job_id) if job_id else None

    if not job:
        st.warning("Job not found or has been dismissed.")
        if st.button("Back to Dashboard"):
            st.session_state.nav_page = "dashboard"
            st.rerun()
        return

    _back_to_dashboard("back_job")

    type_label = "Audit" if job["type"] == "audit" else "Optimization Scan"
    status_pill = {
        "running": '<span class="pill pill-blue">Running</span>',
        "done": '<span class="pill pill-green">Completed</span>',
        "error": '<span class="pill pill-red">Error</span>',
    }.get(job["status"], "")

    st.markdown(
        f'<div class="main-header">'
        f'<div><h1>{type_label}: {job["label"]}</h1>'
        f'<p>Started: {job["start_time"].strftime("%Y-%m-%d %H:%M:%S UTC")} {status_pill}</p></div>'
        f'</div>',
        unsafe_allow_html=True,
    )

    # Progress
    if job["accounts_total"] > 0:
        progress = job["accounts_done"] / job["accounts_total"]
        if job["status"] in ("done", "error"):
            progress = 1.0 if job["status"] == "done" else progress
        st.progress(progress, text=f'{job["accounts_done"]}/{job["accounts_total"]} accounts processed')

    # Step details
    st.markdown("### Current Status")
    st.markdown(
        f'<div class="status-card">'
        f'<div class="card-label">Current Step</div>'
        f'<div class="card-value" style="font-size:1rem;">{job["current_step_label"]}</div>'
        f'</div>',
        unsafe_allow_html=True,
    )

    # Step breakdown per account
    if job["steps"]:
        st.markdown("### Step Progress")
        current_acct = None
        for key, status in job["steps"].items():
            acct_name, step_name = key.split("|", 1)
            if acct_name != current_acct:
                current_acct = acct_name
                st.markdown(f"**{acct_name}**")
            icon = {"running": "&#9881;", "done": "&#10004;", "error": "&#10008;"}.get(status, "&#9711;")
            css_class = {"running": "step-running", "done": "step-done", "error": "step-error"}.get(status, "")
            st.markdown(
                f'<div class="step-row {css_class}">'
                f'<span class="step-icon">{icon}</span>'
                f'<span class="step-text">{step_name}</span>'
                f'</div>',
                unsafe_allow_html=True,
            )

    st.markdown('<div class="divider"></div>', unsafe_allow_html=True)

    if job["status"] == "done":
        elapsed = ""
        if job["end_time"] and job["start_time"]:
            secs = int((job["end_time"] - job["start_time"]).total_seconds())
            mins, s = divmod(secs, 60)
            elapsed = f"{mins}m {s}s" if mins else f"{s}s"

        st.success(f"Job completed in {elapsed}! {job['accounts_total']} account(s) processed.")

        # Show balloons once when job first completes
        if job_id not in st.session_state.balloons_shown_jobs:
            st.session_state.balloons_shown_jobs.add(job_id)
            st.balloons()

        c1, c2 = st.columns(2)
        with c1:
            if st.button("Load Results & View", type="primary", width='stretch'):
                if job["type"] == "audit":
                    st.session_state.audit_results = job["results"]
                    st.session_state.nav_page = "dashboard"
                else:
                    st.session_state.optimization_results = job["results"]
                    st.session_state.nav_page = "optimization"
                st.balloons()
                st.rerun()
        with c2:
            if st.button("Dismiss Job", width='stretch'):
                _dismiss_job(job_id)
                st.session_state.viewing_job_id = None
                st.session_state.nav_page = "dashboard"
                st.rerun()

    elif job["status"] == "error":
        elapsed = ""
        if job["end_time"] and job["start_time"]:
            secs = int((job["end_time"] - job["start_time"]).total_seconds())
            mins, s = divmod(secs, 60)
            elapsed = f"{mins}m {s}s" if mins else f"{s}s"

        st.error(f"Job failed after {elapsed}. Error: {job.get('error', 'Unknown error')}")

        # Show partial results if any
        if job.get("results"):
            st.warning(f"{len(job['results'])} account(s) returned partial results.")
            c1, c2 = st.columns(2)
            with c1:
                if st.button("Load Partial Results", type="primary", width='stretch'):
                    if job["type"] == "audit":
                        st.session_state.audit_results = job["results"]
                        st.session_state.nav_page = "dashboard"
                    else:
                        st.session_state.optimization_results = job["results"]
                        st.session_state.nav_page = "optimization"
                    st.rerun()
            with c2:
                if st.button("Dismiss Failed Job", width='stretch'):
                    _dismiss_job(job_id)
                    st.session_state.viewing_job_id = None
                    st.session_state.nav_page = "dashboard"
                    st.rerun()
        else:
            if st.button("Dismiss Failed Job", width='stretch'):
                _dismiss_job(job_id)
                st.session_state.viewing_job_id = None
                st.session_state.nav_page = "dashboard"
                st.rerun()

    elif job["status"] == "running":
        st.info("Job is running in the background. You can navigate away — it will keep running.")
        time.sleep(2)
        st.rerun()


# ═════════════════════════════════════════════════════════════════════════
# OPTIMIZATION PAGE
# ═════════════════════════════════════════════════════════════════════════

def _render_optimization():
    _back_to_dashboard("back_opt")
    st.markdown(
        '<div class="main-header">'
        '<div><h1>Cost & Security Optimization</h1>'
        '<p>One-click scan for waste, security risks, and optimization opportunities</p></div>'
        '</div>',
        unsafe_allow_html=True,
    )

    if not st.session_state.accounts:
        st.info("No AWS accounts added yet. Go to the **AWS Accounts** page to add credentials.")
        return

    # Controls
    ctrl_c1, ctrl_c2 = st.columns([3, 1])
    with ctrl_c1:
        account_labels = [a["label"] for a in st.session_state.accounts]
        select_all = st.checkbox("Select All Accounts", value=True, key="opt_sel_all")
        if select_all:
            selected = account_labels
        else:
            selected = st.multiselect("Choose Accounts", account_labels,
                                      default=account_labels, key="opt_acct_sel")
    with ctrl_c2:
        st.markdown("<br>", unsafe_allow_html=True)
        run_btn = st.button("Run Optimization Scan", type="primary", width='stretch')

    st.markdown(
        '<div style="background:#131320;border-radius:8px;padding:0.8rem 1rem;'
        'margin:0.5rem 0 1rem 0;border:1px solid #1e1e35;font-size:0.85rem;color:#e2e8f0;">'
        '<strong>What this scans:</strong> '
        '<span class="pill pill-blue">Unattached EBS</span> '
        '<span class="pill pill-blue">Unused EIPs</span> '
        '<span class="pill pill-blue">Old Snapshots</span> '
        '<span class="pill pill-blue">Stopped Instances</span> '
        '<span class="pill pill-blue">GP2 to GP3</span> '
        '<span class="pill pill-blue">Prev-Gen Instances</span> '
        '<span class="pill pill-blue">Idle NAT GWs</span> '
        '<span class="pill pill-blue">Empty LBs</span> '
        '<span class="pill pill-blue">Low CPU</span> '
        '<span class="pill pill-red">Public S3</span> '
        '<span class="pill pill-red">IAM Risks</span> '
        '<span class="pill pill-red">No MFA</span> '
        '<span class="pill pill-red">Old Access Keys</span> '
        '</div>',
        unsafe_allow_html=True,
    )

    st.markdown('<div class="divider"></div>', unsafe_allow_html=True)

    # ── RUN SCAN ──────────────────────────────────────────────────────
    if run_btn:
        if not selected:
            st.error("Select at least one account.")
            st.stop()

        # Check for already running optimization jobs
        user_id = st.session_state.user["id"]
        running = [j for j in _get_user_jobs(user_id) if j["status"] == "running" and j["type"] == "optimization"]
        if running:
            st.warning("An optimization scan is already running. Check the sidebar for progress.")
            st.stop()

        accounts_to_scan = [a for a in st.session_state.accounts if a["label"] in selected]
        label = ", ".join(a["label"] for a in accounts_to_scan[:3])
        if len(accounts_to_scan) > 3:
            label += f" +{len(accounts_to_scan)-3} more"

        job_id = _start_job("optimization", user_id, label, accounts_to_scan)
        st.session_state.viewing_job_id = job_id
        st.session_state.nav_page = "job_view"
        st.rerun()

    # ── DISPLAY RESULTS ───────────────────────────────────────────────
    if not st.session_state.optimization_results:
        st.markdown("### Ready to Scan")
        st.markdown("Click **Run Optimization Scan** to identify cost savings and security issues.")
        return

    results = st.session_state.optimization_results

    # Summary Cards
    total_findings = sum(r.get("summary", {}).get("total_findings", 0) for r in results)
    total_monthly = sum(r.get("summary", {}).get("estimated_monthly_waste", 0) for r in results)
    total_annual = total_monthly * 12
    all_severities = {}
    all_categories = {}
    for r in results:
        for sev, cnt in r.get("summary", {}).get("by_severity", {}).items():
            all_severities[sev] = all_severities.get(sev, 0) + cnt
        for cat, cnt in r.get("summary", {}).get("by_category", {}).items():
            all_categories[cat] = all_categories.get(cat, 0) + cnt

    sc1, sc2, sc3, sc4, sc5 = st.columns(5)
    with sc1:
        st.markdown(
            f'<div class="status-card"><div class="card-label">Total Findings</div>'
            f'<div class="card-value">{total_findings}</div></div>',
            unsafe_allow_html=True)
    with sc2:
        cls = "error" if total_monthly > 50 else "warning" if total_monthly > 10 else "success"
        st.markdown(
            f'<div class="status-card {cls}"><div class="card-label">Est. Monthly Waste</div>'
            f'<div class="card-value">${total_monthly:,.2f}</div></div>',
            unsafe_allow_html=True)
    with sc3:
        st.markdown(
            f'<div class="status-card"><div class="card-label">Est. Annual Waste</div>'
            f'<div class="card-value">${total_annual:,.2f}</div></div>',
            unsafe_allow_html=True)
    with sc4:
        crit = all_severities.get("Critical", 0)
        cls = "error" if crit > 0 else "success"
        st.markdown(
            f'<div class="status-card {cls}"><div class="card-label">Critical Issues</div>'
            f'<div class="card-value">{crit}</div></div>',
            unsafe_allow_html=True)
    with sc5:
        sec = all_categories.get("Security", 0)
        cls = "error" if sec > 0 else "success"
        st.markdown(
            f'<div class="status-card {cls}"><div class="card-label">Security Issues</div>'
            f'<div class="card-value">{sec}</div></div>',
            unsafe_allow_html=True)

    st.markdown('<div class="divider"></div>', unsafe_allow_html=True)

    # Download Report
    st.markdown("### Download Optimization Report")
    dl1, dl2 = st.columns([2, 3])
    with dl1:
        report_bytes, saved_path = generate_optimization_report(
            results, save_dir=_user_reports_dir(),
        )
        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        fname = f"AWS_Optimization_{ts}.xlsx"
        st.download_button(
            "Download Optimization Report (Excel)", data=report_bytes, file_name=fname,
            mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            type="primary", width='stretch',
        )
    with dl2:
        if saved_path:
            st.success(f"Auto-saved: `{saved_path}`")
        st.caption("Sheets: Executive Summary, All Findings, Cost Savings, Security Findings")

    st.markdown('<div class="divider"></div>', unsafe_allow_html=True)

    # Category breakdown
    st.markdown("### Findings by Category")
    cat_cols = st.columns(len(all_categories) if all_categories else 1)
    for i, (cat, cnt) in enumerate(sorted(all_categories.items(), key=lambda x: -x[1])):
        color_map = {"Cost": "pill-orange", "Security": "pill-red", "Optimization": "pill-blue"}
        cls = color_map.get(cat, "pill-blue")
        with cat_cols[i % len(cat_cols)]:
            st.markdown(
                f'<div class="status-card"><div class="card-label">{cat}</div>'
                f'<div class="card-value">{cnt}</div></div>',
                unsafe_allow_html=True)

    st.markdown('<div class="divider"></div>', unsafe_allow_html=True)

    # Per-Account Detailed Findings
    st.markdown("### Detailed Findings")

    for opt in results:
        label = opt.get("account_label", "Unknown")
        summary = opt.get("summary", {})
        findings = opt.get("findings", [])
        monthly = summary.get("estimated_monthly_waste", 0)
        by_sev = summary.get("by_severity", {})

        sev_pills = ""
        for sev in ["Critical", "High", "Medium", "Low"]:
            cnt = by_sev.get(sev, 0)
            if cnt > 0:
                cls_map = {"Critical": "pill-red", "High": "pill-orange",
                           "Medium": "pill-blue", "Low": "pill-green"}
                sev_pills += f'<span class="pill {cls_map.get(sev, "pill-blue")}">{sev}: {cnt}</span> '

        with st.expander(
            f"{label}  |  {summary.get('total_findings', 0)} findings  |  "
            f"~${monthly:,.2f}/month waste",
            expanded=True,
        ):
            st.markdown(sev_pills, unsafe_allow_html=True)

            if not findings:
                st.success("No issues found. This account looks well-optimized!")
                continue

            # Group by category
            tab_cost, tab_sec, tab_opt = st.tabs(["Cost Waste", "Security", "Optimization"])

            with tab_cost:
                cost_findings = [f for f in findings
                                 if f.get("category") == "Cost"]
                if cost_findings:
                    df_cost = pd.DataFrame([{
                        "Severity": f["severity"],
                        "Resource": f"{f['resource_type']}: {f['resource_id']}",
                        "Region": f["region"],
                        "Issue": f["issue"],
                        "Monthly Waste ($)": f["estimated_monthly_waste"],
                        "Recommendation": f["recommendation"],
                    } for f in sorted(cost_findings,
                                      key=lambda x: -x.get("estimated_monthly_waste", 0))])
                    st.dataframe(df_cost, width='stretch', hide_index=True)
                    waste_total = sum(f.get("estimated_monthly_waste", 0) for f in cost_findings)
                    st.markdown(
                        f'<span class="pill pill-orange">Total Monthly Waste: ${waste_total:,.2f}</span> '
                        f'<span class="pill pill-red">Annual: ${waste_total * 12:,.2f}</span>',
                        unsafe_allow_html=True)
                else:
                    st.success("No cost waste found.")

            with tab_sec:
                sec_findings = [f for f in findings
                                if f.get("category") == "Security"]
                if sec_findings:
                    df_sec = pd.DataFrame([{
                        "Severity": f["severity"],
                        "Resource": f"{f['resource_type']}: {f['resource_id']}",
                        "Region": f["region"],
                        "Issue": f["issue"],
                        "Recommendation": f["recommendation"],
                    } for f in sorted(sec_findings,
                                      key=lambda x: {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}.get(
                                          x.get("severity", "Low"), 99))])
                    st.dataframe(df_sec, width='stretch', hide_index=True)
                else:
                    st.success("No security issues found.")

            with tab_opt:
                opt_findings = [f for f in findings
                                if f.get("category") == "Optimization"]
                if opt_findings:
                    df_opt = pd.DataFrame([{
                        "Severity": f["severity"],
                        "Resource": f"{f['resource_type']}: {f['resource_id']}",
                        "Region": f["region"],
                        "Issue": f["issue"],
                        "Detail": f["detail"],
                        "Recommendation": f["recommendation"],
                    } for f in opt_findings])
                    st.dataframe(df_opt, width='stretch', hide_index=True)
                else:
                    st.success("No optimization suggestions.")


# ═════════════════════════════════════════════════════════════════════════
# PROFILE PAGE
# ═════════════════════════════════════════════════════════════════════════

def _render_profile():
    _back_to_dashboard("back_profile")
    user = st.session_state.user
    fresh_user = auth.get_user(user["id"])
    if fresh_user:
        user = fresh_user
        st.session_state.user = user

    st.markdown(
        '<div class="main-header">'
        '<div><h1>My Profile</h1><p>Manage your account settings</p></div>'
        '</div>',
        unsafe_allow_html=True,
    )

    col1, col2 = st.columns([1, 1])

    with col1:
        st.markdown("### Account Information")
        with st.form("profile_form"):
            full_name = st.text_input("Full Name", value=user.get("full_name", ""))
            email = st.text_input("Email", value=user.get("email", ""))
            st.text_input("Username", value=user["username"], disabled=True)
            st.text_input("Role", value=user["role"].upper(), disabled=True)
            st.text_input("Member Since", value=_fmt_dt(user.get("created_at")), disabled=True)
            st.text_input("Last Login", value=_fmt_dt(user.get("last_login")), disabled=True)
            st.text_input("Total Logins", value=str(user.get("login_count", 0)), disabled=True)

            if st.form_submit_button("Update Profile", type="primary",
                                     width='stretch'):
                ok, msg = auth.update_profile(user["id"], full_name=full_name, email=email)
                if ok:
                    st.success(msg)
                    st.session_state.user = auth.get_user(user["id"])
                    st.rerun()
                else:
                    st.error(msg)

    with col2:
        st.markdown("### Change Password")
        with st.form("change_pw_form"):
            old_pw = st.text_input("Current Password", type="password")
            new_pw = st.text_input("New Password", type="password")
            confirm_pw = st.text_input("Confirm New Password", type="password")

            if st.form_submit_button("Change Password", type="primary",
                                     width='stretch'):
                if not all([old_pw, new_pw, confirm_pw]):
                    st.error("All fields are required.")
                elif new_pw != confirm_pw:
                    st.error("New passwords do not match.")
                else:
                    ok, msg = auth.change_password(user["id"], old_pw, new_pw)
                    if ok:
                        st.success(msg)
                    else:
                        st.error(msg)

        st.markdown("### Password Requirements")
        st.markdown(
            '<span class="pill pill-blue">8+ chars</span> '
            '<span class="pill pill-blue">Uppercase</span> '
            '<span class="pill pill-blue">Lowercase</span> '
            '<span class="pill pill-blue">Digit</span> '
            '<span class="pill pill-blue">Special char</span>',
            unsafe_allow_html=True,
        )

    # ── Two-Factor Authentication Section ──
    st.markdown("---")
    st.markdown("### Two-Factor Authentication (2FA)")

    totp_enabled = auth.is_totp_enabled(user["id"])

    if totp_enabled:
        st.success("2FA is currently **enabled** on your account.")
        if st.button("Disable 2FA", type="secondary"):
            ok, msg = auth.disable_totp(user["id"])
            if ok:
                st.success(msg)
                st.rerun()
            else:
                st.error(msg)
    else:
        st.warning("2FA is currently **disabled**. Enable it for extra security.")

        if st.button("Set Up 2FA", type="primary"):
            auth.generate_totp_secret(user["id"])
            st.session_state["show_2fa_setup"] = True
            st.rerun()

        if st.session_state.get("show_2fa_setup"):
            uri, secret = auth.get_totp_uri(user["id"])
            if uri:
                st.markdown("**Step 1:** Scan this QR code with your authenticator app "
                           "(Google Authenticator, Authy, etc.)")

                # Generate QR code image
                qr = qrcode.make(uri)
                buf = io.BytesIO()
                qr.save(buf, format="PNG")
                buf.seek(0)
                st.image(buf, width=250)

                st.markdown(f"**Manual entry key:** `{secret}`")

                st.markdown("**Step 2:** Enter the 6-digit code from your app to verify:")
                with st.form("enable_2fa_form"):
                    verify_code = st.text_input("Verification Code", placeholder="Enter 6-digit code",
                                                max_chars=6)
                    if st.form_submit_button("Enable 2FA", type="primary",
                                             width='stretch'):
                        if not verify_code:
                            st.error("Please enter the verification code.")
                        else:
                            ok, msg = auth.enable_totp(user["id"], verify_code)
                            if ok:
                                st.success(msg)
                                st.session_state.pop("show_2fa_setup", None)
                                st.rerun()
                            else:
                                st.error(msg)


# ═════════════════════════════════════════════════════════════════════════
# AUDIT HISTORY PAGE
# ═════════════════════════════════════════════════════════════════════════

def _render_history():
    _back_to_dashboard("back_history")
    user = st.session_state.user

    st.markdown(
        '<div class="main-header">'
        '<div><h1>Audit History</h1><p>View past audit runs and download reports</p></div>'
        '</div>',
        unsafe_allow_html=True,
    )

    company = auth.get_user_company(user["id"])
    if user["role"] == "admin":
        show_all = st.checkbox("Show all users' audits", value=True)
        history = auth.get_audit_history(user_id=None if show_all else user["id"])
    elif company:
        show_team = st.checkbox("Show team audits", value=True)
        if show_team:
            history = auth.get_company_audit_history(company["id"])
        else:
            history = auth.get_audit_history(user_id=user["id"])
    else:
        history = auth.get_audit_history(user_id=user["id"])

    if not history:
        st.info("No audit history yet. Run your first audit from the Dashboard.")
        return

    # Summary cards
    c1, c2, c3 = st.columns(3)
    with c1:
        st.markdown(
            f'<div class="status-card">'
            f'<div class="card-label">Total Audits</div>'
            f'<div class="card-value">{len(history)}</div>'
            f'</div>', unsafe_allow_html=True)
    with c2:
        total_accts = sum(h.get("total_accounts", 0) for h in history)
        st.markdown(
            f'<div class="status-card">'
            f'<div class="card-label">Total Accounts Scanned</div>'
            f'<div class="card-value">{total_accts}</div>'
            f'</div>', unsafe_allow_html=True)
    with c3:
        total_cost = sum(h.get("total_cost", 0) for h in history)
        st.markdown(
            f'<div class="status-card">'
            f'<div class="card-label">Cumulative Cost Tracked</div>'
            f'<div class="card-value">${total_cost:,.2f}</div>'
            f'</div>', unsafe_allow_html=True)

    st.markdown('<div class="divider"></div>', unsafe_allow_html=True)

    # Per-entry list with download + delete
    st.markdown("### Audit Records")

    for h in history:
        rpath = h.get("report_path")
        has_file = rpath and os.path.exists(rpath)
        month_names = ["", "Jan", "Feb", "Mar", "Apr", "May", "Jun",
                       "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
        period = ""
        if h.get("audit_year") and h.get("audit_month"):
            m_idx = h["audit_month"] if 1 <= h["audit_month"] <= 12 else 0
            period = f"{month_names[m_idx]} {h['audit_year']}"

        file_status = "pill-green" if has_file else "pill-red"
        file_label = "Report Available" if has_file else "No Report File"

        accts_str = h.get('accounts_audited', 'N/A')
        is_opt = accts_str.startswith("[Optimization]")
        scan_type = "Optimization" if is_opt else "Audit"
        display_accts = accts_str.replace("[Optimization] ", "") if is_opt else accts_str
        cost_label = f"Savings: ${h.get('total_cost', 0):,.2f}" if is_opt else f"${h.get('total_cost', 0):,.2f}"

        with st.expander(
            f"{'⚡' if is_opt else '🔍'} {scan_type}  |  {_fmt_dt(h['created_at'])}  |  "
            f"{h.get('username', 'N/A')}  |  {display_accts}  |  {period}  |  "
            f"{cost_label}",
        ):
            # Info row
            info_c1, info_c2, info_c3, info_c4 = st.columns(4)
            with info_c1:
                st.markdown(f"**Accounts:** {h.get('total_accounts', 0)}")
            with info_c2:
                label2 = "Findings" if is_opt else "Resources"
                st.markdown(f"**{label2}:** {h.get('total_resources', 0)}")
            with info_c3:
                st.markdown(f"**Regions:** {h.get('active_regions', 0)}")
            with info_c4:
                errs = h.get("errors", 0)
                if errs:
                    st.markdown(f"**Errors:** :red[{errs}]")
                else:
                    st.markdown("**Errors:** :green[0]")

            st.markdown(
                f'<span class="pill {file_status}">{file_label}</span>',
                unsafe_allow_html=True,
            )

            # Action buttons
            action_c1, action_c2, action_c3 = st.columns([2, 1, 1])

            with action_c1:
                if has_file:
                    fname = os.path.basename(rpath)
                    with open(rpath, "rb") as f:
                        st.download_button(
                            "Download Report",
                            data=f.read(), file_name=fname,
                            mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                            key=f"hist_dl_{h['id']}",
                            width='stretch',
                        )
                else:
                    st.caption("Report file not found on disk.")

            with action_c2:
                if has_file:
                    if st.button("Delete Report File", key=f"hist_delfile_{h['id']}",
                                 width='stretch'):
                        os.remove(rpath)
                        st.success("Report file deleted.")
                        st.rerun()

            with action_c3:
                if st.button("Delete Record", key=f"hist_delrec_{h['id']}",
                             type="secondary", width='stretch'):
                    auth.delete_audit_log(h["id"])
                    st.success("Audit record deleted.")
                    st.rerun()


# ═════════════════════════════════════════════════════════════════════════
# COMPANY PAGE
# ═════════════════════════════════════════════════════════════════════════

def _render_company():
    _back_to_dashboard("back_company")
    user = st.session_state.user
    company = auth.get_user_company(user["id"])

    st.markdown(
        '<div class="main-header">'
        '<div><h1>Company / Team</h1><p>Manage your organization and team members</p></div>'
        '</div>',
        unsafe_allow_html=True,
    )

    if not company:
        # ── No company yet ──
        st.info("You are not part of any company yet.")

        if user["role"] == "admin":
            st.markdown("### Create a Company")
            st.caption("As an admin, you can create a company and add team members. "
                       "All members will share audit reports and history.")
            with st.form("create_company_form"):
                c_name = st.text_input("Company Name", placeholder="e.g. ZenoCloud Technologies")
                c_desc = st.text_input("Description", placeholder="e.g. Cloud consulting firm")
                if st.form_submit_button("Create Company", type="primary",
                                         width='stretch'):
                    if not c_name:
                        st.error("Company name is required.")
                    else:
                        ok, cid, msg = auth.create_company(c_name, c_desc, user["id"])
                        if ok:
                            st.success(msg)
                            st.rerun()
                        else:
                            st.error(msg)
        else:
            st.caption("Ask your admin to create a company and add you as a member.")
        return

    # ── Company exists ──
    is_owner = company["member_role"] == "owner"
    is_company_admin = company["member_role"] in ("owner", "admin")

    # Company header
    st.markdown(
        f'<div class="status-card">'
        f'<div class="card-label">Company</div>'
        f'<div class="card-value">{company["name"]}</div>'
        f'<div class="card-sub">{company.get("description", "")}</div>'
        f'</div>',
        unsafe_allow_html=True,
    )

    # Members
    members = auth.get_company_members(company["id"])
    st.markdown(f"### Team Members ({len(members)})")

    for m in members:
        avatar_color = m.get("avatar_color", "#2F5496")
        initials = "".join([w[0].upper() for w in (m.get("full_name") or m["username"]).split()[:2]])
        role_badge = {
            "owner": '<span class="pill pill-green">Owner</span>',
            "admin": '<span class="pill pill-blue">Admin</span>',
            "member": '<span class="pill">Member</span>',
        }.get(m["company_role"], '<span class="pill">Member</span>')

        is_self = m["id"] == user["id"]
        active_status = "Active" if m["is_active"] else "Disabled"

        with st.expander(
            f"{m['full_name'] or m['username']}  |  {m['email']}  |  "
            f"{m['company_role'].title()}  |  {active_status}"
        ):
            info_c, action_c = st.columns([2, 1])
            with info_c:
                st.markdown(
                    f'<div style="display:flex;align-items:center;gap:12px;margin-bottom:8px;">'
                    f'<div style="width:40px;height:40px;border-radius:50%;'
                    f'background:{avatar_color};display:flex;align-items:center;'
                    f'justify-content:center;font-size:1rem;font-weight:700;color:white;">'
                    f'{initials}</div>'
                    f'<div><strong>{m.get("full_name") or m["username"]}</strong><br>'
                    f'<span style="color:#888;font-size:0.85rem;">{m["email"]}</span></div>'
                    f'</div>',
                    unsafe_allow_html=True,
                )
                st.markdown(f"**System Role:** {m['system_role'].title()}")
                st.markdown(f"**Joined:** {_fmt_dt(m.get('joined_at'))}")
                st.markdown(role_badge, unsafe_allow_html=True)

            with action_c:
                if is_company_admin and not is_self and m["company_role"] != "owner":
                    # Change company role
                    new_role = st.selectbox(
                        "Company Role",
                        ["admin", "member"],
                        index=0 if m["company_role"] == "admin" else 1,
                        key=f"crole_{m['id']}",
                    )
                    if new_role != m["company_role"]:
                        auth.set_company_member_role(company["id"], m["id"], new_role)
                        st.rerun()

                    # Remove member
                    if st.button("Remove from Company", key=f"rm_member_{m['id']}",
                                 type="secondary"):
                        ok, msg = auth.remove_company_member(company["id"], m["id"])
                        if ok:
                            st.success(msg)
                            st.rerun()
                        else:
                            st.error(msg)

    # ── Add Members ──
    if is_company_admin:
        st.markdown("---")
        st.markdown("### Add Team Member")
        available_users = auth.get_users_without_company()

        if available_users:
            with st.form("add_member_form"):
                user_options = {f"{u['full_name'] or u['username']} ({u['email']})": u['id']
                               for u in available_users}
                selected_user = st.selectbox("Select User", list(user_options.keys()))
                member_role = st.selectbox("Role", ["member", "admin"])
                if st.form_submit_button("Add Member", type="primary",
                                         width='stretch'):
                    uid = user_options[selected_user]
                    ok, msg = auth.add_company_member(company["id"], uid, member_role)
                    if ok:
                        st.success(msg)
                        st.rerun()
                    else:
                        st.error(msg)
        else:
            st.caption("All registered users are already part of a company.")

    # ── Company Reports ──
    st.markdown("---")
    st.markdown("### Team Audit History")
    team_history = auth.get_company_audit_history(company["id"], limit=10)
    if team_history:
        for h in team_history:
            month_names = ["", "Jan", "Feb", "Mar", "Apr", "May", "Jun",
                           "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
            period = ""
            if h.get("audit_year") and h.get("audit_month"):
                m_idx = h["audit_month"] if 1 <= h["audit_month"] <= 12 else 0
                period = f"{month_names[m_idx]} {h['audit_year']}"
            st.markdown(
                f"- **{_fmt_dt(h['created_at'])}** — {h.get('username', 'N/A')} — "
                f"{h.get('accounts_audited', '')} — {period} — "
                f"${h.get('total_cost', 0):,.2f}"
            )
    else:
        st.caption("No team audit history yet.")

    # ── Delete Company (owner only) ──
    if is_owner:
        st.markdown("---")
        st.markdown("### Danger Zone")
        with st.expander("Delete Company", expanded=False):
            st.warning("This will remove the company and all member associations. "
                       "Audit history and reports are preserved per user.")
            if st.button("Delete Company Permanently", type="secondary"):
                ok, msg = auth.delete_company(company["id"])
                if ok:
                    st.success(msg)
                    st.rerun()
                else:
                    st.error(msg)


# ═════════════════════════════════════════════════════════════════════════
# ADMIN PANEL
# ═════════════════════════════════════════════════════════════════════════

def _render_admin():
    _back_to_dashboard("back_admin")
    st.markdown(
        '<div class="main-header">'
        '<div><h1>Admin Panel</h1><p>Manage users, settings, and system configuration</p></div>'
        '</div>',
        unsafe_allow_html=True,
    )

    tab_users, tab_smtp, tab_stats = st.tabs(["User Management", "SMTP Settings", "System Stats"])

    # ── User Management ──
    with tab_users:
        users = auth.list_users()
        st.markdown(f"**{len(users)} registered user(s)**")

        for u in users:
            with st.expander(
                f"{'[ADMIN]' if u['role'] == 'admin' else '[USER]'} "
                f"{u['username']}  |  {u['email']}  |  "
                f"{'Active' if u['is_active'] else 'Disabled'}  |  "
                f"Logins: {u['login_count']}"
            ):
                info_col, action_col = st.columns([2, 1])
                with info_col:
                    st.markdown(f"**Full Name:** {u.get('full_name', 'N/A')}")
                    st.markdown(f"**Email:** {u['email']}")
                    st.markdown(f"**Created:** {_fmt_dt(u['created_at'])}")
                    st.markdown(f"**Last Login:** {_fmt_dt(u.get('last_login'))}")

                with action_col:
                    # Don't allow self-modification for dangerous actions
                    is_self = u["id"] == st.session_state.user["id"]

                    # Toggle active
                    new_active = st.checkbox(
                        "Active",
                        value=bool(u["is_active"]),
                        key=f"active_{u['id']}",
                        disabled=is_self,
                    )
                    if new_active != bool(u["is_active"]):
                        auth.toggle_user_active(u["id"], new_active)
                        st.rerun()

                    # Role change
                    current_role = u["role"]
                    new_role = st.selectbox(
                        "Role", ["admin", "user"],
                        index=0 if current_role == "admin" else 1,
                        key=f"role_{u['id']}",
                        disabled=is_self,
                    )
                    if new_role != current_role:
                        auth.set_user_role(u["id"], new_role)
                        st.rerun()

                    # Reset password
                    with st.form(f"reset_pw_{u['id']}"):
                        new_pw = st.text_input("New Password", type="password",
                                               key=f"newpw_{u['id']}")
                        if st.form_submit_button("Reset Password"):
                            if new_pw:
                                ok, msg = auth.admin_reset_password(u["id"], new_pw)
                                if ok:
                                    st.success(msg)
                                else:
                                    st.error(msg)

                    # Delete user
                    if not is_self:
                        if st.button(f"Delete User", key=f"del_user_{u['id']}",
                                     type="secondary"):
                            auth.delete_user(u["id"])
                            st.success(f"User {u['username']} deleted.")
                            st.rerun()

    # ── SMTP Settings ──
    with tab_smtp:
        st.markdown("### Email Configuration (for OTP Password Reset)")
        st.caption("Configure SMTP to enable email-based password resets.")

        smtp_cfg = auth.get_smtp_config()

        with st.form("smtp_form"):
            smtp_host = st.text_input("SMTP Host", value=smtp_cfg.get("host", ""),
                                      placeholder="smtp.gmail.com")
            s_col1, s_col2 = st.columns(2)
            with s_col1:
                smtp_port = st.number_input("Port", value=int(smtp_cfg.get("port", 587)),
                                            min_value=1, max_value=65535)
            with s_col2:
                smtp_tls = st.checkbox("Use TLS", value=smtp_cfg.get("use_tls", True))
            smtp_user = st.text_input("Username", value=smtp_cfg.get("username", ""),
                                      placeholder="your@gmail.com")
            smtp_pass = st.text_input("Password", type="password",
                                      value=smtp_cfg.get("password", ""),
                                      placeholder="App password")
            smtp_from = st.text_input("From Email", value=smtp_cfg.get("from_email", ""),
                                      placeholder="noreply@company.com")

            if st.form_submit_button("Save SMTP Settings", type="primary",
                                     width='stretch'):
                auth.save_smtp_config(smtp_host, smtp_port, smtp_user,
                                      smtp_pass, smtp_from, smtp_tls)
                st.success("SMTP settings saved!")

        st.markdown("### Test SMTP")
        test_email = st.text_input("Test Email", placeholder="test@example.com")
        if st.button("Send Test Email"):
            if test_email:
                ok, msg = auth.test_smtp(test_email)
                if ok:
                    st.success(msg)
                else:
                    st.error(msg)

    # ── System Stats ──
    with tab_stats:
        stats = auth.get_dashboard_stats()
        s1, s2, s3 = st.columns(3)
        with s1:
            st.markdown(
                f'<div class="status-card">'
                f'<div class="card-label">Total Users</div>'
                f'<div class="card-value">{stats["total_users"]}</div>'
                f'<div class="card-sub">{stats["active_users"]} active</div>'
                f'</div>', unsafe_allow_html=True)
        with s2:
            st.markdown(
                f'<div class="status-card">'
                f'<div class="card-label">Total Audits Run</div>'
                f'<div class="card-value">{stats["total_audits"]}</div>'
                f'</div>', unsafe_allow_html=True)
        with s3:
            rl = stats.get("recent_login")
            if rl:
                st.markdown(
                    f'<div class="status-card">'
                    f'<div class="card-label">Last Login</div>'
                    f'<div class="card-value">{rl["username"]}</div>'
                    f'<div class="card-sub">{_fmt_dt(rl["last_login"])}</div>'
                    f'</div>', unsafe_allow_html=True)

        st.markdown("### Database Info")
        st.markdown(f"- **Database:** MySQL `{auth.db_config.get('database', 'aws_audit')}`")
        st.markdown(f"- **Host:** `{auth.db_config.get('host', 'localhost')}`")
        st.markdown(f"- **Reports Directory:** `{REPORTS_DIR}`")
        if os.path.exists(REPORTS_DIR):
            total_files = sum(len(files) for _, _, files in os.walk(REPORTS_DIR))
            st.markdown(f"- **Saved Reports:** {total_files} file(s)")


# ═════════════════════════════════════════════════════════════════════════
# SHARED: SIDEBAR ACCOUNT MANAGEMENT
# ═════════════════════════════════════════════════════════════════════════

def _render_sidebar_accounts():
    """Show account count and reports in sidebar."""
    with st.sidebar:
        st.markdown('<div class="divider"></div>', unsafe_allow_html=True)
        acct_count = len(st.session_state.accounts)
        if acct_count > 0:
            st.markdown(f"### Accounts ({acct_count})")
            for acct in st.session_state.accounts:
                masked = acct["access_key"][:4] + "****" + acct["access_key"][-4:]
                st.markdown(
                    f'<div class="acct-badge">'
                    f'<div class="acct-name">{acct["label"]}</div>'
                    f'<div class="acct-key">{masked}</div>'
                    f'</div>', unsafe_allow_html=True)
        else:
            st.caption("No AWS accounts added yet.")
            st.caption("Go to **AWS Accounts** page to add.")



# ═════════════════════════════════════════════════════════════════════════
# AWS ACCOUNTS PAGE (separate page for credentials)
# ═════════════════════════════════════════════════════════════════════════

def _render_accounts_page():
    _back_to_dashboard("back_accounts")
    st.markdown(
        '<div class="main-header">'
        '<div><h1>AWS Accounts</h1>'
        '<p>Add and manage your AWS account credentials for auditing</p></div>'
        '</div>',
        unsafe_allow_html=True,
    )

    col_form, col_list = st.columns([1, 1], gap="large")

    with col_form:
        st.markdown("### Add New Account")
        st.markdown("")

        with st.form("add_account_form", clear_on_submit=True):
            label = st.text_input("Account Label", placeholder="e.g. Production, Staging, Client-XYZ")
            st.markdown("")
            access_key = st.text_input("Access Key ID", placeholder="AKIA...")
            st.markdown("")
            secret_key = st.text_input("Secret Access Key", type="password", placeholder="Your secret access key")
            st.markdown("")

            submitted = st.form_submit_button("Add Account", type="primary", width='stretch')
            if submitted:
                if not access_key or not secret_key:
                    st.error("Both Access Key ID and Secret Access Key are required.")
                elif any(a["access_key"] == access_key for a in st.session_state.accounts):
                    st.warning("This account is already added.")
                else:
                    st.session_state.accounts.append({
                        "label": label.strip() or f"Account-{len(st.session_state.accounts)+1}",
                        "access_key": access_key.strip(),
                        "secret_key": secret_key.strip(),
                    })
                    st.success(f"Account added successfully!")
                    st.rerun()

        st.markdown("")
        st.info("Credentials are stored in memory only for this session. They are never saved to disk or database.")

    with col_list:
        st.markdown(f"### Added Accounts ({len(st.session_state.accounts)})")
        st.markdown("")

        if not st.session_state.accounts:
            st.markdown(
                '<div class="glow-card" style="padding:2rem;">'
                '<div class="glow-icon">&#128274;</div>'
                '<div class="glow-label">No accounts added</div>'
                '<div style="font-size:0.8rem;color:#64748b;margin-top:0.5rem;">'
                'Add an AWS account to get started with auditing</div>'
                '</div>', unsafe_allow_html=True)
        else:
            for i, acct in enumerate(st.session_state.accounts):
                masked = acct["access_key"][:4] + "****" + acct["access_key"][-4:]
                with st.container():
                    c1, c2 = st.columns([5, 1])
                    with c1:
                        st.markdown(
                            f'<div class="acct-badge">'
                            f'<div class="acct-name">{acct["label"]}</div>'
                            f'<div class="acct-key">{masked}</div>'
                            f'</div>', unsafe_allow_html=True)
                    with c2:
                        if st.button("Remove", key=f"del_acct_{i}", type="secondary"):
                            st.session_state.accounts.pop(i)
                            st.rerun()

            st.markdown("")
            if st.button("Clear All Accounts", width='stretch', type="secondary"):
                st.session_state.accounts = []
                st.session_state.audit_results = []
                st.rerun()


# ═════════════════════════════════════════════════════════════════════════
# MAIN DASHBOARD (Audit)
# ═════════════════════════════════════════════════════════════════════════

def _render_dashboard():
    user = st.session_state.user
    avatar_color = user.get("avatar_color", "#2F5496")
    initials = "".join([w[0].upper() for w in (user.get("full_name") or user["username"]).split()[:2]])

    # Header
    st.markdown(
        f'<div class="main-header">'
        f'<div><h1>AWS Internal Audit Dashboard</h1>'
        f'<p>Multi-account billing, payments, resource tracking, org verification & quotas</p></div>'
        f'<div class="user-badge">'
        f'<div class="user-info"><div class="uname">{user.get("full_name") or user["username"]}</div>'
        f'<div class="urole">{user["role"]}</div></div>'
        f'<div class="user-avatar" style="background:{avatar_color};">{initials}</div>'
        f'</div></div>',
        unsafe_allow_html=True,
    )

    _render_sidebar_accounts()

    # ── Main Content ─────────────────────────────────────────────────

    if not st.session_state.accounts:
        # Welcome Dashboard — no accounts yet
        company = auth.get_user_company(user["id"])
        stats = auth.get_dashboard_stats()

        # Quick stats bar
        st.markdown(
            f'<div class="quick-stats animate-in">'
            f'<div class="quick-stat"><div class="qs-dot" style="background:#6366f1;"></div>'
            f'<span class="qs-label">Users</span><span class="qs-value">{stats["total_users"]}</span></div>'
            f'<div class="quick-stat"><div class="qs-dot" style="background:#10b981;"></div>'
            f'<span class="qs-label">Audits</span><span class="qs-value">{stats["total_audits"]}</span></div>'
            f'<div class="quick-stat"><div class="qs-dot" style="background:#f59e0b;"></div>'
            f'<span class="qs-label">Active</span><span class="qs-value">{stats["active_users"]}</span></div>'
            f'<div class="quick-stat"><div class="qs-dot" style="background:#ef4444;"></div>'
            f'<span class="qs-label">Logins</span><span class="qs-value">{user.get("login_count", 0)}</span></div>'
            f'</div>',
            unsafe_allow_html=True,
        )

        g1, g2, g3, g4 = st.columns(4)
        with g1:
            st.markdown(
                '<div class="glow-card animate-in"><div class="glow-icon">&#9741;</div>'
                '<div class="glow-label">Add Accounts</div>'
                '<div style="font-size:0.75rem;color:#64748b;margin-top:4px;">Manage AWS credentials</div>'
                '</div>', unsafe_allow_html=True)
            if st.button("Go to Accounts", key="qa_accounts", width='stretch'):
                st.session_state.nav_page = "accounts"
                st.rerun()
        with g2:
            st.markdown(
                '<div class="glow-card animate-in"><div class="glow-icon">&#128269;</div>'
                '<div class="glow-label">Run Audit</div>'
                '<div style="font-size:0.75rem;color:#64748b;margin-top:4px;">6-step compliance check</div>'
                '</div>', unsafe_allow_html=True)
            if st.button("Go to Audit", key="qa_audit", width='stretch'):
                st.session_state.nav_page = "accounts"
                st.rerun()
        with g3:
            st.markdown(
                '<div class="glow-card animate-in"><div class="glow-icon">&#9889;</div>'
                '<div class="glow-label">Optimize</div>'
                '<div style="font-size:0.75rem;color:#64748b;margin-top:4px;">Find waste & security issues</div>'
                '</div>', unsafe_allow_html=True)
            if st.button("Go to Optimize", key="qa_optimize", width='stretch'):
                st.session_state.nav_page = "optimization"
                st.rerun()
        with g4:
            st.markdown(
                '<div class="glow-card animate-in"><div class="glow-icon">&#128202;</div>'
                '<div class="glow-label">Reports</div>'
                '<div style="font-size:0.75rem;color:#64748b;margin-top:4px;">Auto-generated Excel reports</div>'
                '</div>', unsafe_allow_html=True)
            if st.button("Go to Reports", key="qa_history", width='stretch'):
                st.session_state.nav_page = "history"
                st.rerun()

        # Recent Activity Timeline
        recent = auth.get_audit_history(user_id=user["id"], limit=5)
        if recent:
            st.markdown('<div class="divider"></div>', unsafe_allow_html=True)
            st.markdown("### Recent Activity")
            for h in recent:
                month_names = ["", "Jan", "Feb", "Mar", "Apr", "May", "Jun",
                               "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
                period = ""
                if h.get("audit_year") and h.get("audit_month"):
                    m_idx = h["audit_month"] if 1 <= h["audit_month"] <= 12 else 0
                    period = f"{month_names[m_idx]} {h['audit_year']}"
                st.markdown(
                    f'<div class="timeline-item">'
                    f'<div class="tl-time">{_fmt_dt(h["created_at"])}</div>'
                    f'<div class="tl-text">{h.get("accounts_audited", "N/A")} &mdash; {period} &mdash; '
                    f'${h.get("total_cost", 0):,.2f} &mdash; {h.get("total_resources", 0)} resources</div>'
                    f'</div>',
                    unsafe_allow_html=True,
                )

        # Team Section
        if company:
            st.markdown('<div class="divider"></div>', unsafe_allow_html=True)
            st.markdown(f"### Team — {company['name']}")
            members = auth.get_company_members(company["id"])
            cols = st.columns(min(len(members), 4))
            for i, m in enumerate(members[:4]):
                mc = m.get("avatar_color", "#6366f1")
                mi = "".join([w[0].upper() for w in (m.get("full_name") or m["username"]).split()[:2]])
                with cols[i]:
                    st.markdown(
                        f'<div class="glow-card" style="padding:1rem;">'
                        f'<div style="width:36px;height:36px;border-radius:10px;'
                        f'background:linear-gradient(135deg,{mc},{mc}cc);display:inline-flex;'
                        f'align-items:center;justify-content:center;font-size:0.85rem;'
                        f'font-weight:700;color:white;margin-bottom:0.4rem;">{mi}</div>'
                        f'<div style="font-size:0.85rem;font-weight:600;color:#e2e8f0;">'
                        f'{m.get("full_name") or m["username"]}</div>'
                        f'<div style="font-size:0.68rem;color:#64748b;">{m["company_role"].title()}</div>'
                        f'</div>',
                        unsafe_allow_html=True)

        st.markdown('<div class="divider"></div>', unsafe_allow_html=True)
        st.info("Add AWS accounts in the sidebar to begin auditing.")
        return

    # Audit Configuration
    st.markdown("### Audit Configuration")
    ctrl_c1, ctrl_c2, ctrl_c3, ctrl_c4 = st.columns([2, 1, 1, 1])

    with ctrl_c1:
        account_labels = [a["label"] for a in st.session_state.accounts]
        select_all = st.checkbox("Select All Accounts", value=True, key="sel_all")
        if select_all:
            selected = account_labels
        else:
            selected = st.multiselect("Choose Accounts", account_labels,
                                      default=account_labels, key="acct_sel")

    with ctrl_c2:
        now = datetime.utcnow()
        audit_year = st.selectbox("Year", list(range(now.year, now.year - 3, -1)),
                                  index=0, key="audit_year")

    with ctrl_c3:
        month_names = ["January", "February", "March", "April", "May", "June",
                       "July", "August", "September", "October", "November", "December"]
        default_month = now.month - 1 if now.month > 1 else 12
        audit_month = st.selectbox("Month", list(range(1, 13)),
                                   index=default_month - 1,
                                   format_func=lambda x: month_names[x - 1],
                                   key="audit_month")

    with ctrl_c4:
        st.markdown("<br>", unsafe_allow_html=True)
        run_btn = st.button("Run Audit", type="primary", width='stretch')

    st.markdown('<div class="divider"></div>', unsafe_allow_html=True)

    # ── RUN AUDIT ────────────────────────────────────────────────────
    if run_btn:
        if not selected:
            st.error("Select at least one account.")
            st.stop()

        # Check for already running audit jobs
        user_id = st.session_state.user["id"]
        running = [j for j in _get_user_jobs(user_id) if j["status"] == "running" and j["type"] == "audit"]
        if running:
            st.warning("An audit job is already running. Check the sidebar for progress.")
            st.stop()

        accounts_to_audit = [a for a in st.session_state.accounts if a["label"] in selected]
        label = ", ".join(a["label"] for a in accounts_to_audit[:3])
        if len(accounts_to_audit) > 3:
            label += f" +{len(accounts_to_audit)-3} more"

        job_id = _start_job(
            "audit", user_id, label, accounts_to_audit,
            year=audit_year, month=audit_month,
        )
        st.session_state.viewing_job_id = job_id
        st.session_state.nav_page = "job_view"
        st.rerun()

    # ── DISPLAY RESULTS ──────────────────────────────────────────────
    if not st.session_state.audit_results:
        st.markdown("### Ready to Audit")
        st.markdown("Configure accounts in the sidebar, select year/month, and click **Run Audit**.")
        return

    results = st.session_state.audit_results

    # Summary Cards
    st.markdown('<div class="divider"></div>', unsafe_allow_html=True)
    st.markdown("### Audit Results Overview")

    total_cost = total_forecast = total_resources_all = error_count = 0
    total_regions_all = set()

    for a in results:
        b = a.get("billing") or {}
        rd = a.get("regions") or {}
        ar = rd.get("regions", {}) if isinstance(rd, dict) else {}
        try:
            total_cost += float(b.get("last_month_total_cost", "0").split(":")[0].replace("Error", "0"))
        except (ValueError, AttributeError):
            pass
        try:
            total_forecast += float(b.get("forecasted_cost_current_month", "0").split(":")[0].replace("Error", "0"))
        except (ValueError, AttributeError):
            pass
        total_resources_all += rd.get("total_resources", 0) if isinstance(rd, dict) else 0
        total_regions_all.update(ar.keys())
        error_count += len(a.get("errors", []))

    sc1, sc2, sc3, sc4, sc5 = st.columns(5)
    with sc1:
        st.markdown(f'<div class="status-card"><div class="card-label">Accounts Audited</div>'
                    f'<div class="card-value">{len(results)}</div></div>', unsafe_allow_html=True)
    with sc2:
        st.markdown(f'<div class="status-card"><div class="card-label">Total Cost (Selected Month)</div>'
                    f'<div class="card-value">${total_cost:,.2f}</div></div>', unsafe_allow_html=True)
    with sc3:
        st.markdown(f'<div class="status-card"><div class="card-label">Forecasted Cost</div>'
                    f'<div class="card-value">${total_forecast:,.2f}</div></div>', unsafe_allow_html=True)
    with sc4:
        cls = "success" if not error_count else "error"
        st.markdown(f'<div class="status-card {cls}"><div class="card-label">Regions / Resources</div>'
                    f'<div class="card-value">{len(total_regions_all)} / {total_resources_all}</div></div>',
                    unsafe_allow_html=True)
    with sc5:
        cls = "success" if not error_count else "error"
        st.markdown(f'<div class="status-card {cls}"><div class="card-label">Errors</div>'
                    f'<div class="card-value">{error_count}</div></div>', unsafe_allow_html=True)

    st.markdown('<div class="divider"></div>', unsafe_allow_html=True)

    # Report Download
    st.markdown("### Download Report")
    dl1, dl2 = st.columns([2, 3])
    with dl1:
        r_year = st.session_state.get("audit_year", now.year)
        r_month = st.session_state.get("audit_month", now.month)
        report_bytes, saved_path = generate_report(
            results, save_dir=_user_reports_dir(), year=r_year, month=r_month,
        )
        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        fname = f"AWS_Audit_{datetime(r_year, r_month, 1).strftime('%b_%Y')}_{ts}.xlsx"
        st.download_button(
            "Download Excel Report", data=report_bytes, file_name=fname,
            mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            type="primary", width='stretch',
        )
    with dl2:
        if saved_path:
            st.success(f"Auto-saved: `{saved_path}`")
        st.caption("Sheets: Master (All Accounts), Per-Account Details, Region & Services, Quotas, Organization")

    st.markdown('<div class="divider"></div>', unsafe_allow_html=True)

    # Per-Account Detail
    st.markdown("### Detailed Account Results")

    for audit in results:
        label = audit.get("account_label", "Unknown")
        account_id = audit.get("account_id", "N/A")
        errors = audit.get("errors", [])
        org = audit.get("organization") or {}
        billing = audit.get("billing") or {}
        payment = audit.get("payment") or {}
        regions_data = audit.get("regions") or {}
        active_regions = regions_data.get("regions", {}) if isinstance(regions_data, dict) else {}
        quotas = audit.get("quotas") or {}
        mfa = org.get("mfa_status", "N/A")

        with st.expander(
            f"{label}  |  {account_id}  |  MFA: {mfa}  |  "
            f"Regions: {len(active_regions)}  |  "
            f"Last Month: ${billing.get('last_month_total_cost', 'N/A')}  |  "
            f"Due: {payment.get('payment_due', 'No')}",
            expanded=True,
        ):
            if errors:
                for err in errors:
                    st.error(err)

            q1, q2, q3, q4 = st.columns(4)
            with q1:
                st.markdown(
                    f'<div class="status-card"><div class="card-label">'
                    f'Step 1: {billing.get("target_month","Last Month")} Total Cost</div>'
                    f'<div class="card-value">${billing.get("last_month_total_cost","N/A")}</div>'
                    f'<div class="card-sub">{billing.get("currency","USD")}</div></div>',
                    unsafe_allow_html=True)
            with q2:
                st.markdown(
                    f'<div class="status-card"><div class="card-label">'
                    f'Step 1: Forecasted Cost (Current Month)</div>'
                    f'<div class="card-value">${billing.get("forecasted_cost_current_month","N/A")}</div>'
                    f'<div class="card-sub">{billing.get("forecast_currency","USD")}</div></div>',
                    unsafe_allow_html=True)
            with q3:
                due = payment.get("payment_due", "No")
                cls = "success" if due == "No" else "error"
                st.markdown(
                    f'<div class="status-card {cls}"><div class="card-label">'
                    f'Step 2: Outstanding Balance</div>'
                    f'<div class="card-value">${payment.get("outstanding_balance","N/A")}</div>'
                    f'<div class="card-sub">Bill Due: {due}</div></div>',
                    unsafe_allow_html=True)
            with q4:
                nr = len(active_regions)
                nres = regions_data.get("total_resources", 0) if isinstance(regions_data, dict) else 0
                st.markdown(
                    f'<div class="status-card"><div class="card-label">Regions / Resources</div>'
                    f'<div class="card-value">{nr} / {nres}</div>'
                    f'<div class="card-sub">Across all services</div></div>',
                    unsafe_allow_html=True)

            tab_bills, tab_r, tab_o, tab_q, tab_a = st.tabs([
                "Step 3: Bills (Service x Region)",
                "Step 3: Region & Service Map",
                "Step 4: Organization",
                "Step 5: Service Quotas",
                "Step 2: Billing Alerts",
            ])

            # == BILLS (Service x Region from Billing > Bills) ==
            with tab_bills:
                bills_data = audit.get("bills") or {}
                for period_key, period_label in [("last_month", "Last Month"), ("current_month", "Current Month")]:
                    items = bills_data.get(period_key, [])
                    st.markdown(f"**{period_label}** ({len(items)} service-region entries)")
                    if items:
                        df_bills = pd.DataFrame(items)
                        st.dataframe(df_bills, width='stretch', hide_index=True)
                    else:
                        st.caption("No bill data available.")

            with tab_r:
                if active_regions:
                    rows = []
                    for r, rd in sorted(active_regions.items()):
                        svcs = rd.get("services", {})
                        rows.append({
                            "Region": r,
                            "Name": rd.get("region_name", r),
                            "Services": ", ".join(svcs.keys()),
                            "Resources": rd.get("total_resources", 0),
                        })
                    st.dataframe(pd.DataFrame(rows), width='stretch', hide_index=True)

                    for r, rd in sorted(active_regions.items()):
                        rn = rd.get("region_name", r)
                        svcs = rd.get("services", {})
                        dets = rd.get("details", {})
                        s_str = ", ".join(f"{k}: {v}" for k, v in svcs.items())
                        with st.expander(f"{rn} ({r}) - {s_str}"):
                            for sn, items in dets.items():
                                st.markdown(f"**{sn}** ({len(items)})")
                                if items:
                                    st.dataframe(pd.DataFrame(items), width='stretch',
                                               hide_index=True,
                                               height=min(len(items) * 40 + 40, 300))
                else:
                    st.info("No active resources found.")

            with tab_o:
                oc1, oc2 = st.columns(2)
                with oc1:
                    st.markdown("**Organization Info**")
                    for f, v in [("Organization ID", org.get("org_id", "N/A")),
                                 ("Org ARN", org.get("org_arn", "N/A")),
                                 ("Mgmt Account ID", org.get("management_account_id", "N/A")),
                                 ("Mgmt Email", org.get("management_account_email", "N/A"))]:
                        st.markdown(f"- **{f}:** `{v}`")
                with oc2:
                    st.markdown("**Account Info**")
                    st.markdown(f"- **Alias:** `{org.get('account_name', 'N/A')}`")
                    st.markdown(f"- **IAM User:** `{org.get('iam_user', 'N/A')}`")
                    if mfa == "Enabled":
                        st.markdown(f"- **MFA:** :green[**{mfa}**]")
                    elif mfa == "Disabled":
                        st.markdown(f"- **MFA:** :red[**{mfa}**]")
                    else:
                        st.markdown(f"- **MFA:** {mfa}")

            with tab_q:
                if quotas:
                    qrows = []
                    for rl, rq in quotas.items():
                        for qn, qd in rq.items():
                            if "error" in qd:
                                qrows.append({"Region": rl, "Quota": qn, "Value": "ERROR",
                                             "Unit": "", "Adjustable": "", "Source": qd["error"][:60]})
                            else:
                                qrows.append({"Region": rl, "Quota": qn,
                                             "Value": str(qd.get("value", "N/A")),
                                             "Unit": qd.get("unit", ""),
                                             "Adjustable": "Yes" if qd.get("adjustable") else "No",
                                             "Source": qd.get("source", "")})
                    st.dataframe(pd.DataFrame(qrows), width='stretch', hide_index=True)
                else:
                    st.warning("Quota data unavailable.")

            with tab_a:
                alerts = payment.get("billing_alerts", [])
                if alerts:
                    st.warning(f"{len(alerts)} billing alarm(s) in ALARM state")
                    for al in alerts:
                        st.markdown(
                            f'<div class="status-card error">'
                            f'<div class="card-label">{al["name"]}</div>'
                            f'<div class="card-sub">{al["reason"]}</div></div>',
                            unsafe_allow_html=True)
                else:
                    st.success("No active billing alarms. All clear.")

    # Footer
    st.markdown('<div class="divider"></div>', unsafe_allow_html=True)
    st.markdown(
        f'<p style="text-align:center;color:#999;font-size:0.78rem;">'
        f'AWS Internal Audit Tool v2.0 | '
        f'{datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")} UTC | '
        f'Reports: per-user storage</p>',
        unsafe_allow_html=True,
    )


def _save_audit_history(results, audit_year, audit_month):
    """Save audit run to history DB."""
    user = st.session_state.user
    if not user:
        return

    account_names = ", ".join(a.get("account_label", "") for a in results)
    t_cost = 0
    t_res = 0
    t_reg = set()
    t_err = 0

    for a in results:
        b = a.get("billing") or {}
        rd = a.get("regions") or {}
        ar = rd.get("regions", {}) if isinstance(rd, dict) else {}
        try:
            t_cost += float(b.get("last_month_total_cost", "0").replace("Error:", "0"))
        except (ValueError, AttributeError):
            pass
        t_res += rd.get("total_resources", 0) if isinstance(rd, dict) else 0
        t_reg.update(ar.keys())
        t_err += len(a.get("errors", []))

    # Generate and save report
    r_year = st.session_state.get("audit_year", datetime.utcnow().year)
    r_month = st.session_state.get("audit_month", datetime.utcnow().month)
    _, saved_path = generate_report(results, save_dir=_user_reports_dir(),
                                     year=r_year, month=r_month)

    auth.save_audit_log(
        user_id=user["id"],
        accounts_audited=account_names,
        total_accounts=len(results),
        audit_year=audit_year,
        audit_month=audit_month,
        total_cost=t_cost,
        total_resources=t_res,
        active_regions=len(t_reg),
        errors=t_err,
        report_path=saved_path,
    )


def _save_optimization_history(results):
    """Save optimization scan to audit history DB."""
    user = st.session_state.user
    if not user:
        return
    account_names = ", ".join(r.get("account_label", "") for r in results)
    total_findings = sum(len(r.get("findings", [])) for r in results)
    total_savings = sum(
        f.get("estimated_savings", 0) for r in results for f in r.get("findings", [])
    )
    now = datetime.utcnow()

    # Generate and save optimization report
    report_bytes, saved_path = generate_optimization_report(
        results, save_dir=_user_reports_dir(),
    )

    auth.save_audit_log(
        user_id=user["id"],
        accounts_audited=f"[Optimization] {account_names}",
        total_accounts=len(results),
        audit_year=now.year,
        audit_month=now.month,
        total_cost=total_savings,
        total_resources=total_findings,
        active_regions=0,
        errors=0,
        report_path=saved_path,
    )


# ═════════════════════════════════════════════════════════════════════════
# MAIN ROUTER
# ═════════════════════════════════════════════════════════════════════════

if st.session_state.setup_2fa_user is not None:
    setup_2fa_page()
elif not st.session_state.authenticated:
    page = st.session_state.auth_page
    if page == "register":
        register_page()
    elif page == "forgot":
        forgot_password_page()
    else:
        login_page()
else:
    dashboard_page()
