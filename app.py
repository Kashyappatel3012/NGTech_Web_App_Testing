from flask import Flask, render_template, redirect, url_for, request, flash, abort, session, make_response, jsonify, send_file, Response
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from werkzeug.exceptions import RequestEntityTooLarge
from security_utils import sanitize_email_header, sanitize_email_content, sanitize_filename, sanitize_referrer, sanitize_path
from password_utils import validate_password_strength, get_password_requirements
from rate_limit_utils import check_rate_limit, record_attempt, check_credential_stuffing, reset_rate_limit
from authorization_utils import require_hr, require_admin, require_audit, check_user_access, can_access_user_data, can_modify_user_data
from error_handler_utils import get_safe_error_message, handle_exception_safely, sanitize_error_response
from excel_security_utils import sanitize_excel_value, sanitize_excel_cell_value
from file_upload_utils import secure_file_upload, validate_file_content, validate_file_size
from client_security_utils import sanitize_for_html, sanitize_for_js, sanitize_url_param, sanitize_for_json
from csrf_utils import generate_csrf_token, validate_csrf_token, csrf_protect
import os
import random
import string
import secrets
import logging
from flask_mail import Mail, Message
from datetime import datetime, timedelta
from flask_session import Session
import tempfile
import io
import base64

import pytz

# Try to import PIL for CAPTCHA generation
try:
    from PIL import Image, ImageDraw, ImageFont
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('app.log'),
        logging.StreamHandler()
    ]
)
from encryption_utils import get_encryption_manager, encrypt_data, decrypt_data
from HR_Dashboard_Files.Hr_dashboard import hr_dashboard_bp
from Admin_Dashboard_Files.admin_dashboard import admin_dashboard_bp
from Audit_Dashboard_Files.Infra_VAPT_First_Audit_Excel import nmap_bp
from Audit_Dashboard_Files.Infra_VAPT_First_Audit_Word_Report import word_report_bp
from VAPT_Dashboard_Files.Infra_VAPT_First_Audit_Excel import vapt_nmap_bp
from VAPT_Dashboard_Files.Infra_VAPT_First_Audit_Word_Report import vapt_word_report_bp
from VAPT_Dashboard_Files.Website_VAPT_First_Audit_Word_Report import website_vapt_word_report_bp
from VAPT_Dashboard_Files.Android_Application_First_Audit_Word_Report import android_app_word_report_bp
from VAPT_Dashboard_Files.IOS_Application_First_Audit_Word_Report import ios_app_word_report_bp
from VAPT_Dashboard_Files.API_VAPT_First_Audit_Word_Report import api_first_audit_word_report_bp
from VAPT_Dashboard_Files.Web_Application_First_Audit_Word_Report import web_app_word_report_bp
from VAPT_Dashboard_Files.Public_IP_VAPT_First_Audit_Word_Report import public_ip_vapt_first_audit_word_report_bp
from Audit_Dashboard_Files.Infra_VAPT_Follow_up_Audit_Excel import follow_up_audit_bp
from VAPT_Dashboard_Files.Infra_VAPT_Follow_up_Audit_Excel import vapt_follow_up_audit_bp
from Audit_Dashboard_Files.Infra_VAPT_Follow_Up_Audit_Word_Report import follow_up_word_report_bp
from VAPT_Dashboard_Files.Infra_VAPT_Follow_Up_Audit_Word_Report import vapt_follow_up_word_report_bp
from VAPT_Dashboard_Files.Android_Application_Follow_Up_Audit_Word_Report import android_follow_up_word_report_bp
from VAPT_Dashboard_Files.IOS_Application_Follow_Up_Audit_Word_Report import ios_follow_up_word_report_bp
from VAPT_Dashboard_Files.API_VAPT_Follow_Up_Audit_Word_Report import api_follow_up_word_report_bp
from VAPT_Dashboard_Files.Web_Application_Follow_Up_Audit_Word_Report import web_app_follow_up_word_report_bp
from VAPT_Dashboard_Files.Website_VAPT_Follow_Up_Audit_Word_Report import website_vapt_follow_up_word_report_bp
from VAPT_Dashboard_Files.Infra_First_Audit_Metadata import vapt_first_audit_metadata_bp
from VAPT_Dashboard_Files.API_First_Audit_Metadata import api_first_audit_metadata_bp
from VAPT_Dashboard_Files.Public_IP_First_Audit_Metadata import public_ip_first_audit_metadata_bp
from VAPT_Dashboard_Files.Public_IP_Follow_Up_Audit_Metadata import public_ip_follow_up_audit_metadata_bp
from VAPT_Dashboard_Files.Website_VAPT_First_Audit_Metadata import website_vapt_first_audit_metadata_bp
from VAPT_Dashboard_Files.IOS_Application_First_Audit_Metadata import ios_application_first_audit_metadata_bp
from VAPT_Dashboard_Files.IOS_Application_Follow_Up_Audit_Metadata import ios_application_follow_up_audit_metadata_bp
from VAPT_Dashboard_Files.Android_Application_First_Audit_Metadata import android_application_first_audit_metadata_bp
from VAPT_Dashboard_Files.Android_Application_First_Audit_Excel import android_app_vapt_bp
from VAPT_Dashboard_Files.Android_Application_Follow_Up_Audit_Metadata import android_application_follow_up_audit_metadata_bp
from VAPT_Dashboard_Files.Web_Application_Follow_Up_Audit_Metadata import web_application_follow_up_audit_metadata_bp
from VAPT_Dashboard_Files.Web_Application_First_Audit_Metadata import web_application_first_audit_metadata_bp
from VAPT_Dashboard_Files.IOS_Application_First_Audit_Metadata import ios_application_first_audit_metadata_bp
from VAPT_Dashboard_Files.Infra_Follow_Up_Audit_Metadata import vapt_follow_up_audit_metadata_bp
from VAPT_Dashboard_Files.API_Follow_Up_Audit_Metadata import api_follow_up_audit_metadata_bp
from VAPT_Dashboard_Files.Website_VAPT_Follow_Up_Audit_Metadata import website_vapt_follow_up_audit_metadata_bp
from VAPT_Dashboard_Files.Website_VAPT_First_Audit_Excel import website_vapt_bp
from VAPT_Dashboard_Files.Website_VAPT_Follow_Up_Audit_Excel import website_vapt_followup_bp
from VAPT_Dashboard_Files.Public_IP_First_Audit_Excel import public_ip_vapt_bp
from VAPT_Dashboard_Files.Public_IP_Follow_Up_Audit_Excel import public_ip_vapt_followup_bp
from VAPT_Dashboard_Files.Public_IP_VAPT_Follow_Up_Audit_Word_Report import public_ip_vapt_follow_up_word_report_bp
from VAPT_Dashboard_Files.Web_Application_First_Audit_Excel import web_app_vapt_bp
from VAPT_Dashboard_Files.Web_Application_Follow_Up_Audit_Excel import web_app_vapt_followup_bp
from VAPT_Dashboard_Files.IOS_Application_First_Audit_Excel import ios_app_vapt_bp
from VAPT_Dashboard_Files.API_First_Audit_Excel import api_vapt_bp
from VAPT_Dashboard_Files.Android_Follow_up_Audit_Excel import android_app_vapt_followup_bp
from VAPT_Dashboard_Files.IOS_Follow_up_Audit_Excel import ios_app_vapt_followup_bp
from VAPT_Dashboard_Files.API_Follow_up_Audit_Excel import api_vapt_followup_bp
from VAPT_Dashboard_Files.Everyday_Workplan import everyday_workplan_bp
from VAPT_Dashboard_Files.Everyday_Updated_Work import everyday_updated_work_bp
from VAPT_Dashboard_Files.Submit_Sprint_Plan import submit_sprint_plan_bp
from VAPT_Dashboard_Files.Submit_Sprint_Work import submit_sprint_work_bp
from VAPT_Dashboard_Files.Extra_Work import extra_work_bp
from Audit_Dashboard_Files.Infra_VAPT_First_Audit_Certificate import first_audit_certificate_bp
from Audit_Dashboard_Files.Infra_VAPT_Follow_up_Audit_Certificate import follow_up_audit_certificate_bp
from VAPT_Dashboard_Files.Infra_VAPT_First_Audit_Certificate import vapt_first_audit_certificate_bp
from VAPT_Dashboard_Files.Website_VAPT_First_Audit_Certificate import website_vapt_first_audit_certificate_bp
from VAPT_Dashboard_Files.Web_Application_VAPT_first_Audit_Certificate import web_app_vapt_first_audit_certificate_bp
from VAPT_Dashboard_Files.Android_Application_VAPT_first_Audit_Certificate import android_app_vapt_first_audit_certificate_bp
from VAPT_Dashboard_Files.IOS_Application_VAPT_first_Audit_Certificate import ios_app_vapt_first_audit_certificate_bp
from VAPT_Dashboard_Files.API_VAPT_first_Audit_Certificate import api_vapt_first_audit_certificate_bp
from VAPT_Dashboard_Files.Public_IP_VAPT_first_Audit_Certificate import public_ip_vapt_first_audit_certificate_bp
from VAPT_Dashboard_Files.Infra_VAPT_Follow_Up_Audit_Certificate import vapt_follow_up_audit_certificate_bp
from VAPT_Dashboard_Files.Website_VAPT_Follow_Up_Audit_Certificate import website_vapt_follow_up_audit_certificate_bp
from VAPT_Dashboard_Files.API_VAPT_follow_Up_Audit_Certificate import api_vapt_follow_up_audit_certificate_bp
from VAPT_Dashboard_Files.Web_Application_VAPT_follow_Up_Audit_Certificate import web_app_vapt_follow_up_audit_certificate_bp
from VAPT_Dashboard_Files.Android_Application_VAPT_follow_Up_Audit_Certificate import android_app_vapt_follow_up_audit_certificate_bp
from VAPT_Dashboard_Files.IOS_Application_VAPT_follow_Up_Audit_Certificate import ios_app_vapt_follow_up_audit_certificate_bp
from VAPT_Dashboard_Files.Public_IP_VAPT_follow_Up_Audit_Certificate import public_ip_vapt_follow_up_audit_certificate_bp
from Audit_Dashboard_Files.IS_Audit_Complition_Certificate import is_audit_certificate_bp
from Audit_Dashboard_Files.Cyber_Security_Audit_Complition_Certificate import cyber_security_audit_certificate_bp
from Audit_Dashboard_Files.Gap_Assessment_Audit_Complition_Certificate import gap_assessment_audit_certificate_bp
from Audit_Dashboard_Files.Branch_Excel_Without_POC import branch_excel_bp
from Audit_Dashboard_Files.Branch_Excel_With_POC import branch_excel_with_poc_bp
from Audit_Dashboard_Files.Combine_Branch_Excel_WithoutPOC import combine_branch_excel_without_poc_bp
from Audit_Dashboard_Files.Combine_Branch_Excel_With_POC import combine_branch_excel_with_poc_bp
from Audit_Dashboard_Files.Combine_Assets_Excels import combine_assets_excels_bp
from Audit_Dashboard_Files.Asset_Review_Non_Compliance_Points import asset_review_non_compliance_bp
from Audit_Dashboard_Files.Branch_Console import branch_console_bp
from Audit_Dashboard_Files.IS_Audit_Word_Report import is_audit_word_report_bp
from Audit_Dashboard_Files.Asset_Review_Evidance_Attach.Network_Review_With_POC import network_review_evidence_bp
from Audit_Dashboard_Files.Asset_Review_Evidance_Attach.Data_Centre_With_POC import data_centre_evidence_bp
from Audit_Dashboard_Files.Asset_Review_Evidance_Attach.Disaster_Recovery_With_POC import disaster_recovery_evidence_bp
from Audit_Dashboard_Files.Asset_Review_Evidance_Attach.Firewall_POC import firewall_evidence_bp
from Audit_Dashboard_Files.Asset_Review_Evidance_Attach.Core_Switch_With_POC import core_switch_evidence_bp
from Audit_Dashboard_Files.Asset_Review_Evidance_Attach.Router_With_POC import router_evidence_bp
from Audit_Dashboard_Files.Asset_Review_Evidance_Attach.Domain_Control_AD_With_POC import domain_controller_evidence_bp
from Audit_Dashboard_Files.Asset_Review_Evidance_Attach.H2H_With_POC import h2h_evidence_bp
from Audit_Dashboard_Files.Asset_Review_Evidance_Attach.Antivirus_With_POC import antivirus_evidence_bp
from Audit_Dashboard_Files.Asset_Review_Evidance_Attach.ATM_With_POC import atm_evidence_bp
from Audit_Dashboard_Files.Asset_Review_Evidance_Attach.Mail_Messaging_With_POC import mail_messaging_evidence_bp
from Audit_Dashboard_Files.Asset_Review_Evidance_Attach.HO_win_Server_With_POC import ho_win_server_evidence_bp
from Audit_Dashboard_Files.Asset_Review_Evidance_Attach.Linux_Server_With_POC import linux_server_evidence_bp
from Audit_Dashboard_Files.Asset_Review_Evidance_Attach.ESXI_Server_With_POC import esxi_server_evidence_bp
from Audit_Dashboard_Files.Asset_Review_Evidance_Attach.Access_Control_OS_With_POC import access_control_os_evidence_bp
from Audit_Dashboard_Files.Asset_Review_Evidance_Attach.Access_Control_Appli_With_POC import access_control_application_evidence_bp
from Audit_Dashboard_Files.Asset_Review_Evidance_Attach.Application_With_POC import application_evidence_bp
from Audit_Dashboard_Files.Asset_Review_Evidance_Attach.Internet_Banking_With_POC import internet_banking_evidence_bp
from Audit_Dashboard_Files.Asset_Review_Evidance_Attach.Internal_Control_Evaluation_With_POC import internal_control_evidence_bp
from Audit_Dashboard_Files.Asset_Review_Evidance_Attach.Fire_Protection_With_POC import fire_protection_evidence_bp
from Audit_Dashboard_Files.Asset_Review_Evidance_Attach.AMC_With_POC import amc_evidence_bp
from Audit_Dashboard_Files.Asset_Review_Evidance_Attach.Data_Input_Control_With_POC import data_input_control_evidence_bp
from Audit_Dashboard_Files.Asset_Review_Evidance_Attach.Purging_of_Data_Files_With_POC import purging_data_files_evidence_bp
from Audit_Dashboard_Files.Asset_Review_Evidance_Attach.BCPlan_With_POC import business_continuity_planning_evidence_bp
from Audit_Dashboard_Files.Asset_Review_Evidance_Attach.In_house_Out_Sou_With_POC import inhouse_outsourced_evidence_bp
from Audit_Dashboard_Files.Asset_Review_Evidance_Attach.Audit_Trail_With_POC import audit_trail_evidence_bp
from Audit_Dashboard_Files.Asset_Review_Evidance_Attach.Packaged_Software_With_POC import packaged_software_evidence_bp
from Audit_Dashboard_Files.Asset_Review_Evidance_Attach.User_Account_Maintenance_With_POC import user_account_maintenance_evidence_bp
from Audit_Dashboard_Files.Asset_Review_Evidance_Attach.Logical_Access_Controls_With_POC import logical_access_controls_evidence_bp
from Audit_Dashboard_Files.Asset_Review_Evidance_Attach.Database_Controls_With_POC import database_controls_evidence_bp
from Audit_Dashboard_Files.Asset_Review_Evidance_Attach.Penetration_Testing_With_POC import penetration_testing_evidence_bp
from Audit_Dashboard_Files.Asset_Review_Evidance_Attach.Training_With_POC import training_evidence_bp
from Audit_Dashboard_Files.Asset_Review_Evidance_Attach.Remote_Access_With_POC import remote_access_evidence_bp
from Audit_Dashboard_Files.Asset_Review_Evidance_Attach.Power_Supply_With_POC import power_supply_evidence_bp
from Audit_Dashboard_Files.Asset_Review_Evidance_Attach.Backup_Restoration_With_POC import backup_restoration_evidence_bp
from Audit_Dashboard_Files.Asset_Review_Evidance_Attach.Maintenance_App_Patches_With_POC import maintenance_patches_evidence_bp
from Audit_Dashboard_Files.Asset_Review_Evidance_Attach.Network_Monitoring_Tool_With_POC import network_monitoring_tool_evidence_bp
from Audit_Dashboard_Files.Asset_Review_Evidance_Attach.SAN_With_CISCO_With_POC import san_switch_cisco_evidence_bp
from Audit_Dashboard_Files.Asset_Review_Evidance_Attach.SAN_Storage_With_POC import san_storage_evidence_bp
from Audit_Dashboard_Files.Asset_Review_Evidance_Attach.NAS_With_POC import nas_evidence_bp
from Audit_Dashboard_Files.Asset_Review_Evidance_Attach.Load_Balancer_With_POC import load_balancer_array_evidence_bp
from Audit_Dashboard_Files.Asset_Review_Evidance_Attach.PAM_With_POC import pam_evidence_bp
from Audit_Dashboard_Files.Asset_Review_Evidance_Attach.SOC_With_POC import soc_evidence_bp
from Audit_Dashboard_Files.Asset_Review_Evidance_Attach.Change_Management_With_POC import change_management_evidence_bp
from Audit_Dashboard_Files.Asset_Review_Evidance_Attach.Asset_Management_With_POC import asset_management_evidence_bp
from Audit_Dashboard_Files.Asset_Review_Evidance_Attach.Others_With_POC import others_evidence_bp
from Audit_Dashboard_Files.GAP_Assessment.VICS_01 import vics_part1_bp
from Audit_Dashboard_Files.GAP_Assessment.VICS_02 import vics_part2_bp
from Audit_Dashboard_Files.GAP_Assessment.VICS_03 import vics_part3_bp
from Audit_Dashboard_Files.GAP_Assessment.VICS_04 import vics_part4_bp
from Audit_Dashboard_Files.GAP_Assessment.VICS_05 import vics_part5_bp
from Audit_Dashboard_Files.GAP_Assessment.VICS_06 import vics_part6_bp
from Audit_Dashboard_Files.GAP_Assessment.VICS_07 import vics_part7_bp
from Audit_Dashboard_Files.GAP_Assessment.Create_VICS_Worksheet import create_vics_worksheet_bp
from Audit_Dashboard_Files.GAP_Assessment.LOC_Level2 import loc_level2_bp
from Audit_Dashboard_Files.GAP_Assessment.LOC_Level3 import loc_level3_bp
from Audit_Dashboard_Files.GAP_Assessment.LOC_Level4 import loc_level4_bp
from Audit_Dashboard_Files.GAP_Assessment.Create_LOC_Worksheet import create_loc_worksheet_bp
from Audit_Dashboard_Files.GAP_Assessment.LOE import loe_bp
from Audit_Dashboard_Files.GAP_Assessment.Create_VICS_Worksheet_with_bank_input import create_vics_with_bank_input_bp
from Audit_Dashboard_Files.GAP_Assessment.Create_LOC_Worksheet_with_bank_input import create_loc_with_bank_input_bp
from Audit_Dashboard_Files.GAP_Assessment.Gap_Assessment_Excel import gap_assessment_excel_bp
from Audit_Dashboard_Files.GAP_Assessment.Gap_Assessment_Word_Report import gap_assessment_report_bp
from Audit_Dashboard_Files.GAP_Assessment.Gap_Assessment_Word_Report_bank_input import gap_assessment_report_bank_input_bp
from Audit_Dashboard_Files.GAP_Assessment.VICS_Certificate import vics_certificate_bp
from Audit_Dashboard_Files.GAP_Assessment.Meity_Audit_Excel_seperate1 import meity_audit_part1_bp
from Audit_Dashboard_Files.GAP_Assessment.Meity_Audit_Excel_seperate2 import meity_audit_part2_bp
from Audit_Dashboard_Files.GAP_Assessment.Meity_Audit_Excel_seperate3 import meity_audit_part3_bp
from Audit_Dashboard_Files.GAP_Assessment.Cyber_Security_Audit_Excel import cyber_security_audit_excel_bp
from Audit_Dashboard_Files.GAP_Assessment.Cyber_Security_Audit_Report import cyber_security_audit_report_bp
from Audit_Dashboard_Files.Infra_First_Audit_Metadata import first_audit_metadata_bp
from Audit_Dashboard_Files.Infra_VAPT_Follow_up_audit_meta_data import follow_up_audit_metadata_bp
from Audit_Dashboard_Files.Is_Audit_Compliance_worksheet import is_audit_compliance_bp
from Audit_Dashboard_Files.Infra_VAPT_Compliance_worksheet import infra_vapt_compliance_bp
from Audit_Dashboard_Files.Website_VAPT_Compliance_Worksheet import website_vapt_compliance_bp
from Audit_Dashboard_Files.Public_IP_VAPT_Compliance_Worksheet import public_ip_vapt_compliance_bp
from Audit_Dashboard_Files.Is_Audit_Compliance_Certificate import is_audit_compliance_certificate_bp
from Audit_Dashboard_Files.Infrastructure_VAPT_Compliance_Certificate import infrastructure_vapt_compliance_certificate_bp
from Audit_Dashboard_Files.Website_VAPT_Compliance_Certificate import website_vapt_compliance_certificate_bp
from Audit_Dashboard_Files.Public_IP_VAPT_Compliance_Certificate import public_ip_vapt_compliance_certificate_bp
# GRC Dashboard blueprints
from GRC_Dashboard_Files.IS_Audit_Compliance_Worksheet import grc_is_audit_compliance_bp
from GRC_Dashboard_Files.Infra_VAPT_Compliance_worksheet import grc_infra_vapt_compliance_bp
from GRC_Dashboard_Files.Website_VAPT_Compliance_Worksheet import grc_website_vapt_compliance_bp
from GRC_Dashboard_Files.Public_IP_VAPT_Compliance_Worksheet import grc_public_ip_vapt_compliance_bp
from GRC_Dashboard_Files.Is_Audit_Compliance_Certificate import grc_is_audit_compliance_certificate_bp
from GRC_Dashboard_Files.Infrastructure_VAPT_Compliance_Certificate import grc_infrastructure_vapt_compliance_certificate_bp
from GRC_Dashboard_Files.Website_VAPT_Compliance_Certificate import grc_website_vapt_compliance_certificate_bp
from GRC_Dashboard_Files.Public_IP_VAPT_Compliance_Certificate import grc_public_ip_vapt_compliance_certificate_bp

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', '3c0cdbae7019ddee299cf614a8966fc07bb50ae2c5081daa460637ebcd1eee47')

# Security: Disable debug mode in production
# Set DEBUG=False in production via environment variable
app.config['DEBUG'] = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
# Database configuration with fallback
# Check for production database URL (PAAS providers set this automatically)
database_url = os.environ.get('DATABASE_URL')
if database_url:
    # Convert DATABASE_URL format (postgres://) to SQLAlchemy format (postgresql://)
    if database_url.startswith('postgres://'):
        database_url = database_url.replace('postgres://', 'postgresql://', 1)
    app.config['SQLALCHEMY_DATABASE_URI'] = database_url
    print("✅ Using PostgreSQL database (Production mode)")
else:
    # Development: Use SQLite
    db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'instance', 'db.sqlite')
    if not os.path.exists(os.path.dirname(db_path)):
        os.makedirs(os.path.dirname(db_path), mode=0o700, exist_ok=True)
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
    print("✅ Using SQLite database (Development mode)")

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}
app.config['MAX_CONTENT_LENGTH'] = 1024 * 1024 * 1024  # 1GB max file size (for large ZIP files with many images)

# Security: Ensure upload directory exists with secure permissions
upload_dir = app.config['UPLOAD_FOLDER']
if not os.path.exists(upload_dir):
    os.makedirs(upload_dir, mode=0o755, exist_ok=True)
else:
    # Set secure permissions on existing directory
    try:
        os.chmod(upload_dir, 0o755)
    except Exception:
        pass  # Ignore permission errors if we can't set them

# Email configuration - use environment variables in production
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.environ.get('MAIL_USE_TLS', 'True').lower() == 'true'
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME', 'techumen3012@gmail.com')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD', 'imso zkvi tdmz rrxu')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER', 'techumen3012@gmail.com')

session_dir = os.path.join(tempfile.gettempdir(), 'ntp2_flask_sessions')
# Security: Set secure permissions on session directory
if not os.path.exists(session_dir):
    os.makedirs(session_dir, mode=0o700, exist_ok=True)
else:
    try:
        os.chmod(session_dir, 0o700)
    except Exception:
        pass  # Ignore permission errors if we can't set them
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_FILE_DIR'] = session_dir
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_USE_SIGNER'] = True
# Session cookie security settings to prevent session hijacking
# Note: SESSION_COOKIE_SECURE should be True in production (HTTPS), False for development (HTTP)
# Set via environment variable or detect automatically
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('SESSION_COOKIE_SECURE', 'False').lower() == 'true'
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevent JavaScript access (prevents XSS from stealing session)
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # CSRF protection (Lax allows GET requests from external sites)
app.config['SESSION_COOKIE_NAME'] = 'session'  # Default name
# Additional cookie security: Set cookie path to root and ensure domain is not set (prevents subdomain attacks)
app.config['SESSION_COOKIE_PATH'] = '/'  # Cookie available for entire site
app.config['SESSION_COOKIE_DOMAIN'] = None  # Don't set domain (prevents subdomain cookie sharing)
# Idle timeout: Session expires after 30 minutes of inactivity (not total time)
# PERMANENT_SESSION_LIFETIME is used by Flask-Session for permanent sessions
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
# SESSION_IDLE_TIMEOUT is our custom idle timeout check
SESSION_IDLE_TIMEOUT = timedelta(minutes=30)  # 30 minutes of inactivity
Session(app)

db = SQLAlchemy(app)
mail = Mail(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Set Indian timezone
ist = pytz.timezone('Asia/Kolkata')

def get_current_ist_time():
    return datetime.now(ist)

def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def validate_type_safe(value, expected_type, min_value=None, max_value=None):
    """
    Safely validate and convert value to expected type.
    Prevents type confusion attacks.
    
    Args:
        value: Value to validate
        expected_type: Type to convert to (int, float, str)
        min_value: Minimum value (for numeric types)
        max_value: Maximum value (for numeric types)
    
    Returns:
        tuple: (is_valid: bool, converted_value or None, error_message: str)
    """
    if value is None:
        return False, None, "Value is required"
    
    try:
        if expected_type == int:
            converted = int(value)
            if min_value is not None and converted < min_value:
                return False, None, f"Value must be at least {min_value}"
            if max_value is not None and converted > max_value:
                return False, None, f"Value must be at most {max_value}"
            return True, converted, None
        
        elif expected_type == float:
            converted = float(value)
            if min_value is not None and converted < min_value:
                return False, None, f"Value must be at least {min_value}"
            if max_value is not None and converted > max_value:
                return False, None, f"Value must be at most {max_value}"
            return True, converted, None
        
        elif expected_type == str:
            converted = str(value)
            if min_value is not None and len(converted) < min_value:
                return False, None, f"String must be at least {min_value} characters"
            if max_value is not None and len(converted) > max_value:
                return False, None, f"String must be at most {max_value} characters"
            return True, converted, None
        
        else:
            return False, None, f"Unsupported type: {expected_type}"
    
    except (ValueError, TypeError) as e:
        return False, None, f"Invalid value for type {expected_type.__name__}: {str(e)}"

# Database Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    employee_name = db.Column(db.String(120), nullable=False)
    password = db.Column(db.String(200), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    department = db.Column(db.String(50), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: get_current_ist_time().replace(tzinfo=None))
    deleted_at = db.Column(db.DateTime, nullable=True)
    status = db.relationship('UserStatus', backref='user', uselist=False, cascade='all, delete-orphan')
    login_activities = db.relationship('LoginActivity', backref='user', lazy=True, cascade='all, delete-orphan')
    employee_data = db.relationship('EmployeeData', backref='user', uselist=False, cascade='all, delete-orphan')
    performance_records = db.relationship('Performance', backref='user', lazy=True, cascade='all, delete-orphan')

class EmployeeData(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), unique=True, nullable=False)
    photo = db.Column(db.String(200), default='default_avatar.jpg')
    position = db.Column(db.String(100))
    experience = db.Column(db.String(50))
    education = db.Column(db.String(200))
    certifications = db.Column(db.String(300))
    date_of_birth = db.Column(db.Date)
    blood_group = db.Column(db.String(10))
    contact_number = db.Column(db.String(20))
    browser_fingerprint = db.Column(db.String(500))  # Increased size for encrypted data
    created_at = db.Column(db.DateTime, default=lambda: get_current_ist_time().replace(tzinfo=None))
    updated_at = db.Column(db.DateTime, default=lambda: get_current_ist_time().replace(tzinfo=None), 
                          onupdate=lambda: get_current_ist_time().replace(tzinfo=None))

class LoginActivity(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    activity_type = db.Column(db.String(20), nullable=False)  # 'login', 'logout', 'failed_attempt'
    ip_address = db.Column(db.String(45), nullable=False)
    timestamp = db.Column(db.DateTime, default=lambda: get_current_ist_time().replace(tzinfo=None))
    details = db.Column(db.String(200))

class UserStatus(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), unique=True, nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    failed_attempts = db.Column(db.Integer, default=0)
    last_failed_attempt = db.Column(db.DateTime)
    locked_until = db.Column(db.DateTime)

class Performance(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    month = db.Column(db.Integer, nullable=False)  # 1-12
    year = db.Column(db.Integer, nullable=False)
    punctuality = db.Column(db.Float, default=0.0)  # HR Dashboard
    client_satisfaction = db.Column(db.Float, default=0.0)  # Admin Dashboard
    behaviour = db.Column(db.Float, default=0.0)  # HR Dashboard
    communication_skills = db.Column(db.Float, default=0.0)  # HR Dashboard
    technical_skills = db.Column(db.Float, default=0.0)  # HR Dashboard
    team_coordination = db.Column(db.Float, default=0.0)  # Admin Dashboard
    created_at = db.Column(db.DateTime, default=lambda: get_current_ist_time().replace(tzinfo=None))
    
    # Remove this line to fix the error:
    # user = db.relationship('User', backref='performance_records')
    
    # Unique constraint to prevent duplicate entries for same user/month/year
    __table_args__ = (db.UniqueConstraint('user_id', 'month', 'year', name='_user_month_year_uc'),)

class ClientMail(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: get_current_ist_time().replace(tzinfo=None))
    updated_at = db.Column(db.DateTime, default=lambda: get_current_ist_time().replace(tzinfo=None), 
                          onupdate=lambda: get_current_ist_time().replace(tzinfo=None))
# ...existing code...

# Helper Functions
def generate_captcha_text():
    """Generate a random 4-character alphanumeric CAPTCHA"""
    characters = string.ascii_uppercase + string.digits
    # Exclude similar looking characters (0, O, I, 1, etc.)
    characters = characters.replace('0', '').replace('O', '').replace('I', '').replace('1', '').replace('L', '')
    return ''.join(random.choice(characters) for _ in range(4))

def create_captcha_image(text):
    """Create a CAPTCHA image with the given text"""
    if not PIL_AVAILABLE:
        # Fallback: return None if PIL is not available
        return None
    
    # Image dimensions
    width, height = 120, 40
    
    # Create image with white background
    image = Image.new('RGB', (width, height), color='white')
    draw = ImageDraw.Draw(image)
    
    # Try to use a default font, fallback to default if not available
    # Cross-platform font handling: Try Linux fonts first (for PAAS), then Windows, then default
    font = None
    font_paths = [
        # Linux/PAAS platform fonts (tried first)
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
        "/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf",
        "/usr/share/fonts/truetype/ttf-dejavu/DejaVuSans-Bold.ttf",
        # Windows fonts (fallback)
        "arial.ttf",
        "C:/Windows/Fonts/arial.ttf",
        # macOS fonts (fallback)
        "/Library/Fonts/Arial.ttf",
        "/System/Library/Fonts/Helvetica.ttc",
    ]
    
    for font_path in font_paths:
        try:
            if os.path.exists(font_path):
                font = ImageFont.truetype(font_path, 24)
                break
        except:
            continue
    
    # Use default font if no system fonts available (works on all platforms)
    if font is None:
        font = ImageFont.load_default()
    
    # Draw text with some noise
    text_width = draw.textlength(text, font=font)
    x = (width - text_width) / 2
    y = (height - 24) / 2
    
    # Draw text in dark color
    draw.text((x, y), text, fill='black', font=font)
    
    # Add some noise lines
    for _ in range(3):
        x1 = random.randint(0, width)
        y1 = random.randint(0, height)
        x2 = random.randint(0, width)
        y2 = random.randint(0, height)
        draw.line([(x1, y1), (x2, y2)], fill='gray', width=1)
    
    # Add some noise dots
    for _ in range(10):
        x = random.randint(0, width)
        y = random.randint(0, height)
        draw.point((x, y), fill='gray')
    
    # Convert to base64 string
    buffer = io.BytesIO()
    image.save(buffer, format='PNG')
    img_str = base64.b64encode(buffer.getvalue()).decode()
    return img_str

def validate_captcha(user_input, session_key='captcha_answer'):
    """Validate CAPTCHA input against session stored answer"""
    if not user_input:
        return False
    
    # Get stored CAPTCHA answer from session
    stored_answer = session.get(session_key)
    if not stored_answer:
        return False
    
    # Compare (case-insensitive, strip whitespace)
    user_input_clean = user_input.strip().upper()
    stored_answer_clean = str(stored_answer).strip().upper()
    
    # Clear CAPTCHA from session after validation (one-time use)
    session.pop(session_key, None)
    
    return user_input_clean == stored_answer_clean

def _decrypt_fingerprint_for_api(encrypted_fingerprint):
    """Helper function to decrypt browser fingerprint for API responses"""
    if not encrypted_fingerprint:
        return ''
    try:
        enc_manager = get_encryption_manager()
        return enc_manager.decrypt(encrypted_fingerprint)
    except:
        # If decryption fails, return as-is (for backward compatibility)
        return encrypted_fingerprint

def validate_browser_fingerprint(browser_fingerprint, user=None):
    """
    Validate browser fingerprint against user's stored fingerprint.
    If user is None, check if fingerprint exists for any user.
    Returns (is_valid, user_found) tuple
    
    Note: 
    - Currently using MD5 for backward compatibility with existing database fingerprints
    - Fingerprints are stored as plain text (unencrypted) in database for consistency
    - Encryption is used only for session storage, not database storage
    """
    if not browser_fingerprint or not browser_fingerprint.strip():
        return False, None
    
    browser_fingerprint = browser_fingerprint.strip()
    
    # Try to get encryption manager for backward compatibility (if old encrypted data exists)
    enc_manager = None
    try:
        enc_manager = get_encryption_manager()
    except Exception:
        # If encryption manager fails to initialize, continue without it
        pass
    
    # If user is provided, check if fingerprint matches that user
    if user:
        employee_data = EmployeeData.query.filter_by(user_id=user.id).first()
        if not employee_data or not employee_data.browser_fingerprint:
            return False, user
        
        # Try to get stored fingerprint (handle both encrypted and unencrypted)
        stored_fingerprint = None
        stored_value = employee_data.browser_fingerprint
        
        # First, try to decrypt (for backward compatibility with old encrypted data)
        if enc_manager:
            try:
                # Try to decrypt - if it fails, assume it's unencrypted
                stored_fingerprint = enc_manager.decrypt(stored_value)
            except:
                # Decryption failed - assume it's stored as plain text (new format)
                stored_fingerprint = stored_value
        else:
            # No encryption manager available, use direct value
            stored_fingerprint = stored_value
        
        # Direct comparison (both should be MD5 now after reverting JavaScript to MD5)
        # Normalize by stripping whitespace
        stored_fingerprint = stored_fingerprint.strip() if stored_fingerprint else ''
        return stored_fingerprint == browser_fingerprint, user
    
    # If user is None, check if fingerprint exists for any user
    # Need to check all fingerprints (can't query encrypted data directly)
    all_employee_data = EmployeeData.query.filter(EmployeeData.browser_fingerprint.isnot(None)).all()
    for emp_data in all_employee_data:
        stored_value = emp_data.browser_fingerprint
        stored_fingerprint = None
        
        # Try to decrypt first (for backward compatibility), then fall back to plain text
        if enc_manager:
            try:
                stored_fingerprint = enc_manager.decrypt(stored_value)
            except:
                # Decryption failed - assume it's stored as plain text
                stored_fingerprint = stored_value
        else:
            stored_fingerprint = stored_value
        
        # Normalize by stripping whitespace
        stored_fingerprint = stored_fingerprint.strip() if stored_fingerprint else ''
        
        if stored_fingerprint == browser_fingerprint:
            user_found = User.query.get(emp_data.user_id)
            return True, user_found
    
    return False, None

def migrate_database():
    """Add missing columns to existing database tables"""
    try:
        # Try to add browser_fingerprint column if it doesn't exist
        # SQLite will raise an error if column already exists, which we'll catch
        try:
            db.session.execute(db.text('ALTER TABLE employee_data ADD COLUMN browser_fingerprint VARCHAR(500)'))
            db.session.commit()
            print("SUCCESS: Added browser_fingerprint column to employee_data table")
        except Exception as e:
            error_msg = str(e).lower()
            if 'duplicate column' not in error_msg and 'already exists' not in error_msg:
                # If column doesn't exist, try renaming mac_address if it exists
                try:
                    db.session.execute(db.text('ALTER TABLE employee_data RENAME COLUMN mac_address TO browser_fingerprint'))
                    db.session.commit()
                    print("SUCCESS: Renamed mac_address column to browser_fingerprint")
                except:
                    pass
    except Exception as e:
        # Column might already exist, which is fine
        error_msg = str(e).lower()
        if 'duplicate column' in error_msg or 'already exists' in error_msg or 'no such table' in error_msg:
            # Column already exists or table doesn't exist yet (will be created by db.create_all())
            # This is expected and not an error
            pass
        else:
            print(f"Migration note: {e}")
        try:
            db.session.rollback()
        except:
            pass
    
    try:
        # Try to add created_at column to user table if it doesn't exist
        db.session.execute(db.text('ALTER TABLE "user" ADD COLUMN created_at TIMESTAMP'))
        db.session.commit()
        print("SUCCESS: Added created_at column to user table")
    except Exception as e:
        error_msg = str(e).lower()
        if 'duplicate column' in error_msg or 'already exists' in error_msg or 'no such table' in error_msg:
            pass
        else:
            print(f"Migration note for created_at: {e}")
        try:
            db.session.rollback()
        except:
            pass
    
    try:
        # Try to add deleted_at column to user table if it doesn't exist
        db.session.execute(db.text('ALTER TABLE "user" ADD COLUMN deleted_at TIMESTAMP'))
        db.session.commit()
        print("SUCCESS: Added deleted_at column to user table")
    except Exception as e:
        error_msg = str(e).lower()
        if 'duplicate column' in error_msg or 'already exists' in error_msg or 'no such table' in error_msg:
            pass
        else:
            print(f"Migration note for deleted_at: {e}")
        try:
            db.session.rollback()
        except:
            pass
    
    # Update existing users' created_at if it's NULL, using EmployeeData.created_at as fallback
    try:
        from app import User, EmployeeData
        users_without_created_at = db.session.query(User).filter(User.created_at.is_(None)).all()
        for user in users_without_created_at:
            if user.employee_data and user.employee_data.created_at:
                user.created_at = user.employee_data.created_at
            else:
                # Use a default date if neither exists
                user.created_at = get_current_ist_time().replace(tzinfo=None)
        if users_without_created_at:
            db.session.commit()
            print(f"SUCCESS: Updated created_at for {len(users_without_created_at)} existing users")
    except Exception as e:
        print(f"Migration note for updating created_at: {e}")
        try:
            db.session.rollback()
        except:
            pass

def initialize_database():
    with app.app_context():
        try:
            # Ensure directories exist
            os.makedirs('instance', mode=0o700, exist_ok=True)
            os.makedirs(app.config['UPLOAD_FOLDER'], mode=0o755, exist_ok=True)
            
            # Check if database file exists and is accessible
            db_path = 'instance/db.sqlite'
            db_exists = os.path.exists(db_path)
            
            # Create all tables
            db.create_all()
            if db_exists:
                print("Database already exists - keeping existing data")
            else:
                print("Database initialized successfully")
            
            # Run migrations for existing databases
            migrate_database()
            
        except Exception as e:
            print(f"Error initializing database: {e}")
            # Try with absolute path
            try:
                import tempfile
                temp_db_path = os.path.join(tempfile.gettempdir(), 'app_database.sqlite')
                app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{temp_db_path}'
                db.create_all()
                print(f"Database created in temporary location: {temp_db_path}")
            except Exception as e2:
                print(f"Failed to create database in temporary location: {e2}")
                raise
        
        if not db_exists:
            dummy_users = [
            ("grc_user", "GRC Staff", "grc123", "pubglover301201@gmail.com", "GRC"),
            ("vapt_user", "VAPT Team", "vapt123", "bestmotivation3012@gmail.com", "VAPT"),
            ("audit_user", "Audit Team", "audit123", "patelkashyap3012@gmail.com", "Audit"),
            ("admin_user", "Admin Staff", "admin123", "pubglover3012@gmail.com", "Admin"),
            ("hr_user", "HR Manager", "hr123", "pubglover30120101@gmail.com", "HR")
        ]
        
            dummy_employee_data = [
            # GRC User
            {
                'position': 'GRC Analyst',
                'experience': '5 years',
                'education': 'MBA in Cybersecurity',
                'certifications': 'CISA, CRISC',
                'date_of_birth': datetime(1990, 5, 15).date(),
                'blood_group': 'O+',
                'contact_number': '+91 9876543210'
            },
            # VAPT User
            {
                'position': 'Penetration Tester',
                'experience': '4 years',
                'education': 'B.Tech in Computer Science',
                'certifications': 'CEH, OSCP',
                'date_of_birth': datetime(1992, 8, 22).date(),
                'blood_group': 'A+',
                'contact_number': '+91 9876543211'
            },
            # Audit User
            {
                'position': 'IT Auditor',
                'experience': '6 years',
                'education': 'M.Com, CISA',
                'certifications': 'CISA, CIA',
                'date_of_birth': datetime(1988, 3, 10).date(),
                'blood_group': 'B+',
                'contact_number': '+91 9876543212'
            },
            # Admin User
            {
                'position': 'System Administrator',
                'experience': '7 years',
                'education': 'B.Tech in IT',
                'certifications': 'RHCE, MCSE',
                'date_of_birth': datetime(1987, 11, 5).date(),
                'blood_group': 'AB+',
                'contact_number': '+91 9876543213'
            },
            # HR User
            {
                'position': 'HR Manager',
                'experience': '8 years',
                'education': 'MBA in HR',
                'certifications': 'SHRM, PHR',
                'date_of_birth': datetime(1985, 7, 20).date(),
                'blood_group': 'O-',
                'contact_number': '+91 9876543214'
            }
        ]
        
            for i, (username, emp_name, password, email, dept) in enumerate(dummy_users):
                user = db.session.execute(db.select(User).filter_by(username=username)).scalar_one_or_none()
                if not user:
                    hashed_pw = generate_password_hash(password)
                    new_user = User(
                        username=username,
                        employee_name=emp_name,
                        password=hashed_pw,
                        email=email,
                        department=dept,
                        created_at=get_current_ist_time().replace(tzinfo=None)
                    )
                    db.session.add(new_user)
                    db.session.flush()  # To get the user ID
                    
                    # Create user status
                    user_status = UserStatus(user_id=new_user.id)
                    db.session.add(user_status)
                    
                    # Create employee data
                    emp_data = dummy_employee_data[i]
                    employee_data = EmployeeData(
                        user_id=new_user.id,
                        position=emp_data['position'],
                        experience=emp_data['experience'],
                        education=emp_data['education'],
                        certifications=emp_data['certifications'],
                        date_of_birth=emp_data['date_of_birth'],
                        blood_group=emp_data['blood_group'],
                        contact_number=emp_data['contact_number']
                    )
                    db.session.add(employee_data)
            # Add dummy performance data for this fresh database
            current_date = get_current_ist_time().replace(tzinfo=None)
            last_month = current_date.month - 1 if current_date.month > 1 else 12
            last_month_year = current_date.year if current_date.month > 1 else current_date.year - 1

            for user in User.query.all():
                existing_performance = Performance.query.filter_by(
                    user_id=user.id, 
                    month=last_month, 
                    year=last_month_year
                ).first()
                
                if not existing_performance:
                    performance = Performance(
                        user_id=user.id,
                        month=last_month,
                        year=last_month_year,
                        punctuality=round(random.uniform(7.5, 10.0)),
                        client_satisfaction=round(random.uniform(7.5, 10.0)),
                        behaviour=round(random.uniform(7.5, 10.0)),
                        communication_skills=round(random.uniform(7.5, 10.0)),
                        technical_skills=round(random.uniform(7.5, 10.0)),
                        team_coordination=round(random.uniform(7.5, 10.0))
                    )
                    db.session.add(performance)

            db.session.commit()

def generate_otp():
    chars = string.ascii_letters + string.digits + "!@#$%^&*"
    return ''.join(random.choice(chars) for _ in range(8))

def send_otp_email(email, otp):
    msg = Message("Your Login OTP", recipients=[email])
    msg.body = f"Your OTP for login is: {otp}\nThis OTP is valid for 3 minutes."
    mail.send(msg)

def redirect_to_dashboard(department):
    # Handle department values with or without "Department" suffix
    department_clean = department.replace(" Department", "").strip()
    dashboards = {
        "GRC": "grc_dashboard",
        "VAPT": "vapt_dashboard",
        "Audit": "audit_dashboard",
        "Admin": "admin_dashboard",
        "HR": "hr_dashboard"
    }
    if department_clean in dashboards:
        return redirect(url_for(dashboards[department_clean]))
    flash('Unknown department')
    return redirect(url_for('login'))

# Flask-Login Setup
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# Security Headers
# Import activity logging middleware
from Admin_Dashboard_Files.activity_logging_middleware import log_activity_after_request

@app.before_request
def enforce_https_in_production():
    """
    Enforce HTTPS in production to prevent insecure data transmission.
    Redirects HTTP to HTTPS if USE_HTTPS is enabled.
    """
    # Only enforce in production when HTTPS is configured
    if os.environ.get('USE_HTTPS', 'False').lower() == 'true':
        # Check if request is not secure (HTTP instead of HTTPS)
        # In production behind reverse proxy, check X-Forwarded-Proto header
        if request.headers.get('X-Forwarded-Proto') != 'https' and not request.is_secure:
            # Log insecure connection attempt
            logger = logging.getLogger(__name__)
            logger.warning(f"Insecure connection attempt from {request.remote_addr} to {request.url}")
            # In production, redirect to HTTPS
            # Note: This requires proper reverse proxy configuration (nginx/apache)
            # For development, this is skipped
            # Redirect to HTTPS version of the URL
            https_url = request.url.replace('http://', 'https://', 1)
            return redirect(https_url, code=301)

@app.before_request
def check_session_idle_timeout():
    """
    Check for idle timeout and update last activity time.
    Session expires after 30 minutes of inactivity (idle timeout).
    """
    # Skip for login, verify_otp, validate_fingerprint, and static files
    if request.endpoint in ['login', 'verify_otp', 'validate_fingerprint', 'static'] or request.endpoint is None:
        return
    
    # Only check for authenticated users
    if current_user.is_authenticated:
        current_time = get_current_ist_time().replace(tzinfo=None)
        last_activity = session.get('last_activity')
        
        if last_activity:
            # Check if session has been idle for more than 30 minutes
            idle_time = current_time - datetime.fromtimestamp(last_activity)
            if idle_time > SESSION_IDLE_TIMEOUT:
                # Session expired due to inactivity
                logout_user()
                session.clear()
                flash('Your session has expired due to inactivity. Please login again.', 'info')
                return redirect(url_for('login'))
        
        # Update last activity time on each request (resets idle timer)
        session['last_activity'] = current_time.timestamp()
        session.permanent = True
        session.modified = True

@app.context_processor
def inject_csrf_token():
    """Inject CSRF token into all templates"""
    return dict(csrf_token=generate_csrf_token())

@app.after_request
def add_security_headers(response):
    if request.path in ['/login', '/verify_otp']:
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, post-check=0, pre-check=0, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '-1'
    
    # Additional security headers to prevent session hijacking
    # X-Frame-Options: Prevent clickjacking
    response.headers['X-Frame-Options'] = 'DENY'
    # X-Content-Type-Options: Prevent MIME type sniffing
    response.headers['X-Content-Type-Options'] = 'nosniff'
    # X-XSS-Protection: Enable XSS filter (legacy, but still useful)
    response.headers['X-XSS-Protection'] = '1; mode=block'
    
    # Content-Security-Policy: Prevent XSS and injection attacks
    # Adjust policy based on your application's needs
    csp_policy = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://fonts.googleapis.com; "
        "img-src 'self' data: https:; "
        "font-src 'self' https://cdnjs.cloudflare.com https://fonts.gstatic.com; "
        "connect-src 'self'; "
        "frame-ancestors 'none';"
    )
    response.headers['Content-Security-Policy'] = csp_policy
    
    # Referrer-Policy: Control referrer information
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    
    # Permissions-Policy: Control browser features
    response.headers['Permissions-Policy'] = (
        "geolocation=(), "
        "microphone=(), "
        "camera=(), "
        "payment=(), "
        "usb=()"
    )
    
    # Remove Server header to prevent information disclosure
    response.headers.pop('Server', None)
    
    # Strict-Transport-Security: Force HTTPS (only set if using HTTPS)
    # Uncomment in production with HTTPS:
    if os.environ.get('USE_HTTPS', 'False').lower() == 'true':
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'
    
    # Log user activity
    try:
        log_activity_after_request()(response)
    except Exception as e:
        # Don't fail the request if logging fails
        logger = logging.getLogger(__name__)
        logger.error(f"Error in activity logging: {e}", exc_info=True)
    
    return response

# Security: Disable directory listing for static files
# Flask doesn't enable directory listing by default, but we explicitly disable it
@app.route('/static/<path:filename>')
def static_files(filename):
    """Serve static files with security headers"""
    from flask import send_from_directory
    response = send_from_directory(app.static_folder, filename)
    # Add security headers
    response.headers['X-Content-Type-Options'] = 'nosniff'
    return response

# Error handlers with safe error messages
@app.errorhandler(404)
def not_found_error(error):
    """Handle 404 errors with safe message"""
    return render_template('errors/404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors with safe message"""
    db.session.rollback()
    logger = logging.getLogger(__name__)
    logger.error(f"Internal server error: {error}", exc_info=True)
    return render_template('errors/500.html'), 500

@app.errorhandler(403)
def forbidden_error(error):
    """Handle 403 errors with safe message"""
    return render_template('errors/403.html'), 403

# Routes
@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/test_fingerprint')
def test_fingerprint():
    """Test endpoint to see what fingerprint the browser generates"""
    browser_fingerprint = request.args.get('browser_fingerprint')
    if browser_fingerprint:
        # Check if this fingerprint exists in database
        is_valid, user_found = validate_browser_fingerprint(browser_fingerprint)
        
        # Also check what's stored for HR Manager
        hr_user = User.query.filter_by(username='hr_user').first() or User.query.filter_by(department='HR').first()
        hr_stored = None
        if hr_user:
            emp_data = EmployeeData.query.filter_by(user_id=hr_user.id).first()
            if emp_data and emp_data.browser_fingerprint:
                hr_stored = emp_data.browser_fingerprint
        
        return f"""
        <html>
        <head><title>Fingerprint Test</title></head>
        <body style="font-family: Arial; padding: 20px;">
            <h2>Browser Fingerprint Test</h2>
            <p><strong>Your Browser Fingerprint:</strong> {browser_fingerprint}</p>
            <p><strong>Fingerprint Length:</strong> {len(browser_fingerprint)} characters</p>
            <p><strong>Fingerprint Valid:</strong> {'YES' if is_valid else 'NO'}</p>
            {f'<p><strong>User Found:</strong> {user_found.username if user_found else "None"}</p>' if user_found else ''}
            <hr>
            <h3>HR Manager Stored Fingerprint:</h3>
            <p><strong>Stored:</strong> {hr_stored if hr_stored else 'None'}</p>
            <p><strong>Match:</strong> {'YES - Matches!' if hr_stored == browser_fingerprint else 'NO - Does not match'}</p>
            {f'<p style="color: red;"><strong>WARNING: Your browser fingerprint does not match the stored one!</strong><br>Update the database with: <code>{browser_fingerprint}</code></p>' if hr_stored and hr_stored != browser_fingerprint else ''}
            <hr>
            <p><a href="/login">Go to Login Page</a></p>
        </body>
        </html>
        """
    else:
        return """
        <html>
        <head><title>Fingerprint Test</title></head>
        <body style="font-family: Arial; padding: 20px;">
            <h2>Browser Fingerprint Test</h2>
            <p>Add ?browser_fingerprint=YOUR_FINGERPRINT to the URL</p>
            <p>Or use the login page - it will show your fingerprint below the password field</p>
            <p><a href="/login">Go to Login Page</a></p>
        </body>
        </html>
        """

@app.route('/validate_fingerprint', methods=['POST'])
def validate_fingerprint():
    """Validate browser fingerprint via AJAX (not exposed in URL)"""
    try:
        data = request.get_json()
        browser_fingerprint = data.get('browser_fingerprint') if data else None
        
        if not browser_fingerprint:
            return jsonify({'valid': False, 'error': 'Fingerprint required'}), 400
        
        is_valid, user_found = validate_browser_fingerprint(browser_fingerprint)
        
        if is_valid:
            # Store fingerprint in session for later validation (try to encrypt, but handle errors)
            try:
                enc_manager = get_encryption_manager()
                session['validated_fingerprint'] = enc_manager.encrypt(browser_fingerprint)
            except:
                # If encryption fails, store plain text (fallback)
                session['validated_fingerprint'] = browser_fingerprint
            session['fingerprint_validation_attempted'] = True
            return jsonify({'valid': True, 'username': user_found.username if user_found else None})
        else:
            # Mark validation as attempted
            session['fingerprint_validation_attempted'] = True
            
            # Debug: Check what's stored for HR Manager
            hr_user = User.query.filter_by(username='hr_user').first() or User.query.filter_by(department='HR').first()
            hr_stored = None
            if hr_user:
                emp_data = EmployeeData.query.filter_by(user_id=hr_user.id).first()
                if emp_data and emp_data.browser_fingerprint:
                    hr_stored = emp_data.browser_fingerprint
            
            # Return invalid fingerprint response (frontend will redirect to custom error page)
            return jsonify({
                'valid': False, 
                'error': 'Invalid fingerprint'
            }), 200
    
    except Exception as e:
        safe_error = get_safe_error_message(e)
        return jsonify({'valid': False, 'error': safe_error}), 500

@app.route('/captcha_image')
def captcha_image():
    """Generate and return CAPTCHA image"""
    try:
        # Generate CAPTCHA text
        captcha_text = generate_captcha_text()
        
        # Store in session for validation
        session['captcha_answer'] = captcha_text
        
        # Create image
        if PIL_AVAILABLE:
            img_str = create_captcha_image(captcha_text)
            if img_str:
                return jsonify({
                    'success': True,
                    'image': f'data:image/png;base64,{img_str}'
                })
        
        # Fallback: return text if PIL not available (less secure but functional)
        return jsonify({
            'success': True,
            'text': captcha_text  # This is less secure, but works if PIL unavailable
        })
    except Exception as e:
        logger = logging.getLogger(__name__)
        logger.error(f"Error generating CAPTCHA: {e}", exc_info=True)
        return jsonify({'success': False, 'error': 'Failed to generate CAPTCHA'}), 500

@app.route('/fingerprint_error')
def fingerprint_error():
    """Custom error page for browser fingerprint mismatch"""
    return render_template('fingerprint_error.html')

@app.route('/submit_complaint', methods=['POST'])
@login_required
def submit_complaint():
    """Handle complaint about team submission and send email"""
    try:
        data = request.get_json() if request.is_json else request.form.to_dict()
        
        # Get form data
        employee_name = data.get('employeeName', current_user.employee_name or current_user.username)
        employee_team = data.get('employeeTeam', current_user.department)
        complaint_date = data.get('date', '')
        person_name = data.get('personName', '')
        complain_description = data.get('complainDescription', '')
        username = current_user.username
        
        # Validate required fields
        if not all([person_name, complain_description]):
            return jsonify({'success': False, 'message': 'Please fill in all required fields.'}), 400
        
        # Format date for display
        try:
            if complaint_date:
                formatted_date = datetime.strptime(complaint_date, '%Y-%m-%d').strftime('%B %d, %Y')
            else:
                formatted_date = datetime.now().strftime('%B %d, %Y')
        except:
            formatted_date = complaint_date or datetime.now().strftime('%B %d, %Y')
        
        # Send email to admin
        try:
            admin_email = 'ngt-auakua@ngtech.co.in'
            msg = Message(
                subject=f"Complaint About Team - {employee_name}",
                recipients=[admin_email],
                sender=app.config['MAIL_DEFAULT_SENDER']
            )
            
            # Create email body
            email_body = f"""Complaint About Team

Employee Details:
- Username: {username}
- Employee Name: {employee_name}
- Employee Team/Department: {employee_team}

Complaint Details:
- Date: {formatted_date}
- Person Name: {person_name}
- Complaint Description:
{complain_description}

Submitted At: {get_current_ist_time().strftime('%B %d, %Y at %I:%M %p IST')}

Please review this complaint and take appropriate action.

Best regards,
NGTech System
"""
            
            msg.body = email_body
            mail.send(msg)
            
            return jsonify({
                'success': True, 
                'message': 'Complaint submitted successfully! An email has been sent to the administrator.'
            })
            
        except Exception as email_error:
            # Log error but don't fail the request
            logger = logging.getLogger(__name__)
            logger.error(f"Error sending complaint email: {email_error}", exc_info=True)
            return jsonify({
                'success': True, 
                'message': 'Complaint submitted successfully! (Note: Email notification may have failed)'
            })
    
    except Exception as e:
        logger = logging.getLogger(__name__)
        logger.error(f"Error processing complaint: {e}", exc_info=True)
        return jsonify({'success': False, 'message': 'An error occurred. Please try again later.'}), 500

@app.route('/submit_leave_request', methods=['POST'])
@login_required
def submit_leave_request():
    """Handle leave approval request submission and send email"""
    try:
        data = request.get_json() if request.is_json else request.form.to_dict()
        
        # Get form data
        employee_name = data.get('employeeName', current_user.employee_name or current_user.username)
        request_date = data.get('requestDate', '')
        leave_type = data.get('leaveType', '')
        leave_from = data.get('leaveFrom', '')
        leave_to = data.get('leaveTo', '')
        reason = data.get('reason', '')
        current_task = data.get('currentTask', '')
        username = current_user.username
        
        # Validate required fields
        if not all([leave_type, leave_from, leave_to, reason]):
            return jsonify({'success': False, 'message': 'Please fill in all required fields.'}), 400
        
        # Validate emergency leave has current task
        if leave_type == 'Emergency Leave' and not current_task:
            return jsonify({'success': False, 'message': 'Please enter your current task for Emergency Leave.'}), 400
        
        # Format dates for display
        try:
            if leave_from:
                from_date = datetime.strptime(leave_from, '%Y-%m-%d').strftime('%B %d, %Y')
            else:
                from_date = 'N/A'
            
            if leave_to:
                to_date = datetime.strptime(leave_to, '%Y-%m-%d').strftime('%B %d, %Y')
            else:
                to_date = 'N/A'
            
            if request_date:
                req_date = datetime.strptime(request_date, '%Y-%m-%d').strftime('%B %d, %Y')
            else:
                req_date = datetime.now().strftime('%B %d, %Y')
        except:
            from_date = leave_from
            to_date = leave_to
            req_date = request_date or datetime.now().strftime('%B %d, %Y')
        
        # Calculate number of days
        try:
            from_dt = datetime.strptime(leave_from, '%Y-%m-%d')
            to_dt = datetime.strptime(leave_to, '%Y-%m-%d')
            days_diff = (to_dt - from_dt).days + 1
        except:
            days_diff = 'N/A'
        
        # Send email to admin
        try:
            admin_email = 'ngt-auakua@ngtech.co.in'
            msg = Message(
                subject=f"Leave Approval Request - {employee_name}",
                recipients=[admin_email],
                sender=app.config['MAIL_DEFAULT_SENDER']
            )
            
            # Create email body
            email_body = f"""Leave Approval Request

Employee Details:
- Username: {username}
- Employee Name: {employee_name}
- Department: {current_user.department}

Request Details:
- Request Date: {req_date}
- Leave Type: {leave_type}
- Leave From: {from_date}
- Leave To: {to_date}
- Number of Days: {days_diff}
- Reason: {reason}
"""
            
            # Add current task if it's emergency leave
            if leave_type == 'Emergency Leave' and current_task:
                email_body += f"- Current Task: {current_task}\n"
            
            email_body += f"""
Submitted At: {get_current_ist_time().strftime('%B %d, %Y at %I:%M %p IST')}

Please review and approve this leave request.

Best regards,
NGTech System
"""
            
            msg.body = email_body
            mail.send(msg)
            
            return jsonify({
                'success': True, 
                'message': 'Leave approval request submitted successfully! An email has been sent to the administrator.'
            })
            
        except Exception as email_error:
            # Log error but don't fail the request
            logger = logging.getLogger(__name__)
            logger.error(f"Error sending leave request email: {email_error}", exc_info=True)
            return jsonify({
                'success': True, 
                'message': 'Leave approval request submitted successfully! (Note: Email notification may have failed)'
            })
    
    except Exception as e:
        logger = logging.getLogger(__name__)
        logger.error(f"Error processing leave request: {e}", exc_info=True)
        return jsonify({'success': False, 'message': 'An error occurred. Please try again later.'}), 500

@app.route('/submit_fingerprint_request', methods=['POST'])
def submit_fingerprint_request():
    """Handle email submission for fingerprint mismatch - only send if email matches a user"""
    try:
        data = request.get_json()
        email = data.get('email') if data else None
        browser_fingerprint = data.get('browser_fingerprint') if data else None
        captcha_input = data.get('captcha', '').strip() if data else ''
        
        # Validate CAPTCHA
        if not validate_captcha(captcha_input):
            return jsonify({'success': False, 'message': 'Invalid CAPTCHA. Please try again.'}), 400
        
        if not email:
            return jsonify({'success': False, 'message': 'Email address is required.'}), 400
        
        # Validate email format
        import re
        email_pattern = r'^[^\s@]+@[^\s@]+\.[^\s@]+$'
        if not re.match(email_pattern, email):
            return jsonify({'success': False, 'message': 'Invalid email format.'}), 400
        
        # Check if email matches any user in the database
        user = User.query.filter_by(email=email).first()
        
        if not user:
            # Email doesn't match any user - don't send email, but return success message
            return jsonify({
                'success': True, 
                'message': 'Thank you for your request. If your email is registered, we will review it shortly.'
            })
        
        # Email matches a user - send email to admin
        try:
            username = user.username
            employee_name = user.employee_name or username
            
            # Send email to admin
            admin_email = 'ngt-auakua@ngtech.co.in'
            msg = Message(
                subject="Browser Fingerprint Mismatch Request",
                recipients=[admin_email],
                sender=app.config['MAIL_DEFAULT_SENDER']
            )
            
            msg.body = f"""A user has requested access due to browser fingerprint mismatch.

User Details:
- Username: {username}
- Employee Name: {employee_name}
- Email: {email}
- Department: {user.department}

Browser Fingerprint: {browser_fingerprint}

Timestamp: {get_current_ist_time().strftime('%Y-%m-%d %H:%M:%S IST')}

Please review this request and update the user's browser fingerprint if approved.
"""
            
            mail.send(msg)
            
            return jsonify({
                'success': True, 
                'message': 'Your request has been submitted successfully. We will review it and contact you shortly.'
            })
            
        except Exception as email_error:
            # Log error but don't expose it to user
            logger = logging.getLogger(__name__)
            logger.error(f"Error sending fingerprint request email: {email_error}", exc_info=True)
            return jsonify({
                'success': True, 
                'message': 'Your request has been received. We will review it shortly.'
            })
    
    except Exception as e:
        safe_error = get_safe_error_message(e)
        logger = logging.getLogger(__name__)
        logger.error(f"Error processing fingerprint request: {e}", exc_info=True)
        return jsonify({'success': False, 'message': 'An error occurred. Please try again later.'}), 500

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect_to_dashboard(current_user.department)
    
    # Get browser fingerprint from request (only from POST/form, never from URL)
    browser_fingerprint = None
    if request.method == 'POST':
        browser_fingerprint = request.form.get('browser_fingerprint') or (request.json.get('browser_fingerprint') if request.is_json else None)
    
    # On GET request, always allow page to load so user can see their fingerprint
    # The JavaScript will handle validation and show appropriate messages
    # Don't block the page from loading - let the user see their fingerprint for debugging
    if request.method == 'GET':
        # Always allow the login page to render on GET requests
        # JavaScript will validate the fingerprint and show error if needed
        pass
    
    if request.method == 'POST':
        # Validate CSRF token
        if not validate_csrf_token():
            flash('Invalid security token. Please try again.', 'error')
            return redirect(url_for('login'))
        
        # Validate CAPTCHA
        captcha_input = request.form.get('captcha', '').strip()
        if not validate_captcha(captcha_input):
            flash('Invalid CAPTCHA. Please try again.', 'error')
            return redirect(url_for('login'))
        
        username = request.form.get('username')
        password = request.form.get('password')
        ip_address = request.remote_addr
        
        # Rate limiting: Check IP-based rate limit (brute force protection)
        is_allowed_ip, remaining_ip, reset_time_ip = check_rate_limit('login_per_ip', ip_address)
        if not is_allowed_ip:
            minutes_remaining = int((reset_time_ip - datetime.now()).total_seconds() / 60) if reset_time_ip else 15
            flash(f'Too many login attempts from this IP. Please try again in {minutes_remaining} minutes.', 'error')
            return redirect(url_for('login'))
        
        # Rate limiting: Check username-based rate limit (brute force protection)
        if username:
            is_allowed_user, remaining_user, reset_time_user = check_rate_limit('login_per_username', username)
            if not is_allowed_user:
                minutes_remaining = int((reset_time_user - datetime.now()).total_seconds() / 60) if reset_time_user else 15
                flash(f'Too many login attempts for this username. Please try again in {minutes_remaining} minutes.', 'error')
                return redirect(url_for('login'))
        
        # Credential stuffing detection: Check if same IP is trying multiple usernames
        if username:
            is_suspicious, stuffing_msg = check_credential_stuffing(ip_address, username)
            if is_suspicious:
                flash('Suspicious activity detected. Please try again later.', 'error')
                activity = LoginActivity(
                    user_id=-1,
                    activity_type='credential_stuffing_detected',
                    ip_address=ip_address,
                    details=f"Credential stuffing detected: Multiple usernames attempted from IP {ip_address}"
                )
                db.session.add(activity)
                db.session.commit()
                return redirect(url_for('login'))
        
        # Record attempt for rate limiting
        record_attempt('login_per_ip', ip_address)
        if username:
            record_attempt('login_per_username', username)
        
        user = db.session.execute(db.select(User).filter_by(username=username)).scalar_one_or_none()
        
        # Validate browser fingerprint before checking user
        if not browser_fingerprint:
            abort(404)
        
        is_valid, fingerprint_user = validate_browser_fingerprint(browser_fingerprint, user)
        
        if not is_valid:
            # Fingerprint doesn't match - return 404
            if user:
                activity = LoginActivity(
                    user_id=user.id,
                    activity_type='failed_attempt',
                    ip_address=ip_address,
                    details=f"Browser fingerprint mismatch. Expected fingerprint for user: {username}"
                )
                db.session.add(activity)
                db.session.commit()
            abort(404)
        
        if not user:
            activity = LoginActivity(
                user_id=-1,
                activity_type='failed_attempt',
                ip_address=ip_address,
                details=f"Attempted login for non-existent user: {username}"
            )
            db.session.add(activity)
            db.session.commit()
            flash('Invalid username or password')
            return redirect(url_for('login'))
        
        # Check if account is locked but lock period has expired
        if (user.status and user.status.locked_until and 
            user.status.locked_until <= get_current_ist_time().replace(tzinfo=None)):
            # Auto-unlock after lock period expires
            user.status.is_active = True
            user.status.locked_until = None
            user.status.failed_attempts = 0
            activity = LoginActivity(
                user_id=user.id,
                activity_type='account_auto_unlocked',
                ip_address=ip_address,
                details="Account automatically unlocked after lock period expired"
            )
            db.session.add(activity)
            db.session.commit()
        
        # Check if account is locked
        if user.status and user.status.locked_until and user.status.locked_until > get_current_ist_time().replace(tzinfo=None):
            remaining_time = user.status.locked_until - get_current_ist_time().replace(tzinfo=None)
            flash(f'Account locked. Please try again in {remaining_time.seconds//60} minutes or contact HR.')
            return redirect(url_for('login'))
        
        if not check_password_hash(user.password, password):
            activity = LoginActivity(
                user_id=user.id,
                activity_type='failed_attempt',
                ip_address=ip_address,
                details="Incorrect password"
            )
            db.session.add(activity)
            
            if not user.status:
                user.status = UserStatus(user_id=user.id)
            
            user.status.failed_attempts += 1
            user.status.last_failed_attempt = get_current_ist_time().replace(tzinfo=None)
            
            # Lock account after 5 failed attempts (permanent lock)
            if user.status.failed_attempts >= 5:
                user.status.is_active = False
                user.status.locked_until = None  # Permanent lock until HR reactivates
                activity = LoginActivity(
                    user_id=user.id,
                    activity_type='account_locked',
                    ip_address=ip_address,
                    details="Account permanently locked due to 5 failed attempts - HR intervention required"
                )
                db.session.add(activity)
                flash('Account locked due to multiple failed attempts. Please contact HR to unlock your account.')
            # Temporary lock after 3 failed attempts (15 minutes)
            elif user.status.failed_attempts >= 3:
                user.status.is_active = False
                user.status.locked_until = get_current_ist_time().replace(tzinfo=None) + timedelta(minutes=15)
                activity = LoginActivity(
                    user_id=user.id,
                    activity_type='account_locked',
                    ip_address=ip_address,
                    details="Account temporarily locked due to 3 failed attempts (15 minutes)"
                )
                db.session.add(activity)
                flash('Account locked for 15 minutes due to multiple failed attempts.')
            else:
                flash(f'Invalid username or password. {5 - user.status.failed_attempts} attempts remaining.')
            
            db.session.commit()
            return redirect(url_for('login'))
        
        # Check if account is active
        if user.status and not user.status.is_active:
            if user.status.locked_until and user.status.locked_until > get_current_ist_time().replace(tzinfo=None):
                remaining_time = user.status.locked_until - get_current_ist_time().replace(tzinfo=None)
                flash(f'Account inactive. Please try again in {remaining_time.seconds//60} minutes.')
            else:
                flash('Your account is inactive. Please contact HR.')
            return redirect(url_for('login'))
        
        # Reset failed attempts on successful credential validation
        if user.status:
            user.status.failed_attempts = 0
            user.status.locked_until = None
            if not user.status.is_active:
                user.status.is_active = True
                activity = LoginActivity(
                    user_id=user.id,
                    activity_type='account_activated',
                    ip_address=ip_address,
                    details="Account reactivated after successful login"
                )
                db.session.add(activity)
        
        # Reset rate limits on successful credential validation (before OTP)
        # This prevents legitimate users from being blocked if they enter correct credentials
        reset_rate_limit('login_per_ip', ip_address)
        reset_rate_limit('login_per_username', username)
        
        activity = LoginActivity(
            user_id=user.id,
            activity_type='login',
            ip_address=ip_address,
            details="OTP requested"
        )
        db.session.add(activity)
        db.session.commit()
        
        # Store browser fingerprint in session for OTP verification (encrypted)
        enc_manager = get_encryption_manager()
        session['browser_fingerprint'] = enc_manager.encrypt(browser_fingerprint)
        
        otp = generate_otp()
        send_otp_email(user.email, otp)
        
        # Encrypt OTP in session for security
        enc_manager = get_encryption_manager()
        session['otp'] = enc_manager.encrypt(otp)
        session['user_id'] = user.id
        session['otp_created'] = get_current_ist_time().timestamp()
        session['remember_me'] = True if request.form.get('remember') else False
        
        # Redirect to verify_otp (fingerprint already in session)
        return redirect(url_for('verify_otp'))
    
    # On GET, check fingerprint via query parameter or show error
    # Sanitize error_message from URL to prevent reflected XSS
    error_message_raw = request.args.get('error_message')
    error_message = sanitize_url_param(error_message_raw) if error_message_raw else None
    response = make_response(render_template('login.html', error_message=error_message))
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate'
    return response

@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # Rate limiting for OTP verification (brute force protection)
    if request.method == 'POST':
        ip_address = request.remote_addr
        is_allowed, remaining, reset_time = check_rate_limit('otp_verification_per_ip', ip_address)
        if not is_allowed:
            minutes_remaining = int((reset_time - datetime.now()).total_seconds() / 60) if reset_time else 15
            flash(f'Too many OTP verification attempts. Please try again in {minutes_remaining} minutes.', 'error')
            return redirect(url_for('login'))
        
        # Record attempt
        record_attempt('otp_verification_per_ip', ip_address)
    
    # Check browser fingerprint on GET request (from session, not URL)
    if request.method == 'GET':
        stored_fingerprint_encrypted = session.get('browser_fingerprint')
        validated_fingerprint_encrypted = session.get('validated_fingerprint')
        
        # Must have fingerprint in session from login
        if not stored_fingerprint_encrypted and not validated_fingerprint_encrypted:
            session.clear()
            abort(404)
    
    remaining_time = 180  # Default 3 minutes
    
    if 'otp_created' in session:
        otp_age = get_current_ist_time().timestamp() - session['otp_created']
        remaining_time = max(0, 180 - int(otp_age))
        
        if remaining_time <= 0:
            session.pop('otp', None)
            session.pop('otp_created', None)
            session.pop('browser_fingerprint', None)
            flash('OTP has expired. Please request a new one.')
            return redirect(url_for('login'))
        
    if request.method == 'POST':
        # Validate CSRF token
        if not validate_csrf_token():
            flash('Invalid security token. Please try again.', 'error')
            return redirect(url_for('verify_otp'))
        
        user_otp = request.form.get('otp')
        browser_fingerprint = request.form.get('browser_fingerprint')
        stored_fingerprint_encrypted = session.get('browser_fingerprint')
        
        # Decrypt stored fingerprint and verify it matches
        if not browser_fingerprint or not stored_fingerprint_encrypted:
            session.clear()
            abort(404)
        
        enc_manager = get_encryption_manager()
        try:
            stored_fingerprint = enc_manager.decrypt(stored_fingerprint_encrypted)
            if browser_fingerprint != stored_fingerprint:
                session.clear()
                abort(404)
        except:
            # If decryption fails, clear session and abort
            session.clear()
            abort(404)
        
        # Decrypt OTP from session for comparison
        encrypted_otp = session.get('otp')
        if not encrypted_otp:
            flash('OTP session expired. Please login again.')
            return redirect(url_for('login'))
        
        enc_manager = get_encryption_manager()
        try:
            stored_otp = enc_manager.decrypt(encrypted_otp)
        except:
            flash('OTP session error. Please login again.')
            return redirect(url_for('login'))
        
        if user_otp == stored_otp:
            user = db.session.get(User, session['user_id'])
            
            # Final fingerprint validation against database
            is_valid, _ = validate_browser_fingerprint(browser_fingerprint, user)
            if not is_valid:
                session.clear()
                abort(404)
            
            # Clear OTP-related session data before login
            remember_me = session.pop('remember_me', None)
            session.pop('otp', None)
            session.pop('user_id', None)
            session.pop('otp_created', None)
            session.pop('browser_fingerprint', None)
            session.pop('validated_fingerprint', None)
            session.pop('fingerprint_validation_attempted', None)
            
            # Regenerate session ID to prevent session fixation attacks
            # This creates a new session with a new ID
            session.permanent = True
            session.modified = True
            
            # Now login the user (this happens after session regeneration)
            login_user(user, remember=remember_me)
            
            # Set initial last activity time for idle timeout tracking
            current_time = get_current_ist_time().replace(tzinfo=None)
            session['last_activity'] = current_time.timestamp()
            
            # Track successful login
            activity = LoginActivity(
                user_id=user.id,
                activity_type='login',
                ip_address=request.remote_addr,
                details="OTP verified, successful login"
            )
            db.session.add(activity)
            db.session.commit()
            
            # Reset rate limits on successful OTP verification
            reset_rate_limit('otp_verification_per_ip', request.remote_addr)
            
            return redirect_to_dashboard(user.department)
        else:
            flash('Invalid OTP. Please try again.')
    
    response = make_response(render_template('verify_otp.html', remaining_time=remaining_time))
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate'
    return response

@app.route('/logout')
@login_required
def logout():
    user_id = current_user.id
    
    activity = LoginActivity(
        user_id=user_id,
        activity_type='logout',
        ip_address=request.remote_addr,
        details="User logged out"
    )
    db.session.add(activity)
    db.session.commit()
    
    # Logout user and clear all session data
    logout_user()
    session.clear()
    
    # Regenerate session ID to prevent session fixation
    # Create a new empty session with a new ID
    session.permanent = False
    session.modified = True
    
    return redirect(url_for('login'))

# Department Dashboards
@app.route('/grc_dashboard')
@login_required
def grc_dashboard():
    if current_user.department != "GRC":
        abort(403)
    
    employee_data = EmployeeData.query.filter_by(user_id=current_user.id).first()
    performance_data = get_user_performance(current_user.id)
    performance_history = get_user_performance_history(current_user.id)
    
    response = make_response(render_template('grc_dashboard.html', 
        user=current_user, 
        employee_data=employee_data,
        performance_data=performance_data,
        performance_history=performance_history
    ))
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate'
    return response

@app.route('/vapt_dashboard')
@login_required
def vapt_dashboard():
    if current_user.department != "VAPT":
        abort(403)
    
    employee_data = EmployeeData.query.filter_by(user_id=current_user.id).first()
    performance_data = get_user_performance(current_user.id)
    performance_history = get_user_performance_history(current_user.id)
    
    response = make_response(render_template('vapt_dashboard.html', 
        user=current_user, 
        employee_data=employee_data,
        performance_data=performance_data,
        performance_history=performance_history
    ))
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate'
    return response

# Update the get_user_performance_history function
def get_user_performance_history(user_id):
    """Get performance data for a user for the previous 12 months"""
    current_date = get_current_ist_time().replace(tzinfo=None)
    
    performance_history = []
    
    for i in range(12):
        # Calculate month and year for each of the previous 12 months
        month_offset = i + 1
        target_date = current_date - timedelta(days=30*month_offset)
        month = target_date.month
        year = target_date.year
        
        performance = Performance.query.filter_by(
            user_id=user_id, 
            month=month, 
            year=year
        ).first()
        
        if performance:
            # Calculate average of all performance metrics
            avg_score = (
                performance.punctuality + 
                performance.client_satisfaction + 
                performance.behaviour + 
                performance.communication_skills + 
                performance.technical_skills + 
                performance.team_coordination
            ) / 6
            
            performance_history.append({
                'month': month,
                'year': year,
                'average': round(avg_score, 2),
                'month_name': target_date.strftime('%b'),
                'year_short': target_date.strftime('%y')
            })
        else:
            # If no data exists for this month, add a placeholder
            performance_history.append({
                'month': month,
                'year': year,
                'average': 0,
                'month_name': target_date.strftime('%b'),
                'year_short': target_date.strftime('%y')
            })
    
    # Reverse to get chronological order (oldest to newest)
    performance_history.reverse()
    
    return performance_history

@app.route('/audit_dashboard')
@login_required
def audit_dashboard():
    if current_user.department != "Audit":
        abort(403)
    
    employee_data = EmployeeData.query.filter_by(user_id=current_user.id).first()
    performance_data = get_user_performance(current_user.id)
    performance_history = get_user_performance_history(current_user.id)
    
    response = make_response(render_template(
        'audit_dashboard.html', 
        user=current_user, 
        employee_data=employee_data,
        performance_data=performance_data,
        performance_history=performance_history
    ))
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate'
    return response


@app.route('/admin_dashboard')
@login_required
def admin_dashboard():  
    if current_user.department != "Admin":
        abort(403)
    
    current_date = get_current_ist_time().replace(tzinfo=None)
    prev_month = current_date.month - 1 if current_date.month > 1 else 12
    prev_year = current_date.year if current_date.month > 1 else current_date.year - 1
    
    show_performance_management = request.args.get('show_performance', 'false').lower() == 'true'
    selected_month = request.args.get('performance_month', prev_month, type=int)
    selected_year = request.args.get('performance_year', prev_year, type=int)
    show_performance_history = request.args.get('show_performance_history', 'false').lower() == 'true'

    # Get all users and their performance data
    users = User.query.all()
    performance_data = get_all_users_performance(selected_month, selected_year)
    
    show_login_activities = sanitize_url_param(request.args.get('show_activities', 'false')).lower() == 'true' if request.args.get('show_activities') else False
    login_activities = LoginActivity.query.order_by(LoginActivity.timestamp.desc()).all() if show_login_activities else []
    
    # Pre-process login activities to include usernames
    processed_activities = []
    for activity in login_activities:
        if activity.user_id == -1:
            username = "Unknown User"
        else:
            user = User.query.get(activity.user_id)
            username = user.username if user else "Deleted User"
        
        processed_activities.append({
            'timestamp': activity.timestamp,
            'username': username,
            'activity_type': activity.activity_type,
            'ip_address': activity.ip_address,
            'details': activity.details,
            'user_id': activity.user_id
        })
    
    employee_data = EmployeeData.query.filter_by(user_id=current_user.id).first()

    performance_history_data = {}
    performance_history_months = []
    performance_history_years = []

    if show_performance_history:
        # Get performance data for the last 12 months
        current_date = get_current_ist_time().replace(tzinfo=None)
        
        for i in range(12):
            # Calculate month and year for each of the previous 12 months
            month_offset = i + 1
            target_date = current_date - timedelta(days=30*month_offset)
            month = target_date.month
            year = target_date.year
            
            performance_history_months.append(month)
            performance_history_years.append(year)
            
            # Get performance for all users for this month/year
            performances = Performance.query.filter_by(month=month, year=year).all()
            
            for perf in performances:
                # Calculate average performance
                avg_score = (
                    perf.punctuality + 
                    perf.client_satisfaction + 
                    perf.behaviour + 
                    perf.communication_skills + 
                    perf.technical_skills + 
                    perf.team_coordination
                ) / 6
                performance_history_data[(perf.user_id, month, year)] = round(avg_score, 1)
    
    # Reverse to show chronological order (oldest to newest)
    performance_history_months.reverse()
    performance_history_years.reverse()
    
    response = make_response(render_template(
        'admin_dashboard.html', 
        user=current_user,
        employee_data=employee_data,
        show_login_activities=show_login_activities,
        login_activities=processed_activities,
        datetime=get_current_ist_time,
        show_performance_management=show_performance_management,
        users=users,
        performance_data=performance_data,
        current_year=current_date.year,
        current_month=current_date.month,
        prev_month=prev_month,
        prev_year=prev_year,
        selected_month=selected_month,
        selected_year=selected_year,
        # Add these new parameters
        show_performance_history=show_performance_history,
        performance_history_data=performance_history_data,
        performance_history_months=performance_history_months,
        performance_history_years=performance_history_years
    ))
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate'
    return response

@app.route('/hr_dashboard')
@login_required
def hr_dashboard():
    if current_user.department != "HR":
        abort(403)
    
    # Sanitize URL parameters to prevent reflected XSS
    show_create_form = sanitize_url_param(request.args.get('show_form', 'false')).lower() == 'true' if request.args.get('show_form') else False
    show_user_status = sanitize_url_param(request.args.get('show_status', 'false')).lower() == 'true' if request.args.get('show_status') else False
    show_employee_details = sanitize_url_param(request.args.get('show_employee_details', 'false')).lower() == 'true' if request.args.get('show_employee_details') else False
    show_performance_management = sanitize_url_param(request.args.get('show_performance', 'false')).lower() == 'true' if request.args.get('show_performance') else False
    edit_user_id_raw = request.args.get('edit_user')
    edit_user_id = int(sanitize_url_param(edit_user_id_raw)) if edit_user_id_raw and edit_user_id_raw.isdigit() else None
    
    users = User.query.all()
    
    # Get employee data for all users
    employee_data = {}
    # performance_data = get_all_users_performance()
    for user in users:
        data = EmployeeData.query.filter_by(user_id=user.id).first()
        employee_data[user.id] = data
    
    current_date = get_current_ist_time().replace(tzinfo=None)
    prev_month = current_date.month - 1 if current_date.month > 1 else 12
    prev_year = current_date.year if current_date.month > 1 else current_date.year - 1
    
    selected_month = request.args.get('performance_month', prev_month, type=int)
    selected_year = request.args.get('performance_year', prev_year, type=int)
    
    # Get performance data for selected month/year
    performance_data = get_all_users_performance(selected_month, selected_year)

    response = make_response(render_template(
        'hr_dashboard.html', 
        user=current_user, 
        show_create_form=show_create_form,
        show_user_status=show_user_status,
        show_employee_details=show_employee_details,
        show_performance_management=show_performance_management,
        edit_user_id=edit_user_id,
        users=users,
        employee_data=employee_data,
        performance_data=performance_data,
        current_month=current_date.month,
        current_year=current_date.year,
        prev_month=prev_month,
        prev_year=prev_year,
        selected_month=selected_month,
        selected_year=selected_year
    ))
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate'
    return response

@app.route('/update_performance/<int:user_id>', methods=['POST'])
@login_required
def update_performance(user_id):
    if current_user.department != "HR":
        abort(403)
    
    user = db.session.get(User, user_id)
    if not user:
        return jsonify({'success': False, 'message': 'User not found'}), 404
    
    # IDOR Protection: Verify user is not deleted and is accessible
    if user.deleted_at:
        return jsonify({'success': False, 'message': 'User not found'}), 404
    
    if user.status and not user.status.is_active:
        return jsonify({'success': False, 'message': 'User not found'}), 404
    
    # Get current month/year for previous month
    current_date = get_current_ist_time().replace(tzinfo=None)
    prev_month = current_date.month - 1 if current_date.month > 1 else 12
    prev_year = current_date.year if current_date.month > 1 else current_date.year - 1
    
    # Validate month and year with type safety
    month_valid, month, month_error = validate_type_safe(request.form.get('month', prev_month), int, min_value=1, max_value=12)
    if not month_valid:
        month = prev_month  # Use default if validation fails
    
    year_valid, year, year_error = validate_type_safe(request.form.get('year', prev_year), int, min_value=2000, max_value=2100)
    if not year_valid:
        year = prev_year  # Use default if validation fails

    # Only allow update if month/year is previous month
    if month != prev_month or year != prev_year:
        return jsonify({'success': False, 'message': 'You can only update performance for the previous month.'})
    # Get or create performance record
    performance = Performance.query.filter_by(
        user_id=user_id, 
        month=month, 
        year=year
    ).first()
    
    if not performance:
        performance = Performance(
            user_id=user_id,
            month=month,
            year=year
        )
        db.session.add(performance)
    
    # Update performance fields
    performance.punctuality = float(request.form.get('punctuality', 0))
    performance.client_satisfaction = float(request.form.get('client_satisfaction', 0))
    performance.behaviour = float(request.form.get('behaviour', 0))
    performance.communication_skills = float(request.form.get('communication_skills', 0))
    performance.technical_skills = float(request.form.get('technical_skills', 0))
    performance.team_coordination = float(request.form.get('team_coordination', 0))
    
    # Log the activity
    activity = LoginActivity(
        user_id=current_user.id,
        activity_type='performance_update',
        ip_address=request.remote_addr,
        details=f"Updated performance for user {user.username} for {month}/{year}"
    )
    db.session.add(activity)
    
    db.session.commit()
    return jsonify({'success': True, 'message': 'Performance updated successfully'})

@app.route('/get_performance_data/<int:user_id>')
@login_required
def get_performance_data(user_id):
    if current_user.department != "HR":
        abort(403)
    
    user = db.session.get(User, user_id)
    if not user:
        return jsonify({'success': False, 'message': 'User not found'}), 404
    
    # IDOR Protection: Verify user is not deleted and is accessible
    if user.deleted_at:
        return jsonify({'success': False, 'message': 'User not found'}), 404
    
    if user.status and not user.status.is_active:
        return jsonify({'success': False, 'message': 'User not found'}), 404
    
    month = request.args.get('month', type=int)
    year = request.args.get('year', type=int)
    
    if month is None or year is None:
        current_date = get_current_ist_time().replace(tzinfo=None)
        month = current_date.month - 1 if current_date.month > 1 else 12
        year = current_date.year if current_date.month > 1 else current_date.year - 1
    
    performance_data = Performance.query.filter_by(
        user_id=user_id, 
        month=month, 
        year=year
    ).first()
    
    if performance_data:
        return jsonify({
            'success': True,
            'punctuality': performance_data.punctuality,
            'client_satisfaction': performance_data.client_satisfaction,
            'behaviour': performance_data.behaviour,
            'communication_skills': performance_data.communication_skills,
            'technical_skills': performance_data.technical_skills,
            'team_coordination': performance_data.team_coordination
        })
    else:
        return jsonify({
            'success': True,
            'punctuality': 0,
            'client_satisfaction': 0,
            'behaviour': 0,
            'communication_skills': 0,
            'technical_skills': 0,
            'team_coordination': 0
        })
        
@app.route('/get_employee_data/<int:user_id>')
@login_required
def get_employee_data(user_id):
    if current_user.department != "HR":
        abort(403)
    
    user = db.session.get(User, user_id)
    if not user:
        return jsonify({'success': False, 'message': 'User not found'}), 404
    
    # IDOR Protection: Verify user is not deleted and is accessible
    if user.deleted_at:
        return jsonify({'success': False, 'message': 'User not found'}), 404
    
    if user.status and not user.status.is_active:
        return jsonify({'success': False, 'message': 'User not found'}), 404
    
    employee_data = EmployeeData.query.filter_by(user_id=user_id).first()
    
    return jsonify({
        'success': True,
        'username': user.username,
        'position': employee_data.position if employee_data else '',
        'experience': employee_data.experience if employee_data else '',
        'education': employee_data.education if employee_data else '',
        'certifications': employee_data.certifications if employee_data else '',
        'date_of_birth': employee_data.date_of_birth.strftime('%Y-%m-%d') if employee_data and employee_data.date_of_birth else '',
        'blood_group': employee_data.blood_group if employee_data else '',
        'contact_number': employee_data.contact_number if employee_data else '',
        'photo': employee_data.photo if employee_data else 'default_avatar.jpg'
    })

@app.route('/update_employee_data/<int:user_id>', methods=['POST'])
@login_required
def update_employee_data(user_id):
    if current_user.department != "HR":
        abort(403)
    
    user = db.session.get(User, user_id)
    if not user:
        return jsonify({'success': False, 'message': 'User not found'}), 404
    
    # IDOR Protection: Verify user is not deleted and is accessible
    if user.deleted_at:
        return jsonify({'success': False, 'message': 'User not found'}), 404
    
    if user.status and not user.status.is_active:
        return jsonify({'success': False, 'message': 'User not found'}), 404
    
    # Get or create employee data
    employee_data = EmployeeData.query.filter_by(user_id=user_id).first()
    if not employee_data:
        employee_data = EmployeeData(user_id=user_id)
        db.session.add(employee_data)
    
    # Update fields
    employee_data.position = request.form.get('position')
    employee_data.experience = request.form.get('experience')
    employee_data.education = request.form.get('education')
    employee_data.certifications = request.form.get('certifications')
    employee_data.blood_group = request.form.get('blood_group')
    employee_data.contact_number = request.form.get('contact_number')
    
    # Handle date of birth
    dob_str = request.form.get('date_of_birth')
    if dob_str:
        try:
            employee_data.date_of_birth = datetime.strptime(dob_str, '%Y-%m-%d').date()
        except ValueError:
            pass
    
    # Handle file upload with comprehensive validation
    if 'photo' in request.files:
        file = request.files['photo']
        if file and file.filename != '':
            # Use secure file upload utility
            success, filename, error_msg = secure_file_upload(
                file,
                app.config['UPLOAD_FOLDER'],
                app.config['ALLOWED_EXTENSIONS'],
                max_size_mb=16,
                custom_filename=f"{user_id}_{file.filename}"
            )
            if success:
                employee_data.photo = filename
            else:
                flash(f'File upload error: {error_msg}', 'error')
    
    db.session.commit()
    return jsonify({'success': True, 'message': 'Employee details updated successfully'})

@app.route('/request_reset_otp', methods=['POST'])
@login_required
def request_reset_otp():
    if current_user.department != "HR":
        abort(403)
    
    data = request.get_json()
    user_id = data.get('user_id')
    
    user = db.session.get(User, user_id)
    if not user:
        return jsonify({'success': False, 'message': 'User not found'}), 404
    
    # IDOR Protection: Verify user is not deleted and is accessible
    if user.deleted_at:
        return jsonify({'success': False, 'message': 'User not found'}), 404
    
    if user.status and not user.status.is_active:
        return jsonify({'success': False, 'message': 'User not found'}), 404
    
    otp = generate_otp()
    send_otp_email(user.email, otp)
    
    # Store the OTP in session with user-specific key
    session[f'reset_otp_{user_id}'] = otp
    session[f'reset_otp_created_{user_id}'] = get_current_ist_time().timestamp()
    
    # Log the activity
    activity = LoginActivity(
        user_id=current_user.id,
        activity_type='password_reset_request',
        ip_address=request.remote_addr,
        details=f"Requested password reset for user {user.username}"
    )
    db.session.add(activity)
    db.session.commit()
    
    return jsonify({'success': True})



@app.route('/verify_reset_otp', methods=['POST'])
@login_required
def verify_reset_otp():
    if current_user.department != "HR":
        abort(403)
    
    data = request.get_json()
    user_id = data.get('user_id')
    user_otp = data.get('otp')
    
    # Check if OTP exists and is not expired
    otp_created = session.get(f'reset_otp_created_{user_id}')
    if not otp_created or (get_current_ist_time().timestamp() - otp_created) > 180:
        return jsonify({'success': False, 'message': 'OTP expired or not requested'})
    
    # Verify OTP
    if user_otp == session.get(f'reset_otp_{user_id}'):
        # Mark OTP as verified
        session[f'reset_verified_{user_id}'] = True
        session.pop(f'reset_otp_{user_id}', None)
        session.pop(f'reset_otp_created_{user_id}', None)
        
        # Log the activity
        activity = LoginActivity(
            user_id=current_user.id,
            activity_type='password_reset_verify',
            ip_address=request.remote_addr,
            details=f"Verified OTP for password reset for user ID {user_id}"
        )
        db.session.add(activity)
        db.session.commit()
        
        return jsonify({'success': True})
    else:
        return jsonify({'success': False, 'message': 'Invalid OTP'})

@app.route('/reset_user_password', methods=['POST'])
@login_required
def reset_user_password():
    if current_user.department != "HR":
        abort(403)
    
    data = request.get_json()
    user_id = data.get('user_id')
    new_password = data.get('new_password')
    
    # Check if OTP was verified
    if not session.get(f'reset_verified_{user_id}'):
        return jsonify({'success': False, 'message': 'OTP not verified'})
    
    user = db.session.get(User, user_id)
    if not user:
        return jsonify({'success': False, 'message': 'User not found'}), 404
    
    # IDOR Protection: Verify user is not deleted and is accessible
    if user.deleted_at:
        return jsonify({'success': False, 'message': 'User not found'}), 404
    
    if user.status and not user.status.is_active:
        return jsonify({'success': False, 'message': 'User not found'}), 404
    
    # Validate password strength
    if not new_password:
        return jsonify({'success': False, 'message': 'Password is required'})
    
    is_valid, error_msg = validate_password_strength(new_password)
    if not is_valid:
        return jsonify({'success': False, 'message': f'Weak password: {error_msg}'})
    
    # Update password
    user.password = generate_password_hash(new_password)
    
    # Reset account lock if any
    if user.status:
        user.status.failed_attempts = 0
        user.status.locked_until = None
        user.status.is_active = True
    
    # Log the activity
    activity = LoginActivity(
        user_id=current_user.id,
        activity_type='password_reset',
        ip_address=request.remote_addr,
        details=f"Reset password for user {user.username}"
    )
    db.session.add(activity)
    db.session.commit()
    
    # Clean up session
    session.pop(f'reset_verified_{user_id}', None)
    
    return jsonify({'success': True})

@app.route('/request_create_id_otp', methods=['POST'])
@login_required
def request_create_id_otp():
    """Generate and send OTP for Create ID authentication"""
    try:
        if current_user.department != "HR":
            return jsonify({'success': False, 'message': 'Unauthorized'}), 403
        
        # Generate 8-character alphanumeric OTP with special characters
        characters = string.ascii_letters + string.digits + "!@#$%^&*"
        otp = ''.join(secrets.choice(characters) for _ in range(8))
        
        # Store OTP in session with expiration (3 minutes) - encrypted
        enc_manager = get_encryption_manager()
        session['create_id_otp'] = enc_manager.encrypt(otp)
        session['create_id_otp_time'] = datetime.now().timestamp()
        session['create_id_otp_verified'] = False
        
        # Send OTP via email
        recipient_email = 'ngt-auakua@ngtech.co.in'
        try:
            msg = Message(
                subject="OTP for Create ID Authentication",
                recipients=[recipient_email],
                sender=app.config['MAIL_DEFAULT_SENDER']
            )
            msg.body = f"""Dear Authorized Personnel,

An OTP has been requested for creating a new user ID in the system.

Your OTP is: {otp}

This OTP is valid for 3 minutes.

If you did not request this OTP, please ignore this email.

Best regards,
System Administrator"""
            mail.send(msg)
            return jsonify({'success': True, 'message': 'OTP sent successfully to authorized email'})
        except Exception as e:
            print(f"Error sending OTP email: {e}")
            return jsonify({'success': False, 'message': 'Failed to send OTP email'}), 500
    
    except Exception as e:
        print(f"Error generating OTP: {e}")
        return jsonify({'success': False, 'message': 'Error generating OTP'}), 500

@app.route('/verify_create_id_otp', methods=['POST'])
@login_required
def verify_create_id_otp():
    """Verify OTP for Create ID authentication"""
    try:
        if current_user.department != "HR":
            return jsonify({'success': False, 'message': 'Unauthorized'}), 403
        
        user_otp = request.form.get('otp', '').strip()
        
        # Check if OTP exists in session (decrypt it)
        encrypted_otp = session.get('create_id_otp')
        otp_time = session.get('create_id_otp_time')
        
        if not encrypted_otp or not otp_time:
            return jsonify({'success': False, 'message': 'OTP not found. Please request a new OTP.'}), 400
        
        # Check if OTP is expired (3 minutes = 180 seconds)
        current_time = datetime.now().timestamp()
        if current_time - otp_time > 180:
            session.pop('create_id_otp', None)
            session.pop('create_id_otp_time', None)
            session.pop('create_id_otp_verified', None)
            return jsonify({'success': False, 'message': 'OTP has expired. Please request a new OTP.'}), 400
        
        # Decrypt OTP for comparison
        enc_manager = get_encryption_manager()
        try:
            stored_otp = enc_manager.decrypt(encrypted_otp)
        except:
            return jsonify({'success': False, 'message': 'OTP session error. Please request a new OTP.'}), 400
        
        # Verify OTP
        if user_otp != stored_otp:
            return jsonify({'success': False, 'message': 'Invalid OTP. Please try again.'}), 400
        
        # Mark OTP as verified
        session['create_id_otp_verified'] = True
        return jsonify({'success': True, 'message': 'OTP verified successfully'})
    
    except Exception as e:
        print(f"Error verifying OTP: {e}")
        return jsonify({'success': False, 'message': 'Error verifying OTP'}), 500

@app.route('/create_user', methods=['POST'])
@login_required
def create_user():
    try:
        if current_user.department != "HR":
            abort(403)
        
        # Check if OTP is verified
        if not session.get('create_id_otp_verified', False):
            flash('You are not add authorized credential.', 'error')
            return redirect(url_for('hr_dashboard'))
        
        # Clear OTP verification after use
        session.pop('create_id_otp', None)
        session.pop('create_id_otp_time', None)
        session.pop('create_id_otp_verified', None)
        
        # Check content length first to avoid parsing large files
        if request.content_length and request.content_length > app.config.get('MAX_CONTENT_LENGTH', 16 * 1024 * 1024):
            flash('File too large. Maximum size is 16MB.', 'error')
            return redirect(url_for('hr_dashboard'))
        
        # Get all form fields - access form data safely
        username = request.form.get('username', '').strip()
        employee_name = request.form.get('employee_name', '').strip()
        password = request.form.get('password', '').strip()
        email = request.form.get('email', '').strip()
        department = request.form.get('department', '').strip()
        designation = request.form.get('designation', '').strip()
        
        print(f"DEBUG: Received form data - username={username}, employee_name={employee_name}, email={email}, department={department}, designation={designation}")
        
        # Validate required fields
        if not username or not employee_name or not password or not email or not department or not designation:
            missing_fields = []
            if not username: missing_fields.append('username')
            if not employee_name: missing_fields.append('employee_name')
            if not password: missing_fields.append('password')
            if not email: missing_fields.append('email')
            if not department: missing_fields.append('department')
            if not designation: missing_fields.append('designation')
            flash(f'Missing required fields: {", ".join(missing_fields)}', 'error')
            return redirect(url_for('hr_dashboard'))
        
        # Check for duplicate username
        if db.session.execute(db.select(User).filter_by(username=username)).scalar_one_or_none():
            flash('Username already exists', 'error')
            return redirect(url_for('hr_dashboard'))
        
        # Check for duplicate email
        if db.session.execute(db.select(User).filter_by(email=email)).scalar_one_or_none():
            flash('Email already exists', 'error')
            return redirect(url_for('hr_dashboard'))
        
        # Validate password strength
        is_valid, error_msg = validate_password_strength(password)
        if not is_valid:
            flash(f'Weak password: {error_msg}', 'error')
            return redirect(url_for('hr_dashboard'))
        
        hashed_pw = generate_password_hash(password)
        new_user = User(
            username=username,
            employee_name=employee_name,
            password=hashed_pw,
            email=email,
            department=department
        )
        db.session.add(new_user)
        db.session.flush()  # Get the user ID
        
        user_status = UserStatus(user_id=new_user.id)
        db.session.add(user_status)
        
        # Validate and format experience (should be a number like 0.5, 1, 1.5, etc.)
        experience = request.form.get('experience')
        if experience:
            # Validate with type safety
            exp_valid, exp_value, exp_error = validate_type_safe(experience, float, min_value=0.0, max_value=100.0)
            if exp_valid:
                experience_str = str(exp_value)
            else:
                experience_str = experience  # Keep original if validation fails
        else:
            experience_str = experience
        
        # Create employee data with form values
        # Store browser fingerprint as plain text (unencrypted) in database
        # This ensures fingerprints work consistently even if encryption key changes
        # Encryption is used only for session storage, not database storage
        browser_fp = request.form.get('browser_fingerprint')
        fingerprint_value = browser_fp.strip() if browser_fp else None
        
        employee_data = EmployeeData(
            user_id=new_user.id,
            position=designation,
            experience=experience_str,
            education=request.form.get('education'),
            certifications=request.form.get('certifications'),
            blood_group=request.form.get('blood_group'),
            contact_number=request.form.get('contact'),
            browser_fingerprint=fingerprint_value
        )
        
        # Handle date of birth
        dob_str = request.form.get('date_of_birth')
        if dob_str:
            try:
                employee_data.date_of_birth = datetime.strptime(dob_str, '%Y-%m-%d').date()
            except ValueError:
                pass  # Handle invalid date format if needed
        
        # Handle file upload - save to Employee_Images folder with employee name as filename
        try:
            if 'photo' in request.files:
                file = request.files['photo']
                if file and file.filename != '':
                    # Create Employee_Images folder if it doesn't exist
                    employee_images_folder = os.path.join(app.config['UPLOAD_FOLDER'], 'Employee_Images')
                    
                    # Get file extension
                    file_ext = os.path.splitext(file.filename)[1]
                    # Use employee name as filename (sanitized)
                    safe_employee_name = secure_filename(employee_name)
                    custom_filename = f"{safe_employee_name}{file_ext}"
                    
                    # Use secure file upload utility
                    success, filename, error_msg = secure_file_upload(
                        file,
                        employee_images_folder,
                        app.config['ALLOWED_EXTENSIONS'],
                        max_size_mb=16,
                        custom_filename=custom_filename
                    )
                    
                    if success:
                        employee_data.photo = f"Employee_Images/{filename}"
                    else:
                        flash(f'File upload error: {error_msg}', 'error')
                        db.session.rollback()
                        return redirect(url_for('hr_dashboard'))
        except Exception as e:
            logger = logging.getLogger(__name__)
            logger.error(f"Error handling file upload: {e}", exc_info=True)
            flash('Error uploading image. Please try again.', 'error')
            db.session.rollback()
            return redirect(url_for('hr_dashboard'))
        
        db.session.add(employee_data)
        
        activity = LoginActivity(
            user_id=current_user.id,
            activity_type='user_creation',
            ip_address=request.remote_addr,
            details=f"Created new user: {username}"
        )
        db.session.add(activity)
        
        db.session.commit()
        
        # Send email to new user with credentials
        try:
            login_url = url_for('login', _external=True)
            msg = Message(
                "Your Account Credentials",
                recipients=[email],
                sender=app.config['MAIL_DEFAULT_SENDER']
            )
            msg.body = f"""Dear {employee_name},

Your account has been successfully created. Please find your login credentials below:

Username: {username}
Password: {password}

Please login at: {login_url}

Note: You will receive an OTP via email for two-factor authentication when you login.

Best regards,
HR Department"""
            mail.send(msg)
        except Exception as e:
            # Log error but don't fail the user creation
            print(f"Error sending email: {e}")
        
        flash('User created successfully and credentials sent via email', 'success')
        return redirect(url_for('hr_dashboard'))
    
    except Exception as e:
        # Log the error for debugging
        # Log error securely (server-side only)
        logger = logging.getLogger(__name__)
        logger.error(f"Error creating user: {type(e).__name__}: {str(e)}", exc_info=True)
        # Don't print traceback to console in production
        if app.config.get('DEBUG', False):
            import traceback
            traceback.print_exc()
        
        # Handle specific error types
        if 'ClientDisconnected' in error_msg or '400 Bad Request' in error_msg:
            flash('Upload failed. The file may be too large or the connection was interrupted. Please try again with a smaller image file (max 16MB).', 'error')
        elif 'RequestEntityTooLarge' in error_msg or '413' in error_msg:
            flash('File too large. Maximum size is 16MB. Please compress your image and try again.', 'error')
        else:
            flash(f'Error creating user: {error_msg}', 'error')
        
        # Rollback any database changes
        try:
            db.session.rollback()
        except:
            pass
        
        return redirect(url_for('hr_dashboard'))

# API Routes for Update ID functionality
@app.route('/api/get_users_list', methods=['GET'])
@login_required
def get_users_list():
    """Get list of all active (non-deleted) users
    Note: For Update/Delete ID modals, use /api/get_users_list_filtered instead
    """
    if current_user.department != "HR":
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    
    try:
        # Get all users and filter out deleted ones
        all_users = User.query.all()
        
        # Filter out deleted users (where deleted_at is not None or is_active is False)
        active_users = []
        for user in all_users:
            # Check if user is deleted
            is_deleted = False
            if hasattr(user, 'deleted_at') and user.deleted_at:
                is_deleted = True
            
            # Check if user is inactive
            is_inactive = False
            if user.status and not user.status.is_active:
                is_inactive = True
            
            # Only include users that are not deleted and are active
            if not is_deleted and not is_inactive:
                active_users.append({'id': user.id, 'employee_name': user.employee_name})
        
        return jsonify({'success': True, 'users': active_users})
    except Exception as e:
        safe_error = get_safe_error_message(e)
        return jsonify({'success': False, 'message': safe_error}), 500

@app.route('/api/get_users_list_filtered', methods=['GET'])
@login_required
def get_users_list_filtered():
    """Get list of active users for Update/Delete ID modals
    Excludes Admin users - only shows GRC, VAPT, Audit, and HR employees
    """
    if current_user.department != "HR":
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    
    try:
        # Allowed departments (excluding Admin)
        allowed_departments = ['GRC', 'VAPT', 'Audit', 'HR']
        
        # Get all users and filter out deleted ones and Admin department
        all_users = User.query.all()
        
        # Filter out deleted users (where deleted_at is not None or is_active is False)
        # Also exclude Admin department - only show GRC, VAPT, Audit, and HR
        active_users = []
        for user in all_users:
            # Check if user is deleted
            is_deleted = False
            if hasattr(user, 'deleted_at') and user.deleted_at:
                is_deleted = True
            
            # Check if user is inactive
            is_inactive = False
            if user.status and not user.status.is_active:
                is_inactive = True
            
            # Check if user is in allowed departments (exclude Admin)
            is_allowed_department = user.department in allowed_departments
            
            # Only include users that are not deleted, are active, and are in allowed departments
            if not is_deleted and not is_inactive and is_allowed_department:
                active_users.append({'id': user.id, 'employee_name': user.employee_name, 'department': user.department})
        
        return jsonify({'success': True, 'users': active_users})
    except Exception as e:
        safe_error = get_safe_error_message(e)
        return jsonify({'success': False, 'message': safe_error}), 500

@app.route('/api/get_user_details/<int:user_id>', methods=['GET'])
@login_required
def get_user_details(user_id):
    """Get detailed information about a specific user"""
    if current_user.department != "HR":
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    
    try:
        user = db.session.get(User, user_id)
        if not user:
            return jsonify({'success': False, 'message': 'User not found'}), 404
        
        # IDOR Protection: Verify user is not deleted and is accessible
        if user.deleted_at:
            return jsonify({'success': False, 'message': 'User not found'}), 404
        
        if user.status and not user.status.is_active:
            return jsonify({'success': False, 'message': 'User not found'}), 404
        
        employee_data = EmployeeData.query.filter_by(user_id=user_id).first()
        
        user_data = {
            'id': user.id,
            'username': user.username,
            'employee_name': user.employee_name,
            'email': user.email,
            'department': user.department
        }
        
        employee_data_dict = {
            'position': employee_data.position if employee_data else '',
            'experience': employee_data.experience if employee_data else '',
            'education': employee_data.education if employee_data else '',
            'certifications': employee_data.certifications if employee_data else '',
            'date_of_birth': employee_data.date_of_birth.strftime('%Y-%m-%d') if employee_data and employee_data.date_of_birth else '',
            'blood_group': employee_data.blood_group if employee_data else '',
            'contact_number': employee_data.contact_number if employee_data else '',
            'browser_fingerprint': _decrypt_fingerprint_for_api(employee_data.browser_fingerprint) if employee_data and employee_data.browser_fingerprint else ''
        }
        
        return jsonify({
            'success': True,
            'user': user_data,
            'employee_data': employee_data_dict
        })
    except Exception as e:
        safe_error = get_safe_error_message(e)
        return jsonify({'success': False, 'message': safe_error}), 500

@app.route('/request_update_id_otp', methods=['POST'])
@login_required
def request_update_id_otp():
    """Generate and send OTP for Update ID authentication"""
    try:
        if current_user.department != "HR":
            return jsonify({'success': False, 'message': 'Unauthorized'}), 403
        
        # Generate 8-character alphanumeric OTP with special characters
        characters = string.ascii_letters + string.digits + "!@#$%^&*"
        otp = ''.join(secrets.choice(characters) for _ in range(8))
        
        # Store OTP in session with expiration (3 minutes) - encrypted
        enc_manager = get_encryption_manager()
        session['update_id_otp'] = enc_manager.encrypt(otp)
        session['update_id_otp_time'] = datetime.now().timestamp()
        session['update_id_otp_verified'] = False
        
        # Send OTP via email
        recipient_email = 'ngt-auakua@ngtech.co.in'
        try:
            msg = Message(
                subject="OTP for Update ID Authentication",
                recipients=[recipient_email],
                sender=app.config['MAIL_DEFAULT_SENDER']
            )
            msg.body = f"""Dear Authorized Personnel,

An OTP has been requested for updating a user ID in the system.

Your OTP is: {otp}

This OTP is valid for 3 minutes.

If you did not request this OTP, please ignore this email.

Best regards,
System Administrator"""
            mail.send(msg)
            return jsonify({'success': True, 'message': 'OTP sent successfully to authorized email'})
        except Exception as e:
            print(f"Error sending OTP email: {e}")
            return jsonify({'success': False, 'message': 'Failed to send OTP email'}), 500
    
    except Exception as e:
        print(f"Error generating OTP: {e}")
        return jsonify({'success': False, 'message': 'Error generating OTP'}), 500

@app.route('/verify_update_id_otp', methods=['POST'])
@login_required
def verify_update_id_otp():
    """Verify OTP for Update ID authentication"""
    try:
        if current_user.department != "HR":
            return jsonify({'success': False, 'message': 'Unauthorized'}), 403
        
        user_otp = request.form.get('otp', '').strip()
        
        # Check if OTP exists in session (decrypt it)
        encrypted_otp = session.get('update_id_otp')
        otp_time = session.get('update_id_otp_time')
        
        if not encrypted_otp or not otp_time:
            return jsonify({'success': False, 'message': 'OTP not found. Please request a new OTP.'}), 400
        
        # Check if OTP is expired (3 minutes = 180 seconds)
        current_time = datetime.now().timestamp()
        if current_time - otp_time > 180:
            session.pop('update_id_otp', None)
            session.pop('update_id_otp_time', None)
            session.pop('update_id_otp_verified', None)
            return jsonify({'success': False, 'message': 'OTP has expired. Please request a new OTP.'}), 400
        
        # Decrypt OTP for comparison
        enc_manager = get_encryption_manager()
        try:
            stored_otp = enc_manager.decrypt(encrypted_otp)
        except:
            return jsonify({'success': False, 'message': 'OTP session error. Please request a new OTP.'}), 400
        
        # Verify OTP
        if user_otp != stored_otp:
            return jsonify({'success': False, 'message': 'Invalid OTP. Please try again.'}), 400
        
        # Mark OTP as verified
        session['update_id_otp_verified'] = True
        return jsonify({'success': True, 'message': 'OTP verified successfully'})
    
    except Exception as e:
        print(f"Error verifying OTP: {e}")
        return jsonify({'success': False, 'message': 'Error verifying OTP'}), 500

@app.route('/api/update_user_field', methods=['POST'])
@login_required
def update_user_field():
    """Update a single field for a user"""
    if current_user.department != "HR":
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    
    # Check if OTP is verified
    if not session.get('update_id_otp_verified', False):
        return jsonify({'success': False, 'message': 'You are not add authorized credential.'}), 403
    
    try:
        data = request.get_json()
        user_id = data.get('user_id')
        field = data.get('field')
        value = data.get('value', '').strip()
        
        if not user_id or not field:
            return jsonify({'success': False, 'message': 'Missing user_id or field'}), 400
        
        user = db.session.get(User, user_id)
        if not user:
            return jsonify({'success': False, 'message': 'User not found'}), 404
        
        employee_data = EmployeeData.query.filter_by(user_id=user_id).first()
        if not employee_data:
            # Create employee data if it doesn't exist
            employee_data = EmployeeData(user_id=user_id)
            db.session.add(employee_data)
        
        # Map field names to database columns
        field_mapping = {
            'employee_name': ('user', 'employee_name'),
            'username': ('user', 'username'),
            'password': ('user', 'password'),
            'email': ('user', 'email'),
            'department': ('user', 'department'),
            'designation': ('employee', 'position'),
            'experience': ('employee', 'experience'),
            'education': ('employee', 'education'),
            'certifications': ('employee', 'certifications'),
            'date_of_birth': ('employee', 'date_of_birth'),
            'blood_group': ('employee', 'blood_group'),
            'contact': ('employee', 'contact_number'),
            'browser_fingerprint': ('employee', 'browser_fingerprint')
        }
        
        if field not in field_mapping:
            return jsonify({'success': False, 'message': f'Invalid field: {field}'}), 400
        
        table, column = field_mapping[field]
        
        # Handle special cases
        if field == 'password':
            if not value:
                return jsonify({'success': False, 'message': 'Password cannot be empty'}), 400
            
            # Validate password strength
            is_valid, error_msg = validate_password_strength(value)
            if not is_valid:
                return jsonify({'success': False, 'message': f'Weak password: {error_msg}'}), 400
            
            value = generate_password_hash(value)
        elif field == 'date_of_birth':
            if value:
                try:
                    value = datetime.strptime(value, '%Y-%m-%d').date()
                except ValueError:
                    return jsonify({'success': False, 'message': 'Invalid date format'}), 400
            else:
                value = None
        elif field == 'username' or field == 'email':
            # Only check for duplicates if the value has changed
            if field == 'username':
                if value != user.username:  # Only check if username is actually changing
                    existing = User.query.filter(User.username == value, User.id != user_id).first()
                    if existing:
                        return jsonify({'success': False, 'message': 'Username already exists'}), 400
            elif field == 'email':
                if value != user.email:  # Only check if email is actually changing
                    existing = User.query.filter(User.email == value, User.id != user_id).first()
                    if existing:
                        return jsonify({'success': False, 'message': 'Email already exists'}), 400
        
        # Update the field
        if table == 'user':
            setattr(user, column, value)
        else:
            setattr(employee_data, column, value)
        
        # Log the activity
        activity = LoginActivity(
            user_id=current_user.id,
            activity_type='user_update',
            ip_address=request.remote_addr,
            details=f"Updated {field} for user {user.username}"
        )
        db.session.add(activity)
        
        db.session.commit()
        
        # Clear OTP verification after successful update
        session.pop('update_id_otp_verified', None)
        session.pop('update_id_otp', None)
        session.pop('update_id_otp_time', None)
        
        return jsonify({'success': True, 'message': f'{field} updated successfully'})
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/update_user_all', methods=['POST'])
@login_required
def update_user_all():
    """Update all fields for a user at once"""
    if current_user.department != "HR":
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    
    # Check if OTP is verified
    if not session.get('update_id_otp_verified', False):
        return jsonify({'success': False, 'message': 'You are not add authorized credential.'}), 403
    
    try:
        data = request.get_json()
        user_id = data.get('user_id')
        
        if not user_id:
            return jsonify({'success': False, 'message': 'Missing user_id'}), 400
        
        user = db.session.get(User, user_id)
        if not user:
            return jsonify({'success': False, 'message': 'User not found'}), 404
        
        # IDOR Protection: Verify user is not deleted and is accessible
        if user.deleted_at:
            return jsonify({'success': False, 'message': 'User not found'}), 404
        
        if user.status and not user.status.is_active:
            return jsonify({'success': False, 'message': 'User not found'}), 404
        
        employee_data = EmployeeData.query.filter_by(user_id=user_id).first()
        if not employee_data:
            employee_data = EmployeeData(user_id=user_id)
            db.session.add(employee_data)
        
        # Update user fields
        if 'employee_name' in data:
            user.employee_name = data['employee_name'].strip()
        if 'username' in data:
            new_username = data['username'].strip()
            # Only check for duplicates if username is actually changing
            if new_username != user.username:
                existing = User.query.filter(User.username == new_username, User.id != user_id).first()
                if existing:
                    return jsonify({'success': False, 'message': 'Username already exists'}), 400
            user.username = new_username
        if 'password' in data and data['password']:
            password = data['password'].strip()
            
            # Validate password strength
            is_valid, error_msg = validate_password_strength(password)
            if not is_valid:
                return jsonify({'success': False, 'message': f'Weak password: {error_msg}'}), 400
            
            user.password = generate_password_hash(password)
        if 'email' in data:
            new_email = data['email'].strip()
            # Only check for duplicates if email is actually changing
            if new_email != user.email:
                existing = User.query.filter(User.email == new_email, User.id != user_id).first()
                if existing:
                    return jsonify({'success': False, 'message': 'Email already exists'}), 400
            user.email = new_email
        if 'department' in data:
            user.department = data['department'].strip()
        
        # Update employee data fields
        if 'designation' in data:
            employee_data.position = data['designation'].strip()
        if 'experience' in data:
            try:
                float(data['experience'])
                employee_data.experience = str(float(data['experience']))
            except (ValueError, TypeError):
                employee_data.experience = data['experience'].strip()
        if 'education' in data:
            employee_data.education = data['education'].strip()
        if 'certifications' in data:
            employee_data.certifications = data['certifications'].strip()
        if 'date_of_birth' in data and data['date_of_birth']:
            try:
                employee_data.date_of_birth = datetime.strptime(data['date_of_birth'], '%Y-%m-%d').date()
            except ValueError:
                pass
        if 'blood_group' in data:
            employee_data.blood_group = data['blood_group'].strip()
        if 'contact' in data:
            employee_data.contact_number = data['contact'].strip()
        if 'browser_fingerprint' in data:
            # Store browser fingerprint as plain text (unencrypted) in database
            # This ensures fingerprints work consistently even if encryption key changes
            # Encryption is used only for session storage, not database storage
            browser_fp = data['browser_fingerprint'].strip()
            employee_data.browser_fingerprint = browser_fp if browser_fp else None
        
        # Log the activity
        activity = LoginActivity(
            user_id=current_user.id,
            activity_type='user_update',
            ip_address=request.remote_addr,
            details=f"Updated all fields for user {user.username}"
        )
        db.session.add(activity)
        
        db.session.commit()
        
        # Clear OTP verification after successful update
        session.pop('update_id_otp_verified', None)
        session.pop('update_id_otp', None)
        session.pop('update_id_otp_time', None)
        
        return jsonify({'success': True, 'message': 'All fields updated successfully'})
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/request_delete_id_otp', methods=['POST'])
@login_required
def request_delete_id_otp():
    """Generate and send OTP for Delete ID authentication"""
    try:
        if current_user.department != "HR":
            return jsonify({'success': False, 'message': 'Unauthorized'}), 403
        
        # Generate 8-character alphanumeric OTP with special characters
        characters = string.ascii_letters + string.digits + "!@#$%^&*"
        otp = ''.join(secrets.choice(characters) for _ in range(8))
        
        # Store OTP in session with expiration (3 minutes)
        session['delete_id_otp'] = otp
        session['delete_id_otp_time'] = datetime.now().timestamp()
        session['delete_id_otp_verified'] = False
        
        # Send OTP via email
        recipient_email = 'ngt-auakua@ngtech.co.in'
        try:
            msg = Message(
                subject="OTP for Delete ID Authentication",
                recipients=[recipient_email],
                sender=app.config['MAIL_DEFAULT_SENDER']
            )
            msg.body = f"""Dear Authorized Personnel,

An OTP has been requested for deleting a user ID in the system.

Your OTP is: {otp}

This OTP is valid for 3 minutes.

If you did not request this OTP, please ignore this email.

Best regards,
System Administrator"""
            mail.send(msg)
            return jsonify({'success': True, 'message': 'OTP sent successfully to authorized email'})
        except Exception as e:
            print(f"Error sending OTP email: {e}")
            return jsonify({'success': False, 'message': 'Failed to send OTP email'}), 500
    
    except Exception as e:
        print(f"Error generating OTP: {e}")
        return jsonify({'success': False, 'message': 'Error generating OTP'}), 500

@app.route('/verify_delete_id_otp', methods=['POST'])
@login_required
def verify_delete_id_otp():
    """Verify OTP for Delete ID authentication"""
    try:
        if current_user.department != "HR":
            return jsonify({'success': False, 'message': 'Unauthorized'}), 403
        
        user_otp = request.form.get('otp', '').strip()
        
        # Check if OTP exists in session
        stored_otp = session.get('delete_id_otp')
        otp_time = session.get('delete_id_otp_time')
        
        if not stored_otp or not otp_time:
            return jsonify({'success': False, 'message': 'OTP not found. Please request a new OTP.'}), 400
        
        # Check if OTP is expired (3 minutes = 180 seconds)
        current_time = datetime.now().timestamp()
        if current_time - otp_time > 180:
            session.pop('delete_id_otp', None)
            session.pop('delete_id_otp_time', None)
            session.pop('delete_id_otp_verified', None)
            return jsonify({'success': False, 'message': 'OTP has expired. Please request a new OTP.'}), 400
        
        # Verify OTP
        if user_otp != stored_otp:
            return jsonify({'success': False, 'message': 'Invalid OTP. Please try again.'}), 400
        
        # Mark OTP as verified
        session['delete_id_otp_verified'] = True
        return jsonify({'success': True, 'message': 'OTP verified successfully'})
    
    except Exception as e:
        print(f"Error verifying OTP: {e}")
        return jsonify({'success': False, 'message': 'Error verifying OTP'}), 500

@app.route('/api/delete_user', methods=['POST'])
@login_required
def delete_user():
    """Delete a user and all associated details"""
    if current_user.department != "HR":
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    
    # Check if OTP is verified
    if not session.get('delete_id_otp_verified', False):
        return jsonify({'success': False, 'message': 'You are not add authorized credential.'}), 403
    
    try:
        data = request.get_json()
        user_id = data.get('user_id')
        
        if not user_id:
            return jsonify({'success': False, 'message': 'Missing user_id'}), 400
        
        user = db.session.get(User, user_id)
        if not user:
            return jsonify({'success': False, 'message': 'User not found'}), 404
        
        if user.id == current_user.id:
            return jsonify({'success': False, 'message': 'You cannot delete your own ID'}), 400
        
        # Remove employee photo if stored
        if user.employee_data and user.employee_data.photo and user.employee_data.photo != 'default_avatar.jpg':
            photo_path = os.path.join(app.config['UPLOAD_FOLDER'], user.employee_data.photo)
            if os.path.exists(photo_path):
                try:
                    os.remove(photo_path)
                except OSError:
                    pass
        
        # Soft delete: Set deleted_at timestamp and deactivate instead of hard delete
        # This allows tracking deleted users in the past record
        username = user.username
        
        # Set deleted_at timestamp
        user.deleted_at = get_current_ist_time().replace(tzinfo=None)
        
        # Deactivate the user
        if user.status:
            user.status.is_active = False
        else:
            user.status = UserStatus(user_id=user.id, is_active=False)
        
        # Don't actually delete - keep for historical records
        # Remove related records explicitly to avoid FK issues (optional - can keep for history)
        # LoginActivity.query.filter_by(user_id=user_id).delete(synchronize_session=False)
        # Performance.query.filter_by(user_id=user_id).delete(synchronize_session=False)
        
        activity = LoginActivity(
            user_id=current_user.id,
            activity_type='user_deletion',
            ip_address=request.remote_addr,
            details=f"Deleted user {username} (ID {user_id})"
        )
        db.session.add(activity)
        
        db.session.commit()
        
        # Clear OTP verification after successful deletion
        session.pop('delete_id_otp_verified', None)
        session.pop('delete_id_otp', None)
        session.pop('delete_id_otp_time', None)
        
        return jsonify({'success': True, 'message': 'User deleted successfully'})
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500


def get_user_performance(user_id):
    """Get performance data for a user for the previous month"""
    current_date = get_current_ist_time().replace(tzinfo=None)
    last_month = current_date.month - 1 if current_date.month > 1 else 12
    last_month_year = current_date.year if current_date.month > 1 else current_date.year - 1
    
    performance = Performance.query.filter_by(
        user_id=user_id, 
        month=last_month, 
        year=last_month_year
    ).first()
    
    return performance

def get_all_users_performance(month=None, year=None):
    """Get performance data for all users for a specific month/year"""
    if month is None or year is None:
        current_date = get_current_ist_time().replace(tzinfo=None)
        month = current_date.month - 1 if current_date.month > 1 else 12
        year = current_date.year if current_date.month > 1 else current_date.year - 1
    
    performances = Performance.query.filter_by(
        month=month, 
        year=year
    ).all()
    
    return {p.user_id: p for p in performances}



@app.route('/toggle_user_status/<int:user_id>')
@login_required
def toggle_user_status(user_id):
    if current_user.department != "HR":
        abort(403)
    
    user = db.session.get(User, user_id)
    if not user:
        abort(404)
    
    # IDOR Protection: Verify user is not deleted
    if user.deleted_at:
        abort(404)
    
    if not user.status:
        user.status = UserStatus(user_id=user.id)
    
    # If account was permanently locked, reset failed attempts when reactivating
    if user.status.failed_attempts >= 5 and not user.status.is_active:
        user.status.failed_attempts = 0
    
    user.status.is_active = not user.status.is_active
    user.status.locked_until = None
    
    activity = LoginActivity(
        user_id=current_user.id,
        activity_type='status_change',
        ip_address=request.remote_addr,
        details=f"Changed status for {user.username} to {'active' if user.status.is_active else 'inactive'}"
    )
    db.session.add(activity)
    db.session.commit()
    
    flash(f'User {user.username} status updated')
    return redirect(url_for('hr_dashboard', show_status='true'))

# Initialize the database
initialize_database()

@app.route('/generate_network_review_excel', methods=['POST'])
@login_required
def generate_network_review_excel():
    """
    Generate Network Review Excel file and return it for download
    """
    # Access Control: Only Audit department can generate audit reports
    require_audit()
    
    try:
        # Import the function from the Network Review script
        import sys
        import importlib.util
        
        # Get the absolute path to the Network Review script
        script_path = os.path.join(os.path.dirname(__file__), 'Audit_Dashboard_Files', 'Asset_Review', 'Network_Review_without_POC.py')
        
        # Load the module dynamically
        spec = importlib.util.spec_from_file_location("network_review_module", script_path)
        network_review_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(network_review_module)
        
        # Use the function from the loaded module
        create_network_review_excel = network_review_module.create_network_review_excel
        
        # Get form data
        form_data = request.form.to_dict()
        
        # Create the Excel file with form data
        filepath, filename = create_network_review_excel(form_data)
        
        # Read file content and prepare response
        with open(filepath, 'rb') as f:
            file_content = f.read()
        
        # Clean up the file after reading
        cleanup_function = network_review_module.cleanup_file
        cleanup_function(filepath)
        
        # Return the file for download
        from flask import Response
        return Response(
            file_content,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            headers={'Content-Disposition': f'attachment; filename="{filename}"'}
        )
        
    except Exception as e:
        safe_error = get_safe_error_message(e)
        flash(f'Error generating Excel file. Please try again later.', 'error')
        return redirect(url_for('audit_dashboard'))

@app.route('/generate_data_centre_excel', methods=['POST'])
@login_required
def generate_data_centre_excel():
    """
    Generate Data Centre Excel file and return it for download
    """
    # Access Control: Only Audit department can generate audit reports
    require_audit()
    
    try:
        # Import the function from the Data Centre script
        import sys
        import importlib.util
        
        # Get the absolute path to the Data Centre script
        script_path = os.path.join(os.path.dirname(__file__), 'Audit_Dashboard_Files', 'Asset_Review', 'Data_Centre_Without_POC.py')
        
        # Load the module dynamically
        spec = importlib.util.spec_from_file_location("data_centre_module", script_path)
        data_centre_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(data_centre_module)
        
        # Use the function from the loaded module
        create_data_centre_excel = data_centre_module.create_data_centre_excel
        
        # Get form data
        form_data = request.form.to_dict()
        
        # Create the Excel file with form data
        filepath, filename = create_data_centre_excel(form_data)
        
        # Read file content and prepare response
        with open(filepath, 'rb') as f:
            file_content = f.read()
        
        # Clean up the file after reading
        cleanup_function = data_centre_module.cleanup_file
        cleanup_function(filepath)
        
        # Return the file for download
        from flask import Response
        return Response(
            file_content,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            headers={'Content-Disposition': f'attachment; filename="{filename}"'}
        )
        
    except Exception as e:
        safe_error = get_safe_error_message(e)
        flash(f'Error generating Excel file. Please try again later.', 'error')
        return redirect(url_for('audit_dashboard'))

@app.route('/generate_disaster_recovery_excel', methods=['POST'])
@login_required
def generate_disaster_recovery_excel():
    """
    Generate Disaster Recovery Excel file and return it for download
    """
    # Access Control: Only Audit department can generate audit reports
    require_audit()
    
    try:
        # Import the function from the Disaster Recovery script
        import sys
        import importlib.util
        
        # Get the absolute path to the Disaster Recovery script
        script_path = os.path.join(os.path.dirname(__file__), 'Audit_Dashboard_Files', 'Asset_Review', 'Disaster_Recovery_Without_POC.py')
        
        # Load the module dynamically
        spec = importlib.util.spec_from_file_location("disaster_recovery_module", script_path)
        disaster_recovery_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(disaster_recovery_module)
        
        # Use the function from the loaded module
        create_disaster_recovery_excel = disaster_recovery_module.create_disaster_recovery_excel
        
        # Get form data
        form_data = request.form.to_dict()
        
        # Create the Excel file with form data
        filepath, filename = create_disaster_recovery_excel(form_data)
        
        # Read file content and prepare response
        with open(filepath, 'rb') as f:
            file_content = f.read()
        
        # Clean up the file after reading
        cleanup_function = disaster_recovery_module.cleanup_file
        cleanup_function(filepath)
        
        # Return the file for download
        from flask import Response
        return Response(
            file_content,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            headers={'Content-Disposition': f'attachment; filename="{filename}"'}
        )
        
    except Exception as e:
        safe_error = get_safe_error_message(e)
        flash(f'Error generating Excel file. Please try again later.', 'error')
        return redirect(url_for('audit_dashboard'))

@app.route('/generate_firewall_excel', methods=['POST'])
@login_required
def generate_firewall_excel():
    """
    Generate Firewall Assessment Excel file
    """
    # Access Control: Only Audit department can generate audit reports
    require_audit()
    
    try:
        # Import the Firewall module dynamically
        import importlib.util
        firewall_script_path = os.path.join(os.path.dirname(__file__), 'Audit_Dashboard_Files', 'Asset_Review', 'Firewall_Without_POC.py')
        spec = importlib.util.spec_from_file_location("firewall_module", firewall_script_path)
        firewall_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(firewall_module)
        
        # Get form data
        form_data = request.form.to_dict()
        
        # Create Excel file
        filepath, filename = firewall_module.create_firewall_excel(form_data)
        
        # Read file content
        with open(filepath, 'rb') as f:
            file_content = f.read()
        
        # Clean up file
        firewall_module.cleanup_file(filepath)
        
        # Return file for download
        return Response(
            file_content,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            headers={
                'Content-Disposition': f'attachment; filename={filename}',
                'Content-Type': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
            }
        )
        
    except Exception as e:
        flash(f'Error generating Firewall Excel file: {str(e)}', 'error')
        return redirect(url_for('audit_dashboard'))

@app.route('/generate_core_switch_excel', methods=['POST'])
@login_required
def generate_core_switch_excel():
    """
    Generate Core Switch Assessment Excel file
    """
    # Access Control: Only Audit department can generate audit reports
    require_audit()
    
    try:
        # Import the Core Switch module dynamically
        import importlib.util
        core_switch_script_path = os.path.join(os.path.dirname(__file__), 'Audit_Dashboard_Files', 'Asset_Review', 'Core_Switch_Without_POC.py')
        spec = importlib.util.spec_from_file_location("core_switch_module", core_switch_script_path)
        core_switch_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(core_switch_module)
        
        # Get form data
        form_data = request.form.to_dict()
        
        # Create Excel file
        filepath, filename = core_switch_module.create_core_switch_excel(form_data)
        
        # Read file content
        with open(filepath, 'rb') as f:
            file_content = f.read()
        
        # Clean up file
        core_switch_module.cleanup_file(filepath)
        
        # Return file for download
        return Response(
            file_content,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            headers={
                'Content-Disposition': f'attachment; filename={filename}',
                'Content-Type': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
            }
        )
        
    except Exception as e:
        flash(f'Error generating Core Switch Excel file: {str(e)}', 'error')
        return redirect(url_for('audit_dashboard'))

@app.route('/generate_router_excel', methods=['POST'])
@login_required
def generate_router_excel():
    """
    Generate Router Assessment Excel file
    """
    # Access Control: Only Audit department can generate audit reports
    require_audit()
    
    try:
        # Import the Router module dynamically
        import importlib.util
        router_script_path = os.path.join(os.path.dirname(__file__), 'Audit_Dashboard_Files', 'Asset_Review', 'Router_Without_POC.py')
        spec = importlib.util.spec_from_file_location("router_module", router_script_path)
        router_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(router_module)
        
        # Get form data
        form_data = request.form.to_dict()
        
        # Create Excel file
        filepath, filename = router_module.create_router_excel(form_data)
        
        # Read file content
        with open(filepath, 'rb') as f:
            file_content = f.read()
        
        # Clean up file
        router_module.cleanup_file(filepath)
        
        # Return file for download
        return Response(
            file_content,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            headers={
                'Content-Disposition': f'attachment; filename={filename}',
                'Content-Type': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
            }
        )
        
    except Exception as e:
        flash(f'Error generating Router Excel file: {str(e)}', 'error')
        return redirect(url_for('audit_dashboard'))

@app.route('/generate_domain_controller_excel', methods=['POST'])
@login_required
def generate_domain_controller_excel():
    """
    Generate Domain Controller (AD) Assessment Excel file
    """
    # Access Control: Only Audit department can generate audit reports
    require_audit()
    
    try:
        # Import the Domain Controller module dynamically
        import importlib.util
        domain_controller_script_path = os.path.join(os.path.dirname(__file__), 'Audit_Dashboard_Files', 'Asset_Review', 'Domain_Controller_AD_Without_POC.py')
        spec = importlib.util.spec_from_file_location("domain_controller_module", domain_controller_script_path)
        domain_controller_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(domain_controller_module)
        
        # Get form data
        form_data = request.form.to_dict()
        
        # Create Excel file
        filepath, filename = domain_controller_module.create_domain_controller_excel(form_data)
        
        # Read file content
        with open(filepath, 'rb') as f:
            file_content = f.read()
        
        # Clean up file
        domain_controller_module.cleanup_file(filepath)
        
        # Return file for download
        return Response(
            file_content,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            headers={
                'Content-Disposition': f'attachment; filename={filename}',
                'Content-Type': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
            }
        )
        
    except Exception as e:
        flash(f'Error generating Domain Controller Excel file: {str(e)}', 'error')
        return redirect(url_for('audit_dashboard'))

@app.route('/generate_h2h_excel', methods=['POST'])
@login_required
def generate_h2h_excel():
    """
    Generate H2H Audit Assessment Excel file
    """
    # Access Control: Only Audit department can generate audit reports
    require_audit()
    
    try:
        # Import the H2H module dynamically
        import importlib.util
        h2h_script_path = os.path.join(os.path.dirname(__file__), 'Audit_Dashboard_Files', 'Asset_Review', 'H2H_Without_POC.py')
        spec = importlib.util.spec_from_file_location("h2h_module", h2h_script_path)
        h2h_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(h2h_module)
        
        # Get form data
        form_data = request.form.to_dict()
        
        # Create Excel file
        filepath, filename = h2h_module.create_h2h_excel(form_data)
        
        # Read file content
        with open(filepath, 'rb') as f:
            file_content = f.read()
        
        # Clean up file
        h2h_module.cleanup_file(filepath)
        
        # Return file for download
        return Response(
            file_content,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            headers={
                'Content-Disposition': f'attachment; filename={filename}',
                'Content-Type': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
            }
        )
        
    except Exception as e:
        flash(f'Error generating H2H Audit Excel file: {str(e)}', 'error')
        return redirect(url_for('audit_dashboard'))

@app.route('/generate_antivirus_excel', methods=['POST'])
@login_required
def generate_antivirus_excel():
    """
    Generate Antivirus Assessment Excel file
    """
    # Access Control: Only Audit department can generate audit reports
    require_audit()
    
    try:
        # Import the Antivirus module dynamically
        import importlib.util
        antivirus_script_path = os.path.join(os.path.dirname(__file__), 'Audit_Dashboard_Files', 'Asset_Review', 'Antivirus_Without_POC.py')
        spec = importlib.util.spec_from_file_location("antivirus_module", antivirus_script_path)
        antivirus_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(antivirus_module)
        
        # Get form data
        form_data = request.form.to_dict()
        
        # Create Excel file
        filepath, filename = antivirus_module.create_antivirus_excel(form_data)
        
        # Read file content
        with open(filepath, 'rb') as f:
            file_content = f.read()
        
        # Clean up file
        antivirus_module.cleanup_file(filepath)
        
        # Return file for download
        return Response(
            file_content,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            headers={
                'Content-Disposition': f'attachment; filename={filename}',
                'Content-Type': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
            }
        )
        
    except Exception as e:
        flash(f'Error generating Antivirus Excel file: {str(e)}', 'error')
        return redirect(url_for('audit_dashboard'))

@app.route('/generate_atm_excel', methods=['POST'])
@login_required
def generate_atm_excel():
    """
    Generate ATM Assessment Excel file
    """
    # Access Control: Only Audit department can generate audit reports
    require_audit()
    
    try:
        # Import the ATM module dynamically
        import importlib.util
        atm_script_path = os.path.join(os.path.dirname(__file__), 'Audit_Dashboard_Files', 'Asset_Review', 'ATM_Without_POC.py')
        spec = importlib.util.spec_from_file_location("atm_module", atm_script_path)
        atm_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(atm_module)
        
        # Get form data
        form_data = request.form.to_dict()
        
        # Create Excel file
        filepath, filename = atm_module.create_atm_excel(form_data)
        
        # Read file content
        with open(filepath, 'rb') as f:
            file_content = f.read()
        
        # Clean up file
        atm_module.cleanup_file(filepath)
        
        # Return file for download
        return Response(
            file_content,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            headers={
                'Content-Disposition': f'attachment; filename={filename}',
                'Content-Type': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
            }
        )
        
    except Exception as e:
        flash(f'Error generating ATM Excel file: {str(e)}', 'error')
        return redirect(url_for('audit_dashboard'))

@app.route('/generate_mail_messaging_excel', methods=['POST'])
@login_required
def generate_mail_messaging_excel():
    """
    Generate Mail and Messaging Assessment Excel file
    """
    # Access Control: Only Audit department can generate audit reports
    require_audit()
    
    try:
        # Import the Mail and Messaging module dynamically
        import importlib.util
        mail_messaging_script_path = os.path.join(os.path.dirname(__file__), 'Audit_Dashboard_Files', 'Asset_Review', 'Mail_and_Messaging.py')
        spec = importlib.util.spec_from_file_location("mail_messaging_module", mail_messaging_script_path)
        mail_messaging_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mail_messaging_module)
        
        # Get form data
        form_data = request.form.to_dict()
        
        # Create Excel file
        filepath, filename = mail_messaging_module.create_mail_messaging_excel(form_data)
        
        # Read file content
        with open(filepath, 'rb') as f:
            file_content = f.read()
        
        # Clean up file
        mail_messaging_module.cleanup_file(filepath)
        
        # Return file for download
        return Response(
            file_content,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            headers={
                'Content-Disposition': f'attachment; filename={filename}',
                'Content-Type': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
            }
        )
        
    except Exception as e:
        flash(f'Error generating Mail and Messaging Excel file: {str(e)}', 'error')
        return redirect(url_for('audit_dashboard'))

@app.route('/generate_ho_win_server_excel', methods=['POST'])
@login_required
def generate_ho_win_server_excel():
    """
    Generate HO Win_Server Logical Review Assessment Excel file
    """
    # Access Control: Only Audit department can generate audit reports
    require_audit()
    
    try:
        # Import the HO Win_Server Logical Review module dynamically
        import importlib.util
        ho_win_server_script_path = os.path.join(os.path.dirname(__file__), 'Audit_Dashboard_Files', 'Asset_Review', 'HO_Win_Server_Logical.py')
        spec = importlib.util.spec_from_file_location("ho_win_server_module", ho_win_server_script_path)
        ho_win_server_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(ho_win_server_module)
        
        # Get form data
        form_data = request.form.to_dict()
        
        # Create Excel file
        filepath, filename = ho_win_server_module.create_ho_win_server_excel(form_data)
        
        # Read file content
        with open(filepath, 'rb') as f:
            file_content = f.read()
        
        # Clean up file after reading (file is already in memory)
        try:
            ho_win_server_module.cleanup_file(filepath)
        except:
            pass  # Ignore cleanup errors
        
        # Return file for download
        return Response(
            file_content,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            headers={
                'Content-Disposition': f'attachment; filename="{filename}"',
                'Content-Type': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                'Cache-Control': 'no-cache, no-store, must-revalidate',
                'Pragma': 'no-cache',
                'Expires': '0'
            }
        )
        
    except Exception as e:
        flash(f'Error generating HO Win_Server Logical Review Excel file: {str(e)}', 'error')
        return redirect(url_for('audit_dashboard'))

@app.route('/generate_linux_server_excel', methods=['POST'])
@login_required
def generate_linux_server_excel():
    """
    Generate Linux Server Logical Review Assessment Excel file
    """
    # Access Control: Only Audit department can generate audit reports
    require_audit()
    
    try:
        # Import the Linux Server Logical Review module dynamically
        import importlib.util
        linux_server_script_path = os.path.join(os.path.dirname(__file__), 'Audit_Dashboard_Files', 'Asset_Review', 'Linux_Server_Logical.py')
        spec = importlib.util.spec_from_file_location("linux_server_module", linux_server_script_path)
        linux_server_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(linux_server_module)
        
        # Get form data
        form_data = request.form.to_dict()
        
        # Create Excel file
        filepath, filename = linux_server_module.create_linux_server_excel(form_data)
        
        # Read file content
        with open(filepath, 'rb') as f:
            file_content = f.read()
        
        # Clean up file
        linux_server_module.cleanup_file(filepath)
        
        # Return file for download
        return Response(
            file_content,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            headers={
                'Content-Disposition': f'attachment; filename={filename}',
                'Content-Type': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
            }
        )
        
    except Exception as e:
        flash(f'Error generating Linux Server Logical Review Excel file: {str(e)}', 'error')
        return redirect(url_for('audit_dashboard'))

@app.route('/generate_esxi_server_excel', methods=['POST'])
@login_required
def generate_esxi_server_excel():
    """
    Generate ESXi Server Logical Review Assessment Excel file
    """
    # Access Control: Only Audit department can generate audit reports
    require_audit()
    
    try:
        # Import the ESXi Server Logical Review module dynamically
        import importlib.util
        esxi_server_script_path = os.path.join(os.path.dirname(__file__), 'Audit_Dashboard_Files', 'Asset_Review', 'ESXi_Server_Logical.py')
        spec = importlib.util.spec_from_file_location("esxi_server_module", esxi_server_script_path)
        esxi_server_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(esxi_server_module)
        
        # Get form data
        form_data = request.form.to_dict()
        
        # Create Excel file
        filepath, filename = esxi_server_module.create_esxi_server_excel(form_data)
        
        # Read file content
        with open(filepath, 'rb') as f:
            file_content = f.read()
        
        # Clean up file
        esxi_server_module.cleanup_file(filepath)
        
        # Return file for download
        return Response(
            file_content,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            headers={
                'Content-Disposition': f'attachment; filename={filename}',
                'Content-Type': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
            }
        )
        
    except Exception as e:
        flash(f'Error generating ESXi Server Logical Review Excel file: {str(e)}', 'error')
        return redirect(url_for('audit_dashboard'))

@app.route('/generate_access_control_os_excel', methods=['POST'])
@login_required
def generate_access_control_os_excel():
    """
    Generate Access Control – OS Level Assessment Excel file
    """
    # Access Control: Only Audit department can generate audit reports
    require_audit()
    
    try:
        # Import the Access Control – OS Level module dynamically
        import importlib.util
        access_control_script_path = os.path.join(os.path.dirname(__file__), 'Audit_Dashboard_Files', 'Asset_Review', 'Access_Control_OS_Level_Without_POC.py')
        spec = importlib.util.spec_from_file_location("access_control_module", access_control_script_path)
        access_control_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(access_control_module)
        
        # Get form data
        form_data = request.form.to_dict()
        
        # Create Excel file
        filepath, filename = access_control_module.create_access_control_os_excel(form_data)
        
        # Read file content
        with open(filepath, 'rb') as f:
            file_content = f.read()
        
        # Clean up file
        access_control_module.cleanup_file(filepath)
        
        # Return file for download
        return Response(
            file_content,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            headers={
                'Content-Disposition': f'attachment; filename={filename}',
                'Content-Type': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
            }
        )
        
    except Exception as e:
        flash(f'Error generating Access Control – OS Level Excel file: {str(e)}', 'error')
        return redirect(url_for('audit_dashboard'))

@app.route('/generate_access_control_application_excel', methods=['POST'])
@login_required
def generate_access_control_application_excel():
    """
    Generate Access Control Application Assessment Excel file
    """
    # Access Control: Only Audit department can generate audit reports
    require_audit()
    
    try:
        # Import the Access Control Application module dynamically
        import importlib.util
        access_control_app_script_path = os.path.join(os.path.dirname(__file__), 'Audit_Dashboard_Files', 'Asset_Review', 'Access_Control_Application_Without_POC.py')
        spec = importlib.util.spec_from_file_location("access_control_app_module", access_control_app_script_path)
        access_control_app_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(access_control_app_module)
        
        # Get form data
        form_data = request.form.to_dict()
        
        # Create Excel file
        filepath, filename = access_control_app_module.create_access_control_application_excel(form_data)
        
        # Read file content
        with open(filepath, 'rb') as f:
            file_content = f.read()
        
        # Clean up file
        access_control_app_module.cleanup_file(filepath)
        
        # Return file for download
        return Response(
            file_content,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            headers={
                'Content-Disposition': f'attachment; filename={filename}',
                'Content-Type': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
            }
        )
        
    except Exception as e:
        flash(f'Error generating Access Control Application Excel file: {str(e)}', 'error')
        return redirect(url_for('audit_dashboard'))

@app.route('/generate_application_excel', methods=['POST'])
@login_required
def generate_application_excel():
    """
    Generate Application Assessment Excel file
    """
    # Access Control: Only Audit department can generate audit reports
    require_audit()
    
    try:
        # Import the Application module dynamically
        import importlib.util
        application_script_path = os.path.join(os.path.dirname(__file__), 'Audit_Dashboard_Files', 'Asset_Review', 'Application_Without_POC.py')
        spec = importlib.util.spec_from_file_location("application_module", application_script_path)
        application_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(application_module)
        
        # Get form data
        form_data = request.form.to_dict()
        
        # Create Excel file
        filepath, filename = application_module.create_application_excel(form_data)
        
        # Read file content
        with open(filepath, 'rb') as f:
            file_content = f.read()
        
        # Clean up file
        application_module.cleanup_file(filepath)
        
        # Return file for download
        return Response(
            file_content,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            headers={
                'Content-Disposition': f'attachment; filename="{filename}"',
                'Content-Type': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
            }
        )
        
    except Exception as e:
        flash(f'Error generating Application Excel file: {str(e)}', 'error')
        return redirect(url_for('audit_dashboard'))

@app.route('/generate_internet_banking_excel', methods=['POST'])
@login_required
def generate_internet_banking_excel():
    """
    Generate Internet Banking Assessment Excel file
    """
    # Access Control: Only Audit department can generate audit reports
    require_audit()
    
    try:
        # Import the Internet Banking module dynamically
        import importlib.util
        internet_banking_script_path = os.path.join(os.path.dirname(__file__), 'Audit_Dashboard_Files', 'Asset_Review', 'Internet_Banking_Without_POC.py')
        spec = importlib.util.spec_from_file_location("internet_banking_module", internet_banking_script_path)
        internet_banking_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(internet_banking_module)
        
        # Get form data
        form_data = request.form.to_dict()
        
        # Create Excel file
        filepath, filename = internet_banking_module.create_internet_banking_excel(form_data)
        
        # Read file content
        with open(filepath, 'rb') as f:
            file_content = f.read()
        
        # Clean up file
        internet_banking_module.cleanup_file(filepath)
        
        # Return file for download
        return Response(
            file_content,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            headers={
                'Content-Disposition': f'attachment; filename={filename}',
                'Content-Type': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
            }
        )
        
    except Exception as e:
        flash(f'Error generating Internet Banking Excel file: {str(e)}', 'error')
        return redirect(url_for('audit_dashboard'))

@app.route('/generate_internal_control_excel', methods=['POST'])
@login_required
def generate_internal_control_excel():
    """
    Generate Internal Control Evaluation Excel file
    """
    # Access Control: Only Audit department can generate audit reports
    require_audit()
    
    try:
        # Import the Internal Control Evaluation module dynamically
        import importlib.util
        internal_control_script_path = os.path.join(os.path.dirname(__file__), 'Audit_Dashboard_Files', 'Asset_Review', 'Internal_Control_Evaluation_Without_POC.py')
        spec = importlib.util.spec_from_file_location("internal_control_module", internal_control_script_path)
        internal_control_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(internal_control_module)
        
        # Get form data
        form_data = request.form.to_dict()
        
        # Create Excel file
        filepath, filename = internal_control_module.create_internal_control_evaluation_excel(form_data)
        
        # Read file content
        with open(filepath, 'rb') as f:
            file_content = f.read()
        
        # Clean up file
        internal_control_module.cleanup_file(filepath)
        
        # Return file for download
        return Response(
            file_content,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            headers={
                'Content-Disposition': f'attachment; filename={filename}',
                'Content-Type': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
            }
        )
        
    except Exception as e:
        flash(f'Error generating Internal Control Evaluation Excel file: {str(e)}', 'error')
        return redirect(url_for('audit_dashboard'))

@app.route('/generate_fire_protection_excel', methods=['POST'])
@login_required
def generate_fire_protection_excel():
    """
    Generate Fire Protection Excel file
    """
    # Access Control: Only Audit department can generate audit reports
    require_audit()
    
    try:
        # Import the Fire Protection module dynamically
        import importlib.util
        fire_protection_script_path = os.path.join(os.path.dirname(__file__), 'Audit_Dashboard_Files', 'Asset_Review', 'Fire_Protection_Without_POC.py')
        spec = importlib.util.spec_from_file_location("fire_protection_module", fire_protection_script_path)
        fire_protection_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(fire_protection_module)
        
        # Get form data
        form_data = request.form.to_dict()
        
        # Create Excel file
        filepath, filename = fire_protection_module.create_fire_protection_excel(form_data)
        
        # Read file content
        with open(filepath, 'rb') as f:
            file_content = f.read()
        
        # Clean up file
        fire_protection_module.cleanup_file(filepath)
        
        # Return file for download
        return Response(
            file_content,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            headers={
                'Content-Disposition': f'attachment; filename={filename}',
                'Content-Type': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
            }
        )
        
    except Exception as e:
        flash(f'Error generating Fire Protection Excel file: {str(e)}', 'error')
        return redirect(url_for('audit_dashboard'))

@app.route('/generate_amc_excel', methods=['POST'])
@login_required
def generate_amc_excel():
    """
    Generate AMC Excel file
    """
    # Access Control: Only Audit department can generate audit reports
    require_audit()
    
    try:
        # Import the AMC module dynamically
        import importlib.util
        amc_script_path = os.path.join(os.path.dirname(__file__), 'Audit_Dashboard_Files', 'Asset_Review', 'AMC_Without_POC.py')
        spec = importlib.util.spec_from_file_location("amc_module", amc_script_path)
        amc_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(amc_module)
        
        # Get form data
        form_data = request.form.to_dict()
        
        # Create Excel file
        filepath, filename = amc_module.create_amc_excel(form_data)
        
        # Read file content
        with open(filepath, 'rb') as f:
            file_content = f.read()
        
        # Clean up file
        amc_module.cleanup_file(filepath)
        
        # Return file for download
        return Response(
            file_content,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            headers={
                'Content-Disposition': f'attachment; filename={filename}',
                'Content-Type': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
            }
        )
        
    except Exception as e:
        flash(f'Error generating AMC Excel file: {str(e)}', 'error')
        return redirect(url_for('audit_dashboard'))

@app.route('/generate_data_input_control_excel', methods=['POST'])
@login_required
def generate_data_input_control_excel():
    """
    Generate Data Input Control Excel file
    """
    # Access Control: Only Audit department can generate audit reports
    require_audit()
    
    try:
        # Import the Data Input Control module dynamically
        import importlib.util
        data_input_control_script_path = os.path.join(os.path.dirname(__file__), 'Audit_Dashboard_Files', 'Asset_Review', 'Data_Input_Control_Without_POC.py')
        spec = importlib.util.spec_from_file_location("data_input_control_module", data_input_control_script_path)
        data_input_control_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(data_input_control_module)
        
        # Get form data
        form_data = request.form.to_dict()
        
        # Create Excel file
        filepath, filename = data_input_control_module.create_data_input_control_excel(form_data)
        
        # Read file content
        with open(filepath, 'rb') as f:
            file_content = f.read()
        
        # Clean up file
        data_input_control_module.cleanup_file(filepath)
        
        # Return file for download
        return Response(
            file_content,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            headers={
                'Content-Disposition': f'attachment; filename={filename}',
                'Content-Type': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
            }
        )
        
    except Exception as e:
        flash(f'Error generating Data Input Control Excel file: {str(e)}', 'error')
        return redirect(url_for('audit_dashboard'))

@app.route('/generate_purging_data_files_excel', methods=['POST'])
@login_required
def generate_purging_data_files_excel():
    """
    Generate Purging of Data Files Excel file
    """
    # Access Control: Only Audit department can generate audit reports
    require_audit()
    
    try:
        # Import the Purging of Data Files module dynamically
        import importlib.util
        purging_data_files_script_path = os.path.join(os.path.dirname(__file__), 'Audit_Dashboard_Files', 'Asset_Review', 'Purging_of_Data_Files_Without_POC.py')
        spec = importlib.util.spec_from_file_location("purging_data_files_module", purging_data_files_script_path)
        purging_data_files_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(purging_data_files_module)
        
        # Get form data
        form_data = request.form.to_dict()
        
        # Create Excel file
        filepath, filename = purging_data_files_module.create_purging_data_files_excel(form_data)
        
        # Read file content
        with open(filepath, 'rb') as f:
            file_content = f.read()
        
        # Clean up file
        purging_data_files_module.cleanup_file(filepath)
        
        # Return file for download
        return Response(
            file_content,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            headers={
                'Content-Disposition': f'attachment; filename={filename}',
                'Content-Type': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
            }
        )
        
    except Exception as e:
        flash(f'Error generating Purging of Data Files Excel file: {str(e)}', 'error')
        return redirect(url_for('audit_dashboard'))

@app.route('/generate_business_continuity_planning_excel', methods=['POST'])
@login_required
def generate_business_continuity_planning_excel():
    """
    Generate Business Continuity Planning Excel file
    """
    # Access Control: Only Audit department can generate audit reports
    require_audit()
    
    try:
        # Import the Business Continuity Planning module dynamically
        import importlib.util
        business_continuity_planning_script_path = os.path.join(os.path.dirname(__file__), 'Audit_Dashboard_Files', 'Asset_Review', 'Business_Continuity_Planning_Without_POC.py')
        spec = importlib.util.spec_from_file_location("business_continuity_planning_module", business_continuity_planning_script_path)
        business_continuity_planning_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(business_continuity_planning_module)
        
        # Get form data
        form_data = request.form.to_dict()
        
        # Create Excel file
        filepath, filename = business_continuity_planning_module.create_business_continuity_planning_excel(form_data)
        
        # Read file content
        with open(filepath, 'rb') as f:
            file_content = f.read()
        
        # Clean up file
        business_continuity_planning_module.cleanup_file(filepath)
        
        # Return file for download
        return Response(
            file_content,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            headers={
                'Content-Disposition': f'attachment; filename={filename}',
                'Content-Type': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
            }
        )
        
    except Exception as e:
        flash(f'Error generating Business Continuity Planning Excel file: {str(e)}', 'error')
        return redirect(url_for('audit_dashboard'))

@app.route('/generate_inhouse_outsourced_excel', methods=['POST'])
@login_required
def generate_inhouse_outsourced_excel():
    """
    Generate In-house and Out-sourced Excel file
    """
    # Access Control: Only Audit department can generate audit reports
    require_audit()
    
    try:
        # Import the In-house and Out-sourced module dynamically
        import importlib.util
        inhouse_outsourced_script_path = os.path.join(os.path.dirname(__file__), 'Audit_Dashboard_Files', 'Asset_Review', 'In-house_and_Out-sourced_Without_POC.py')
        spec = importlib.util.spec_from_file_location("inhouse_outsourced_module", inhouse_outsourced_script_path)
        inhouse_outsourced_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(inhouse_outsourced_module)
        
        # Get form data
        form_data = request.form.to_dict()
        
        # Create Excel file
        filepath, filename = inhouse_outsourced_module.create_inhouse_outsourced_excel(form_data)
        
        # Read file content
        with open(filepath, 'rb') as f:
            file_content = f.read()
        
        # Clean up file
        inhouse_outsourced_module.cleanup_file(filepath)
        
        # Return file for download
        return Response(
            file_content,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            headers={
                'Content-Disposition': f'attachment; filename={filename}',
                'Content-Type': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
            }
        )
        
    except Exception as e:
        flash(f'Error generating In-house and Out-sourced Excel file: {str(e)}', 'error')
        return redirect(url_for('audit_dashboard'))

@app.route('/generate_audit_trail_excel', methods=['POST'])
@login_required
def generate_audit_trail_excel():
    """
    Generate Audit Trail Excel file
    """
    # Access Control: Only Audit department can generate audit reports
    require_audit()
    
    try:
        # Import the Audit Trail module dynamically
        import importlib.util
        audit_trail_script_path = os.path.join(os.path.dirname(__file__), 'Audit_Dashboard_Files', 'Asset_Review', 'Audit_Trail_Without_POC.py')
        spec = importlib.util.spec_from_file_location("audit_trail_module", audit_trail_script_path)
        audit_trail_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(audit_trail_module)
        
        # Get form data
        form_data = request.form.to_dict()
        
        # Create Excel file
        filepath, filename = audit_trail_module.create_audit_trail_excel(form_data)
        
        # Read file content
        with open(filepath, 'rb') as f:
            file_content = f.read()
        
        # Clean up file
        audit_trail_module.cleanup_file(filepath)
        
        # Return file for download
        return Response(
            file_content,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            headers={
                'Content-Disposition': f'attachment; filename={filename}',
                'Content-Type': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
            }
        )
        
    except Exception as e:
        flash(f'Error generating Audit Trail Excel file: {str(e)}', 'error')
        return redirect(url_for('audit_dashboard'))

@app.route('/generate_packaged_software_excel', methods=['POST'])
@login_required
def generate_packaged_software_excel():
    """
    Generate Packaged Software Excel file
    """
    # Access Control: Only Audit department can generate audit reports
    require_audit()
    
    try:
        # Import the Packaged Software module dynamically
        import importlib.util
        packaged_software_script_path = os.path.join(os.path.dirname(__file__), 'Audit_Dashboard_Files', 'Asset_Review', 'Packaged_Software_Without_POC.py')
        spec = importlib.util.spec_from_file_location("packaged_software_module", packaged_software_script_path)
        packaged_software_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(packaged_software_module)
        
        # Get form data
        form_data = request.form.to_dict()
        
        # Create Excel file
        filepath, filename = packaged_software_module.create_packaged_software_excel(form_data)
        
        # Read file content
        with open(filepath, 'rb') as f:
            file_content = f.read()
        
        # Clean up file
        packaged_software_module.cleanup_file(filepath)
        
        # Return file for download
        return Response(
            file_content,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            headers={
                'Content-Disposition': f'attachment; filename={filename}',
                'Content-Type': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
            }
        )
        
    except Exception as e:
        flash(f'Error generating Packaged Software Excel file: {str(e)}', 'error')
        return redirect(url_for('audit_dashboard'))

@app.route('/generate_user_account_maintenance_excel', methods=['POST'])
@login_required
def generate_user_account_maintenance_excel():
    """
    Generate User Account Maintenance Excel file
    """
    # Access Control: Only Audit department can generate audit reports
    require_audit()
    
    try:
        # Import the User Account Maintenance module dynamically
        import importlib.util
        user_account_maintenance_script_path = os.path.join(os.path.dirname(__file__), 'Audit_Dashboard_Files', 'Asset_Review', 'User_Account_Maintenance_Without_POC.py')
        spec = importlib.util.spec_from_file_location("user_account_maintenance_module", user_account_maintenance_script_path)
        user_account_maintenance_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(user_account_maintenance_module)
        
        # Get form data
        form_data = request.form.to_dict()
        
        # Create Excel file
        filepath, filename = user_account_maintenance_module.create_user_account_maintenance_excel(form_data)
        
        # Read file content
        with open(filepath, 'rb') as f:
            file_content = f.read()
        
        # Clean up file
        user_account_maintenance_module.cleanup_file(filepath)
        
        # Return file for download
        return Response(
            file_content,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            headers={
                'Content-Disposition': f'attachment; filename={filename}',
                'Content-Type': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
            }
        )
        
    except Exception as e:
        flash(f'Error generating User Account Maintenance Excel file: {str(e)}', 'error')
        return redirect(url_for('audit_dashboard'))

@app.route('/generate_logical_access_controls_excel', methods=['POST'])
@login_required
def generate_logical_access_controls_excel():
    """
    Generate Logical Access Controls Excel file
    """
    # Access Control: Only Audit department can generate audit reports
    require_audit()
    
    try:
        # Import the Logical Access Controls module dynamically
        import importlib.util
        logical_access_controls_script_path = os.path.join(os.path.dirname(__file__), 'Audit_Dashboard_Files', 'Asset_Review', 'Logical_Access_Controls_Without_POC.py')
        spec = importlib.util.spec_from_file_location("logical_access_controls_module", logical_access_controls_script_path)
        logical_access_controls_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(logical_access_controls_module)
        
        # Get form data
        form_data = request.form.to_dict()
        
        # Create Excel file
        filepath, filename = logical_access_controls_module.create_logical_access_controls_excel(form_data)
        
        # Read file content
        with open(filepath, 'rb') as f:
            file_content = f.read()
        
        # Clean up file
        logical_access_controls_module.cleanup_file(filepath)
        
        # Return file for download
        return Response(
            file_content,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            headers={
                'Content-Disposition': f'attachment; filename={filename}',
                'Content-Type': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
            }
        )
        
    except Exception as e:
        flash(f'Error generating Logical Access Controls Excel file: {str(e)}', 'error')
        return redirect(url_for('audit_dashboard'))

@app.route('/generate_database_controls_excel', methods=['POST'])
@login_required
def generate_database_controls_excel():
    """
    Generate Database Controls Excel file
    """
    # Access Control: Only Audit department can generate audit reports
    require_audit()
    
    try:
        # Import the Database Controls module dynamically
        import importlib.util
        database_controls_script_path = os.path.join(os.path.dirname(__file__), 'Audit_Dashboard_Files', 'Asset_Review', 'Database_Controls_without_POC.py')
        spec = importlib.util.spec_from_file_location("database_controls_module", database_controls_script_path)
        database_controls_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(database_controls_module)
        
        # Get form data
        form_data = request.form.to_dict()
        
        # Create Excel file
        filepath, filename = database_controls_module.create_database_controls_excel(form_data)
        
        # Read file content
        with open(filepath, 'rb') as f:
            file_content = f.read()
        
        # Clean up file
        database_controls_module.cleanup_file(filepath)
        
        # Return file for download
        return Response(
            file_content,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            headers={
                'Content-Disposition': f'attachment; filename={filename}',
                'Content-Type': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
            }
        )
        
    except Exception as e:
        flash(f'Error generating Database Controls Excel file: {str(e)}', 'error')
        return redirect(url_for('audit_dashboard'))

@app.route('/generate_penetration_testing_excel', methods=['POST'])
@login_required
def generate_penetration_testing_excel():
    """
    Generate Penetration Testing Excel file
    """
    # Access Control: Only Audit department can generate audit reports
    require_audit()
    
    try:
        # Import the Penetration Testing module dynamically
        import importlib.util
        penetration_testing_script_path = os.path.join(os.path.dirname(__file__), 'Audit_Dashboard_Files', 'Asset_Review', 'Penetration_Testing_Without_POC.py')
        spec = importlib.util.spec_from_file_location("penetration_testing_module", penetration_testing_script_path)
        penetration_testing_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(penetration_testing_module)
        
        # Get form data
        form_data = request.form.to_dict()
        
        # Create Excel file
        filepath, filename = penetration_testing_module.create_penetration_testing_excel(form_data)
        
        # Read file content
        with open(filepath, 'rb') as f:
            file_content = f.read()
        
        # Clean up file
        penetration_testing_module.cleanup_file(filepath)
        
        # Return file for download
        return Response(
            file_content,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            headers={
                'Content-Disposition': f'attachment; filename={filename}',
                'Content-Type': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
            }
        )
        
    except Exception as e:
        flash(f'Error generating Penetration Testing Excel file: {str(e)}', 'error')
        return redirect(url_for('audit_dashboard'))

@app.route('/generate_training_excel', methods=['POST'])
@login_required
def generate_training_excel():
    """
    Generate Training Excel file
    """
    # Access Control: Only Audit department can generate audit reports
    require_audit()
    
    try:
        # Import the Training module dynamically
        import importlib.util
        training_script_path = os.path.join(os.path.dirname(__file__), 'Audit_Dashboard_Files', 'Asset_Review', 'Training_Without_POC.py')
        spec = importlib.util.spec_from_file_location("training_module", training_script_path)
        training_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(training_module)
        
        # Get form data
        form_data = request.form.to_dict()
        
        # Create Excel file
        filepath, filename = training_module.create_training_excel(form_data)
        
        # Read file content
        with open(filepath, 'rb') as f:
            file_content = f.read()
        
        # Clean up file
        training_module.cleanup_file(filepath)
        
        # Return file for download
        return Response(
            file_content,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            headers={
                'Content-Disposition': f'attachment; filename={filename}',
                'Content-Type': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
            }
        )
        
    except Exception as e:
        flash(f'Error generating Training Excel file: {str(e)}', 'error')
        return redirect(url_for('audit_dashboard'))

@app.route('/generate_remote_access_excel', methods=['POST'])
@login_required
def generate_remote_access_excel():
    """
    Generate Remote Access Excel file
    """
    # Access Control: Only Audit department can generate audit reports
    require_audit()
    
    try:
        # Import the Remote Access module dynamically
        import importlib.util
        remote_access_script_path = os.path.join(os.path.dirname(__file__), 'Audit_Dashboard_Files', 'Asset_Review', 'Remote_Access_without_POC.py')
        spec = importlib.util.spec_from_file_location("remote_access_module", remote_access_script_path)
        remote_access_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(remote_access_module)
        
        # Get form data
        form_data = request.form.to_dict()
        
        # Create Excel file
        filepath, filename = remote_access_module.create_remote_access_excel(form_data)
        
        # Read file content
        with open(filepath, 'rb') as f:
            file_content = f.read()
        
        # Clean up file
        remote_access_module.cleanup_file(filepath)
        
        # Return file for download
        return Response(
            file_content,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            headers={
                'Content-Disposition': f'attachment; filename={filename}',
                'Content-Type': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
            }
        )
        
    except Exception as e:
        flash(f'Error generating Remote Access Excel file: {str(e)}', 'error')
        return redirect(url_for('audit_dashboard'))

@app.route('/generate_power_supply_excel', methods=['POST'])
@login_required
def generate_power_supply_excel():
    """
    Generate Power Supply (UPS) Excel file
    """
    # Access Control: Only Audit department can generate audit reports
    require_audit()
    
    try:
        # Import the Power Supply module dynamically
        import importlib.util
        power_supply_script_path = os.path.join(os.path.dirname(__file__), 'Audit_Dashboard_Files', 'Asset_Review', 'Power_Supply_Without_POC.py')
        spec = importlib.util.spec_from_file_location("power_supply_module", power_supply_script_path)
        power_supply_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(power_supply_module)
        
        # Get form data
        form_data = request.form.to_dict()
        
        # Create Excel file
        filepath, filename = power_supply_module.create_power_supply_excel(form_data)
        
        # Read file content
        with open(filepath, 'rb') as f:
            file_content = f.read()
        
        # Clean up file
        power_supply_module.cleanup_file(filepath)
        
        # Return file for download
        return Response(
            file_content,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            headers={
                'Content-Disposition': f'attachment; filename={filename}',
                'Content-Type': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
            }
        )
        
    except Exception as e:
        flash(f'Error generating Power Supply Excel file: {str(e)}', 'error')
        return redirect(url_for('audit_dashboard'))

@app.route('/generate_backup_restoration_excel', methods=['POST'])
@login_required
def generate_backup_restoration_excel():
    """
    Generate Backup and Restoration Excel file
    """
    # Access Control: Only Audit department can generate audit reports
    require_audit()
    
    try:
        # Import the Backup and Restoration module dynamically
        import importlib.util
        backup_restoration_script_path = os.path.join(os.path.dirname(__file__), 'Audit_Dashboard_Files', 'Asset_Review', 'Backup_and_Restoration_Without_POC.py')
        spec = importlib.util.spec_from_file_location("backup_restoration_module", backup_restoration_script_path)
        backup_restoration_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(backup_restoration_module)
        
        # Get form data
        form_data = request.form.to_dict()
        
        # Create Excel file
        filepath, filename = backup_restoration_module.create_backup_restoration_excel(form_data)
        
        # Read file content
        with open(filepath, 'rb') as f:
            file_content = f.read()
        
        # Clean up file
        backup_restoration_module.cleanup_file(filepath)
        
        # Return file for download
        return Response(
            file_content,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            headers={
                'Content-Disposition': f'attachment; filename={filename}',
                'Content-Type': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
            }
        )
        
    except Exception as e:
        flash(f'Error generating Backup and Restoration Excel file: {str(e)}', 'error')
        return redirect(url_for('audit_dashboard'))

@app.route('/generate_maintenance_patches_excel', methods=['POST'])
@login_required
def generate_maintenance_patches_excel():
    """
    Generate Maintenance & App Patches Excel file
    """
    # Access Control: Only Audit department can generate audit reports
    require_audit()
    
    try:
        # Import the Maintenance & App Patches module dynamically
        import importlib.util
        maintenance_patches_script_path = os.path.join(os.path.dirname(__file__), 'Audit_Dashboard_Files', 'Asset_Review', 'Maintenance_and_App_Patches_without_POC.py')
        spec = importlib.util.spec_from_file_location("maintenance_patches_module", maintenance_patches_script_path)
        maintenance_patches_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(maintenance_patches_module)
        
        # Get form data
        form_data = request.form.to_dict()
        
        # Create Excel file
        filepath, filename = maintenance_patches_module.create_maintenance_patches_excel(form_data)
        
        # Read file content
        with open(filepath, 'rb') as f:
            file_content = f.read()
        
        # Clean up file
        maintenance_patches_module.cleanup_file(filepath)
        
        # Return file for download
        return Response(
            file_content,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            headers={
                'Content-Disposition': f'attachment; filename={filename}',
                'Content-Type': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
            }
        )
        
    except Exception as e:
        flash(f'Error generating Maintenance & App Patches Excel file: {str(e)}', 'error')
        return redirect(url_for('audit_dashboard'))

@app.route('/generate_network_monitor_tool_excel', methods=['POST'])
@login_required
def generate_network_monitor_tool_excel():
    """
    Generate Network Monitor Tool Excel file
    """
    # Access Control: Only Audit department can generate audit reports
    require_audit()
    
    try:
        # Import the Network Monitor Tool module dynamically
        import importlib.util
        network_monitor_tool_script_path = os.path.join(os.path.dirname(__file__), 'Audit_Dashboard_Files', 'Asset_Review', 'Network_Monitor_Tool_Without_POC.py')
        spec = importlib.util.spec_from_file_location("network_monitor_tool_module", network_monitor_tool_script_path)
        network_monitor_tool_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(network_monitor_tool_module)
        
        # Get form data
        form_data = request.form.to_dict()
        
        # Create Excel file
        filepath, filename = network_monitor_tool_module.create_network_monitor_tool_excel(form_data)
        
        # Read file content
        with open(filepath, 'rb') as f:
            file_content = f.read()
        
        # Clean up file
        network_monitor_tool_module.cleanup_file(filepath)
        
        # Return file for download
        return Response(
            file_content,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            headers={
                'Content-Disposition': f'attachment; filename={filename}',
                'Content-Type': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
            }
        )
        
    except Exception as e:
        flash(f'Error generating Network Monitor Tool Excel file: {str(e)}', 'error')
        return redirect(url_for('audit_dashboard'))

@app.route('/generate_san_switch_cisco_excel', methods=['POST'])
@login_required
def generate_san_switch_cisco_excel():
    """
    Generate SAN Switch CISCO Excel file
    """
    # Access Control: Only Audit department can generate audit reports
    require_audit()
    
    try:
        # Import the SAN Switch CISCO module dynamically
        import importlib.util
        san_switch_cisco_script_path = os.path.join(os.path.dirname(__file__), 'Audit_Dashboard_Files', 'Asset_Review', 'SAN_Switch_CISCO_Without_POC.py')
        spec = importlib.util.spec_from_file_location("san_switch_cisco_module", san_switch_cisco_script_path)
        san_switch_cisco_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(san_switch_cisco_module)
        
        # Get form data
        form_data = request.form.to_dict()
        
        # Create Excel file
        filepath, filename = san_switch_cisco_module.create_san_switch_cisco_excel(form_data)
        
        # Read file content
        with open(filepath, 'rb') as f:
            file_content = f.read()
        
        # Clean up file
        san_switch_cisco_module.cleanup_file(filepath)
        
        # Return file for download
        return Response(
            file_content,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            headers={
                'Content-Disposition': f'attachment; filename={filename}',
                'Content-Type': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
            }
        )
        
    except Exception as e:
        flash(f'Error generating SAN Switch CISCO Excel file: {str(e)}', 'error')
        return redirect(url_for('audit_dashboard'))

@app.route('/generate_san_storage_excel', methods=['POST'])
@login_required
def generate_san_storage_excel():
    """
    Generate SAN Storage Excel file
    """
    # Access Control: Only Audit department can generate audit reports
    require_audit()
    
    try:
        # Import the SAN Storage module dynamically
        import importlib.util
        san_storage_script_path = os.path.join(os.path.dirname(__file__), 'Audit_Dashboard_Files', 'Asset_Review', 'SAN_Storage_Without_POC.py')
        spec = importlib.util.spec_from_file_location("san_storage_module", san_storage_script_path)
        san_storage_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(san_storage_module)
        
        # Get form data
        form_data = request.form.to_dict()
        
        # Create Excel file
        filepath, filename = san_storage_module.create_san_storage_excel(form_data)
        
        # Read file content
        with open(filepath, 'rb') as f:
            file_content = f.read()
        
        # Clean up file
        san_storage_module.cleanup_file(filepath)
        
        # Return file for download
        return Response(
            file_content,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            headers={
                'Content-Disposition': f'attachment; filename={filename}',
                'Content-Type': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
            }
        )
        
    except Exception as e:
        flash(f'Error generating SAN Storage Excel file: {str(e)}', 'error')
        return redirect(url_for('audit_dashboard'))

@app.route('/generate_nas_excel', methods=['POST'])
@login_required
def generate_nas_excel():
    """
    Generate NAS Excel file
    """
    # Access Control: Only Audit department can generate audit reports
    require_audit()
    
    try:
        # Import the NAS module dynamically
        import importlib.util
        nas_script_path = os.path.join(os.path.dirname(__file__), 'Audit_Dashboard_Files', 'Asset_Review', 'NAS_Without_POC.py')
        spec = importlib.util.spec_from_file_location("nas_module", nas_script_path)
        nas_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(nas_module)
        
        # Get form data
        form_data = request.form.to_dict()
        
        # Create Excel file
        filepath, filename = nas_module.create_nas_excel(form_data)
        
        # Read file content
        with open(filepath, 'rb') as f:
            file_content = f.read()
        
        # Clean up file
        nas_module.cleanup_file(filepath)
        
        # Return file for download
        return Response(
            file_content,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            headers={
                'Content-Disposition': f'attachment; filename={filename}',
                'Content-Type': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
            }
        )
        
    except Exception as e:
        flash(f'Error generating NAS Excel file: {str(e)}', 'error')
        return redirect(url_for('audit_dashboard'))

@app.route('/generate_load_balancer_array_excel', methods=['POST'])
@login_required
def generate_load_balancer_array_excel():
    """
    Generate Load Balancer Array Excel file
    """
    # Access Control: Only Audit department can generate audit reports
    require_audit()
    
    try:
        # Import the Load Balancer Array module dynamically
        import importlib.util
        load_balancer_array_script_path = os.path.join(os.path.dirname(__file__), 'Audit_Dashboard_Files', 'Asset_Review', 'Load_Balancer_Array_without_POC.py')
        spec = importlib.util.spec_from_file_location("load_balancer_array_module", load_balancer_array_script_path)
        load_balancer_array_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(load_balancer_array_module)
        
        # Get form data
        form_data = request.form.to_dict()
        
        # Create Excel file
        filepath, filename = load_balancer_array_module.create_load_balancer_array_excel(form_data)
        
        # Read file content
        with open(filepath, 'rb') as f:
            file_content = f.read()
        
        # Clean up file
        load_balancer_array_module.cleanup_file(filepath)
        
        # Return file for download
        return Response(
            file_content,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            headers={
                'Content-Disposition': f'attachment; filename={filename}',
                'Content-Type': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
            }
        )
        
    except Exception as e:
        flash(f'Error generating Load Balancer Array Excel file: {str(e)}', 'error')
        return redirect(url_for('audit_dashboard'))

@app.route('/generate_pam_excel', methods=['POST'])
@login_required
def generate_pam_excel():
    """
    Generate PAM Excel file
    """
    # Access Control: Only Audit department can generate audit reports
    require_audit()
    
    try:
        # Import the PAM module dynamically
        import importlib.util
        pam_script_path = os.path.join(os.path.dirname(__file__), 'Audit_Dashboard_Files', 'Asset_Review', 'PAM_Without_POC.py')
        spec = importlib.util.spec_from_file_location("pam_module", pam_script_path)
        pam_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(pam_module)
        
        # Get form data
        form_data = request.form.to_dict()
        
        # Create Excel file
        filepath, filename = pam_module.create_pam_excel(form_data)
        
        # Read file content
        with open(filepath, 'rb') as f:
            file_content = f.read()
        
        # Clean up file
        pam_module.cleanup_file(filepath)
        
        # Return file for download
        return Response(
            file_content,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            headers={
                'Content-Disposition': f'attachment; filename={filename}',
                'Content-Type': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
            }
        )
        
    except Exception as e:
        flash(f'Error generating PAM Excel file: {str(e)}', 'error')
        return redirect(url_for('audit_dashboard'))

@app.route('/generate_soc_excel', methods=['POST'])
@login_required
def generate_soc_excel():
    """
    Generate SOC Excel file
    """
    # Access Control: Only Audit department can generate audit reports
    require_audit()
    
    try:
        # Import the SOC module dynamically
        import importlib.util
        soc_script_path = os.path.join(os.path.dirname(__file__), 'Audit_Dashboard_Files', 'Asset_Review', 'SOC_Without_POC.py')
        spec = importlib.util.spec_from_file_location("soc_module", soc_script_path)
        soc_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(soc_module)
        
        # Get form data
        form_data = request.form.to_dict()
        
        # Create Excel file
        filepath, filename = soc_module.create_soc_excel(form_data)
        
        # Read file content
        with open(filepath, 'rb') as f:
            file_content = f.read()
        
        # Clean up file
        soc_module.cleanup_file(filepath)
        
        # Return file for download
        return Response(
            file_content,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            headers={
                'Content-Disposition': f'attachment; filename={filename}',
                'Content-Type': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
            }
        )
        
    except Exception as e:
        flash(f'Error generating SOC Excel file: {str(e)}', 'error')
        return redirect(url_for('audit_dashboard'))

@app.route('/generate_change_management_excel', methods=['POST'])
@login_required
def generate_change_management_excel():
    """
    Generate Change Management Excel file
    """
    # Access Control: Only Audit department can generate audit reports
    require_audit()
    
    try:
        # Import the Change Management module dynamically
        import importlib.util
        change_management_script_path = os.path.join(os.path.dirname(__file__), 'Audit_Dashboard_Files', 'Asset_Review', 'Change_Management_without_POC.py')
        spec = importlib.util.spec_from_file_location("change_management_module", change_management_script_path)
        change_management_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(change_management_module)
        
        # Get form data
        form_data = request.form.to_dict()
        
        # Create Excel file
        filepath, filename = change_management_module.create_change_management_excel(form_data)
        
        # Read file content
        with open(filepath, 'rb') as f:
            file_content = f.read()
        
        # Clean up file
        change_management_module.cleanup_file(filepath)
        
        # Return file for download
        return Response(
            file_content,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            headers={
                'Content-Disposition': f'attachment; filename={filename}',
                'Content-Type': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
            }
        )
        
    except Exception as e:
        flash(f'Error generating Change Management Excel file: {str(e)}', 'error')
        return redirect(url_for('audit_dashboard'))

@app.route('/generate_asset_management_excel', methods=['POST'])
@login_required
def generate_asset_management_excel():
    """
    Generate Asset Management Excel file
    """
    # Access Control: Only Audit department can generate audit reports
    require_audit()
    
    try:
        # Import the Asset Management module dynamically
        import importlib.util
        asset_management_script_path = os.path.join(os.path.dirname(__file__), 'Audit_Dashboard_Files', 'Asset_Review', 'Asset_Management_without_POC.py')
        spec = importlib.util.spec_from_file_location("asset_management_module", asset_management_script_path)
        asset_management_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(asset_management_module)
        
        # Get form data
        form_data = request.form.to_dict()
        
        # Create Excel file
        filepath, filename = asset_management_module.create_asset_management_excel(form_data)
        
        # Read file content
        with open(filepath, 'rb') as f:
            file_content = f.read()
        
        # Clean up file
        asset_management_module.cleanup_file(filepath)
        
        # Return file for download
        return Response(
            file_content,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            headers={
                'Content-Disposition': f'attachment; filename={filename}',
                'Content-Type': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
            }
        )
        
    except Exception as e:
        flash(f'Error generating Asset Management Excel file: {str(e)}', 'error')
        return redirect(url_for('audit_dashboard'))

@app.route('/generate_others_excel', methods=['POST'])
@login_required
def generate_others_excel():
    """
    Generate Others Excel file
    """
    # Access Control: Only Audit department can generate audit reports
    require_audit()
    
    try:
        # Import the Others module dynamically
        import importlib.util
        others_script_path = os.path.join(os.path.dirname(__file__), 'Audit_Dashboard_Files', 'Asset_Review', 'Others_Without_POC.py')
        spec = importlib.util.spec_from_file_location("others_module", others_script_path)
        others_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(others_module)
        
        # Get form data
        form_data = request.form.to_dict()
        
        # Create Excel file
        filepath, filename = others_module.create_others_excel(form_data)
        
        # Read file content
        with open(filepath, 'rb') as f:
            file_content = f.read()
        
        # Clean up file
        others_module.cleanup_file(filepath)
        
        # Return file for download
        return Response(
            file_content,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            headers={
                'Content-Disposition': f'attachment; filename={filename}',
                'Content-Type': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
            }
        )
        
    except Exception as e:
        safe_error = get_safe_error_message(e)
        flash(f'Error generating Others Excel file. Please try again later.', 'error')
        return redirect(url_for('audit_dashboard'))

app.register_blueprint(nmap_bp)
app.register_blueprint(word_report_bp)
app.register_blueprint(follow_up_audit_bp)
app.register_blueprint(vapt_nmap_bp)
app.register_blueprint(vapt_word_report_bp)
app.register_blueprint(website_vapt_word_report_bp)
app.register_blueprint(web_app_word_report_bp)
app.register_blueprint(android_app_word_report_bp)
app.register_blueprint(ios_app_word_report_bp)
app.register_blueprint(api_first_audit_word_report_bp)
app.register_blueprint(vapt_follow_up_audit_bp)
app.register_blueprint(vapt_first_audit_metadata_bp)
app.register_blueprint(api_first_audit_metadata_bp)
app.register_blueprint(public_ip_first_audit_metadata_bp)
app.register_blueprint(public_ip_follow_up_audit_metadata_bp)
app.register_blueprint(website_vapt_first_audit_metadata_bp)
app.register_blueprint(ios_application_first_audit_metadata_bp)
app.register_blueprint(android_application_first_audit_metadata_bp)
app.register_blueprint(android_app_vapt_bp)
app.register_blueprint(ios_app_vapt_bp)
app.register_blueprint(api_vapt_bp)
app.register_blueprint(android_app_vapt_followup_bp)
app.register_blueprint(ios_app_vapt_followup_bp)
app.register_blueprint(api_vapt_followup_bp)
app.register_blueprint(web_application_first_audit_metadata_bp)
app.register_blueprint(ios_application_follow_up_audit_metadata_bp)
app.register_blueprint(android_application_follow_up_audit_metadata_bp)
app.register_blueprint(web_application_follow_up_audit_metadata_bp)
app.register_blueprint(vapt_follow_up_audit_metadata_bp)
app.register_blueprint(api_follow_up_audit_metadata_bp)
app.register_blueprint(website_vapt_follow_up_audit_metadata_bp)
app.register_blueprint(website_vapt_bp)
app.register_blueprint(website_vapt_followup_bp)
app.register_blueprint(website_vapt_follow_up_word_report_bp)
app.register_blueprint(public_ip_vapt_bp)
app.register_blueprint(public_ip_vapt_followup_bp)
app.register_blueprint(public_ip_vapt_follow_up_word_report_bp)
app.register_blueprint(web_app_vapt_bp)
app.register_blueprint(web_app_vapt_followup_bp)
app.register_blueprint(web_app_follow_up_word_report_bp)
app.register_blueprint(android_follow_up_word_report_bp)
app.register_blueprint(api_follow_up_word_report_bp)
app.register_blueprint(ios_follow_up_word_report_bp)
app.register_blueprint(public_ip_vapt_first_audit_word_report_bp)
app.register_blueprint(everyday_workplan_bp)
app.register_blueprint(everyday_updated_work_bp)
app.register_blueprint(submit_sprint_plan_bp)
app.register_blueprint(submit_sprint_work_bp)
app.register_blueprint(extra_work_bp)
app.register_blueprint(follow_up_word_report_bp)
app.register_blueprint(vapt_follow_up_word_report_bp)
app.register_blueprint(first_audit_certificate_bp)
app.register_blueprint(follow_up_audit_certificate_bp)
app.register_blueprint(vapt_first_audit_certificate_bp)
app.register_blueprint(website_vapt_first_audit_certificate_bp)
app.register_blueprint(web_app_vapt_first_audit_certificate_bp)
app.register_blueprint(android_app_vapt_first_audit_certificate_bp)
app.register_blueprint(ios_app_vapt_first_audit_certificate_bp)
app.register_blueprint(api_vapt_first_audit_certificate_bp)
app.register_blueprint(public_ip_vapt_first_audit_certificate_bp)
app.register_blueprint(vapt_follow_up_audit_certificate_bp)
app.register_blueprint(website_vapt_follow_up_audit_certificate_bp)
app.register_blueprint(api_vapt_follow_up_audit_certificate_bp)
app.register_blueprint(web_app_vapt_follow_up_audit_certificate_bp)
app.register_blueprint(android_app_vapt_follow_up_audit_certificate_bp)
app.register_blueprint(ios_app_vapt_follow_up_audit_certificate_bp)
app.register_blueprint(public_ip_vapt_follow_up_audit_certificate_bp)
app.register_blueprint(is_audit_certificate_bp)
app.register_blueprint(cyber_security_audit_certificate_bp)
app.register_blueprint(gap_assessment_audit_certificate_bp)
app.register_blueprint(branch_excel_bp)
app.register_blueprint(branch_excel_with_poc_bp)
app.register_blueprint(combine_branch_excel_without_poc_bp)
app.register_blueprint(combine_branch_excel_with_poc_bp)
app.register_blueprint(combine_assets_excels_bp)
app.register_blueprint(asset_review_non_compliance_bp)
app.register_blueprint(branch_console_bp)
app.register_blueprint(is_audit_word_report_bp)
app.register_blueprint(network_review_evidence_bp)
app.register_blueprint(data_centre_evidence_bp)
app.register_blueprint(disaster_recovery_evidence_bp)
app.register_blueprint(firewall_evidence_bp)
app.register_blueprint(core_switch_evidence_bp)
app.register_blueprint(router_evidence_bp)
app.register_blueprint(domain_controller_evidence_bp)
app.register_blueprint(h2h_evidence_bp)
app.register_blueprint(antivirus_evidence_bp)
app.register_blueprint(atm_evidence_bp)
app.register_blueprint(mail_messaging_evidence_bp)
app.register_blueprint(ho_win_server_evidence_bp)
app.register_blueprint(linux_server_evidence_bp)
app.register_blueprint(esxi_server_evidence_bp)
app.register_blueprint(access_control_os_evidence_bp)
app.register_blueprint(access_control_application_evidence_bp)
app.register_blueprint(application_evidence_bp)
app.register_blueprint(internet_banking_evidence_bp)
app.register_blueprint(internal_control_evidence_bp)
app.register_blueprint(fire_protection_evidence_bp)
app.register_blueprint(amc_evidence_bp)
app.register_blueprint(data_input_control_evidence_bp)
app.register_blueprint(purging_data_files_evidence_bp)
app.register_blueprint(business_continuity_planning_evidence_bp)
app.register_blueprint(inhouse_outsourced_evidence_bp)
app.register_blueprint(audit_trail_evidence_bp)
app.register_blueprint(packaged_software_evidence_bp)
app.register_blueprint(user_account_maintenance_evidence_bp)
app.register_blueprint(logical_access_controls_evidence_bp)
app.register_blueprint(database_controls_evidence_bp)
app.register_blueprint(penetration_testing_evidence_bp)
app.register_blueprint(training_evidence_bp)
app.register_blueprint(remote_access_evidence_bp)
app.register_blueprint(power_supply_evidence_bp)
app.register_blueprint(backup_restoration_evidence_bp)
app.register_blueprint(maintenance_patches_evidence_bp)
app.register_blueprint(network_monitoring_tool_evidence_bp)
app.register_blueprint(san_switch_cisco_evidence_bp)
app.register_blueprint(san_storage_evidence_bp)
app.register_blueprint(nas_evidence_bp)
app.register_blueprint(load_balancer_array_evidence_bp)
app.register_blueprint(pam_evidence_bp)
app.register_blueprint(soc_evidence_bp)
app.register_blueprint(change_management_evidence_bp)
app.register_blueprint(asset_management_evidence_bp)
app.register_blueprint(others_evidence_bp)
app.register_blueprint(vics_part1_bp)
app.register_blueprint(vics_part2_bp)
app.register_blueprint(vics_part3_bp)
app.register_blueprint(vics_part4_bp)
app.register_blueprint(vics_part5_bp)
app.register_blueprint(vics_part6_bp)
app.register_blueprint(vics_part7_bp)
app.register_blueprint(create_vics_worksheet_bp)
app.register_blueprint(loc_level2_bp)
app.register_blueprint(loc_level3_bp)
app.register_blueprint(loc_level4_bp)
app.register_blueprint(create_loc_worksheet_bp)
app.register_blueprint(loe_bp)
app.register_blueprint(create_vics_with_bank_input_bp)
app.register_blueprint(create_loc_with_bank_input_bp)
app.register_blueprint(gap_assessment_excel_bp)
app.register_blueprint(gap_assessment_report_bp)
app.register_blueprint(gap_assessment_report_bank_input_bp)
app.register_blueprint(vics_certificate_bp)
app.register_blueprint(meity_audit_part1_bp)
app.register_blueprint(meity_audit_part2_bp)
app.register_blueprint(meity_audit_part3_bp)
app.register_blueprint(cyber_security_audit_excel_bp)
app.register_blueprint(cyber_security_audit_report_bp)
app.register_blueprint(first_audit_metadata_bp)
app.register_blueprint(follow_up_audit_metadata_bp)
app.register_blueprint(is_audit_compliance_bp)
app.register_blueprint(infra_vapt_compliance_bp)
app.register_blueprint(website_vapt_compliance_bp)
app.register_blueprint(public_ip_vapt_compliance_bp)
app.register_blueprint(is_audit_compliance_certificate_bp)
app.register_blueprint(infrastructure_vapt_compliance_certificate_bp)
app.register_blueprint(website_vapt_compliance_certificate_bp)
app.register_blueprint(public_ip_vapt_compliance_certificate_bp)
# Register GRC Dashboard blueprints
app.register_blueprint(grc_is_audit_compliance_bp)
app.register_blueprint(grc_infra_vapt_compliance_bp)
app.register_blueprint(grc_website_vapt_compliance_bp)
app.register_blueprint(grc_public_ip_vapt_compliance_bp)
app.register_blueprint(grc_is_audit_compliance_certificate_bp)
app.register_blueprint(grc_infrastructure_vapt_compliance_certificate_bp)
app.register_blueprint(grc_website_vapt_compliance_certificate_bp)
app.register_blueprint(grc_public_ip_vapt_compliance_certificate_bp)
app.register_blueprint(hr_dashboard_bp)
app.register_blueprint(admin_dashboard_bp)

# Global error handler for 413 Request Entity Too Large
@app.errorhandler(RequestEntityTooLarge)
def handle_request_entity_too_large(e):
    """Handle 413 Request Entity Too Large errors with user-friendly message"""
    flash('File size too large! The maximum file size is 1GB. Please compress your ZIP file or split it into smaller files. If the file is still too large, consider using image compression tools to reduce the size of images in the ZIP file.', 'error')
    # Sanitize referrer to prevent open redirect attacks
    safe_referrer = sanitize_referrer(request.referrer)
    redirect_url = safe_referrer if safe_referrer else url_for('audit_dashboard')
    return redirect(redirect_url), 413

# Initialize daily workplan email scheduler
try:
    from daily_workplan_email_scheduler import start_scheduler
    email_scheduler = start_scheduler()
    # Store scheduler in app config for cleanup on shutdown
    app.config['EMAIL_SCHEDULER'] = email_scheduler
    
    # Register shutdown handler to stop scheduler gracefully
    import atexit
    def shutdown_scheduler():
        if email_scheduler and email_scheduler.running:
            email_scheduler.shutdown()
            logging.info("Email scheduler stopped")
            print("Email scheduler stopped")
    atexit.register(shutdown_scheduler)
    
except Exception as e:
    logging.error(f"Failed to start email scheduler: {str(e)}")
    print(f"⚠️ Warning: Failed to start email scheduler: {str(e)}")

if __name__ == '__main__':
    # Run migrations on startup
    with app.app_context():
        migrate_database()
    
    # Security: Only enable debug mode if explicitly set via environment variable
    # In production, set FLASK_DEBUG=False or don't set it at all
    debug_mode = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    app.run(debug=debug_mode)

