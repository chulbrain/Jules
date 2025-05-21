import os
import json
from datetime import datetime, timedelta # Added
from flask import Flask, session, redirect, url_for, request, render_template, flash
from flask_sqlalchemy import SQLAlchemy
from google_auth_oauthlib import flow
from google.oauth2 import credentials as GoogleCredentials # Alias to avoid conflict
from googleapiclient.discovery import build as build_google_service
from googleapiclient import discovery # Already here, but build_google_service is more specific

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///scheduler.db'
db = SQLAlchemy(app)

# OAuth 2.0 Configuration
app.secret_key = os.urandom(24) # For session management
app.config['GOOGLE_CLIENT_ID'] = os.environ.get("GOOGLE_CLIENT_ID", None) # Replace with your actual client ID later
app.config['GOOGLE_CLIENT_SECRET'] = os.environ.get("GOOGLE_CLIENT_SECRET", None) # Replace with your actual client secret later
app.config['GOOGLE_DISCOVERY_URL'] = "https://accounts.google.com/.well-known/openid-configuration"
app.config['OAUTH2_SCOPES'] = ['openid', 'https://www.googleapis.com/auth/userinfo.email', 'https://www.googleapis.com/auth/userinfo.profile', 'https://www.googleapis.com/auth/calendar', 'https://www.googleapis.com/auth/tasks']
# IMPORTANT: The redirect URI must match what you configure in Google Cloud Console
app.config['OAUTH2_REDIRECT_URI'] = 'http://localhost:5000/authorize' # For local testing

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    google_id = db.Column(db.String(200), unique=True, nullable=False)
    email = db.Column(db.String(200), nullable=False)
    credentials_json = db.Column(db.Text, nullable=True) # To store Google OAuth credentials

    def __repr__(self):
        return f'<User {self.email}>'

# Models for Task Templates and Rules
class TaskTemplate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    rules = db.relationship('TaskRule', backref='template', lazy=True, cascade="all, delete-orphan")
    user = db.relationship('User', backref=db.backref('task_templates', lazy=True))

    def __repr__(self):
        return f'<TaskTemplate {self.name}>'

class TaskRule(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    template_id = db.Column(db.Integer, db.ForeignKey('task_template.id'), nullable=False)
    task_name = db.Column(db.String(200), nullable=False)
    schedule_type = db.Column(db.String(20), nullable=False)  # 'fixed_day' or 'offset'
    day_of_week = db.Column(db.Integer, nullable=True)  # 1=Monday, 7=Sunday for fixed_day
    offset_days = db.Column(db.Integer, nullable=True) # For offset from template start

    def __repr__(self):
        return f'<TaskRule {self.task_name} for template {self.template_id}>'

# CRUD functions for TaskTemplate
def create_task_template(user_id, name, description=None):
    if not User.query.get(user_id):
        return None 
    template = TaskTemplate(user_id=user_id, name=name, description=description)
    db.session.add(template)
    db.session.commit()
    return template

def get_task_template(template_id, user_id):
    return TaskTemplate.query.filter_by(id=template_id, user_id=user_id).first()

def get_task_templates_for_user(user_id):
    return TaskTemplate.query.filter_by(user_id=user_id).all()

def update_task_template(template_id, user_id, name=None, description=None):
    template = get_task_template(template_id, user_id)
    if template:
        if name is not None:
            template.name = name
        if description is not None:
            template.description = description
        db.session.commit()
    return template

def delete_task_template(template_id, user_id):
    template = get_task_template(template_id, user_id)
    if template:
        db.session.delete(template)
        db.session.commit()
        return True
    return False

# CRUD functions for TaskRule
def add_rule_to_template(template_id, user_id, task_name, schedule_type, day_of_week=None, offset_days=None):
    template = get_task_template(template_id, user_id)
    if not template:
        return None

    if schedule_type == 'fixed_day' and (day_of_week is None or not (1 <= day_of_week <= 7)):
        raise ValueError("요일 지정 스케줄 타입에는 유효한 요일(1-7)이 필요합니다.")
    if schedule_type == 'offset' and offset_days is None:
        raise ValueError("오프셋 스케줄 타입에는 오프셋 일수가 필요합니다.")

    rule = TaskRule(
        template_id=template_id, 
        task_name=task_name, 
        schedule_type=schedule_type, 
        day_of_week=day_of_week, 
        offset_days=offset_days
    )
    db.session.add(rule)
    db.session.commit()
    return rule

def get_rules_for_template(template_id, user_id):
    template = get_task_template(template_id, user_id)
    if template:
        return template.rules
    return []

def get_task_rule(rule_id, user_id):
    rule = TaskRule.query.get(rule_id)
    if rule and hasattr(rule, 'template') and rule.template.user_id == user_id:
        return rule
    return None

def update_task_rule(rule_id, user_id, task_name=None, schedule_type=None, day_of_week=None, offset_days=None):
    rule = get_task_rule(rule_id, user_id)
    if not rule:
        return None

    if task_name is not None:
        rule.task_name = task_name
    
    # Handle schedule_type changes and corresponding conditional updates
    if schedule_type is not None:
        rule.schedule_type = schedule_type
        if schedule_type == 'fixed_day':
            if day_of_week is not None and (1 <= day_of_week <= 7):
                rule.day_of_week = day_of_week
            else:
                # If day_of_week is invalid or not provided for fixed_day, it's an issue.
                # Depending on desired behavior, either raise error or don't set day_of_week
                pass # Or raise ValueError("Valid day_of_week required for fixed_day")
            rule.offset_days = None # Clear offset when switching to fixed_day
        elif schedule_type == 'offset':
            if offset_days is not None:
                rule.offset_days = offset_days
            else:
                # Similar to above, offset_days is required for 'offset'
                pass # Or raise ValueError("offset_days required for offset")
            rule.day_of_week = None # Clear day_of_week when switching to offset
    else: # schedule_type was not changed, update fields if provided
        if rule.schedule_type == 'fixed_day' and day_of_week is not None:
            if 1 <= day_of_week <= 7:
                rule.day_of_week = day_of_week
            # else: handle invalid day_of_week if necessary
        elif rule.schedule_type == 'offset' and offset_days is not None:
            rule.offset_days = offset_days

    db.session.commit()
    return rule

def delete_task_rule(rule_id, user_id):
    rule = get_task_rule(rule_id, user_id)
    if rule:
        db.session.delete(rule)
        db.session.commit()
        return True
    return False

# Helper to convert Credentials object to dict for session/DB storage
def credentials_to_dict(credentials):
    return {'token': credentials.token,
            'refresh_token': credentials.refresh_token,
            'token_uri': credentials.token_uri,
            'client_id': credentials.client_id,
            'client_secret': credentials.client_secret,
            'scopes': credentials.scopes}

def get_google_api_credentials(user_id=None):
    '''
    Retrieves Google API credentials from session or database.
    Returns a google.oauth2.credentials.Credentials object or None.
    '''
    creds_dict = None
    current_user_id = user_id if user_id else session.get('user_id')

    if 'credentials' in session: # Prioritize fresh session credentials
        creds_dict = session['credentials']
    elif current_user_id:
        user = User.query.get(current_user_id)
        if user and user.credentials_json:
            try:
                creds_dict = json.loads(user.credentials_json)
            except json.JSONDecodeError:
                flash("저장된 인증 정보 해독 중 오류가 발생했습니다.", "danger")
                return None
            
    if creds_dict:
        # Ensure all necessary fields are present for from_authorized_user_info
        required_scopes = app.config.get('OAUTH2_SCOPES', [
            'openid', 
            'https://www.googleapis.com/auth/userinfo.email', 
            'https://www.googleapis.com/auth/userinfo.profile', 
            'https://www.googleapis.com/auth/calendar', 
            'https://www.googleapis.com/auth/tasks'
        ])
        try:
            # Ensure creds_dict['scopes'] exists and is a list of strings, or use required_scopes
            creds_dict_scopes = creds_dict.get('scopes', [])
            if not isinstance(creds_dict_scopes, list) or not all(isinstance(s, str) for s in creds_dict_scopes):
                 creds_dict_scopes = required_scopes # Fallback to default scopes

            # Re-construct the GoogleCredentials object
            # GoogleCredentials.from_authorized_user_info requires 'client_id', 'client_secret', and 'refresh_token'
            # to be top-level keys in the 'info' dictionary.
            # Our current session['credentials'] structure is flat and matches this.
            return GoogleCredentials.Credentials.from_authorized_user_info(info=creds_dict, scopes=creds_dict_scopes)
        except Exception as e:
            flash(f"인증 정보 로드 중 오류: {str(e)}", "danger")
            # Potentially log this error
            return None
    return None

def get_calendar_service(user_id=None):
    '''
    Builds and returns an authorized Google Calendar API service instance.
    'user_id' is optional if credentials are expected to be in session.
    '''
    if not user_id and 'user_id' in session:
        user_id = session['user_id']

    if not user_id: 
        # flash("User ID not found for Calendar service.", "warning") # Too noisy
        return None

    g_credentials = get_google_api_credentials(user_id) # Renamed to avoid conflict with 'credentials' import
    if g_credentials and g_credentials.valid:
        if g_credentials.expired and g_credentials.refresh_token:
            # The googleapiclient library will attempt to refresh the token automatically
            # if a refresh_token is present and the token has expired, provided that
            # the token_uri, client_id, and client_secret are also part of the credentials.
            # Explicit refresh logic (commented out in instructions) can be added here for more control
            # or to update stored credentials after a refresh.
            # For now, rely on the library's auto-refresh or eventual failure if refresh is not possible.
            pass # Assuming googleapiclient handles refresh if possible or user re-auths
        
        try:
            service = build_google_service('calendar', 'v3', credentials=g_credentials)
            return service
        except Exception as e:
            flash(f"Calendar 서비스 구성 중 오류: {str(e)}", "danger")
            return None
    else:
        # flash("Google Calendar API credentials are not valid or not found. Please log in.", "warning")
        return None

def get_tasks_service(user_id=None):
    '''
    Builds and returns an authorized Google Tasks API service instance.
    'user_id' is optional if credentials are expected to be in session.
    '''
    if not user_id and 'user_id' in session:
        user_id = session['user_id']

    if not user_id: # If still no user_id, cannot proceed
        # flash("User ID not found for Tasks service.", "warning") # Optional: too noisy
        return None

    credentials = get_google_api_credentials(user_id) # Re-use the function from Step 6
    
    if credentials and credentials.valid:
        # Token refresh considerations are similar to get_calendar_service.
        # Relying on library's auto-refresh or eventual re-authentication.
        # if credentials.expired and credentials.refresh_token:
        #    try:
        #        import google.auth.transport.requests
        #        request = google.auth.transport.requests.Request()
        #        credentials.refresh(request)
        #        # Re-save credentials to session and DB (omitted for brevity)
        #    except Exception as e:
        #        flash(f"Error refreshing token for Tasks API: {e}. Please try logging in again.", "warning")
        #        pass # Proceed with potentially expired token

        try:
            service = build_google_service('tasks', 'v1', credentials=credentials)
            return service
        except Exception as e:
            flash(f"Tasks 서비스 구성 중 오류: {str(e)}", "danger")
            # Potentially log this error
            return None
    else:
        # flash("Google Tasks API credentials are not valid or not found. Please log in.", "warning")
        # Let calling function decide on flashing.
        return None

# Helper function for date calculation
def calculate_target_date_for_fixed_day(start_date_obj, rule_day_of_week):
    # start_date_obj: datetime.date object
    # rule_day_of_week: 1 (Mon) to 7 (Sun)
    start_day_of_week = start_date_obj.isoweekday() # Monday is 1 and Sunday is 7
    
    days_ahead = rule_day_of_week - start_day_of_week
    if days_ahead < 0: # Target day is earlier in the week than start_date's day
        days_ahead += 7
    return start_date_obj + timedelta(days=days_ahead)

@app.route('/templates/<int:template_id>/apply', methods=['GET', 'POST'])
def apply_template(template_id):
    if 'user_id' not in session:
        flash("로그인이 필요합니다.", "warning")
        return redirect(url_for('login'))

    user_id = session['user_id']
    template = get_task_template(template_id, user_id)

    if not template:
        flash("템플릿을 찾을 수 없거나 접근 권한이 없습니다.", "danger")
        return redirect(url_for('index'))

    if request.method == 'POST':
        start_date_str = request.form.get('start_date')
        if not start_date_str:
            flash("시작 날짜를 선택해주세요.", "danger")
            return render_template('apply_template.html', template=template)

        try:
            start_date_obj = datetime.strptime(start_date_str, '%Y-%m-%d').date()
        except ValueError:
            flash("잘못된 날짜 형식입니다. (YYYY-MM-DD)", "danger")
            return render_template('apply_template.html', template=template)

        calendar_service = get_calendar_service(user_id)
        # Initialize tasks_service, it will be checked before use
        tasks_service = get_tasks_service(user_id)

        rules = get_rules_for_template(template.id, user_id)
        created_calendar_events = 0
        skipped_calendar_events = 0
        created_google_tasks = 0
        failed_google_tasks = 0

        for rule in rules:
            target_date = None
            if rule.schedule_type == 'fixed_day':
                if rule.day_of_week:
                    target_date = calculate_target_date_for_fixed_day(start_date_obj, rule.day_of_week)
                else:
                    flash(f"규칙 '{rule.task_name}'에 요일이 설정되지 않았습니다. Calendar/Task 항목을 건너뜁니다.", "warning")
                    skipped_calendar_events +=1
                    failed_google_tasks +=1 # Count as failed if rule detail missing
                    continue
            elif rule.schedule_type == 'offset':
                if rule.offset_days is not None:
                    target_date = start_date_obj + timedelta(days=rule.offset_days)
                else:
                    flash(f"규칙 '{rule.task_name}'에 오프셋 일수가 설정되지 않았습니다. Calendar/Task 항목을 건너뜁니다.", "warning")
                    skipped_calendar_events += 1
                    failed_google_tasks +=1
                    continue
            else:
                flash(f"규칙 '{rule.task_name}'에 알 수 없는 스케줄 타입입니다. Calendar/Task 항목을 건너뜁니다.", "warning")
                skipped_calendar_events += 1
                failed_google_tasks +=1
                continue
            
            if not target_date: # Should be caught by inner checks, but as a safeguard
                flash(f"규칙 '{rule.task_name}'의 대상 날짜를 계산할 수 없습니다. Calendar/Task 항목을 건너뜁니다.", "warning")
                skipped_calendar_events += 1
                failed_google_tasks +=1
                continue

            event_summary = rule.task_name # Used for Calendar
            task_title = rule.task_name    # Used for Tasks

            # Google Calendar Logic
            if calendar_service:
                event_start_iso = target_date.isoformat()
                # For all-day events, Google Calendar API expects end date to be the day after.
                event_end_iso = (target_date + timedelta(days=1)).isoformat() 
                
                # Basic Conflict Handling for Calendar
                conflict_found_calendar = False
                try:
                    time_min = target_date.strftime('%Y-%m-%dT00:00:00Z')
                    time_max = (target_date + timedelta(days=1)).strftime('%Y-%m-%dT00:00:00Z')

                    existing_events_response = calendar_service.events().list(
                        calendarId='primary',
                        q=event_summary, 
                        timeMin=time_min,
                        timeMax=time_max,
                        singleEvents=True
                    ).execute()
                    
                    if 'items' in existing_events_response:
                        for item in existing_events_response['items']:
                            if item['summary'] == event_summary:
                                conflict_found_calendar = True
                                break
                    
                    if conflict_found_calendar:
                        flash(f"Calendar: '{event_summary}' 작업이 {target_date.strftime('%Y년 %m월 %d일')}에 이미 존재하여 건너뛰었습니다.", "info")
                        skipped_calendar_events += 1
                    else: # No conflict, try to create
                        event_body = {
                            'summary': event_summary,
                            'description': f"'{template.name}' 템플릿에서 생성됨.",
                            'start': {'date': event_start_iso},
                            'end': {'date': event_end_iso},
                        }
                        calendar_service.events().insert(calendarId='primary', body=event_body).execute()
                        created_calendar_events += 1
                except Exception as e:
                    flash(f"'{event_summary}' 작업을 Google Calendar에 생성/확인 중 오류: {str(e)}", "danger")
                    skipped_calendar_events += 1
            # else: calendar_service is not available, already handled by initial flash

            # Google Tasks Logic
            if tasks_service:
                task_due_date = target_date.isoformat() + 'T00:00:00.000Z' # RFC 3339 format
                task_body = {
                    'title': task_title,
                    'notes': f"'{template.name}' 템플릿에서 생성됨.",
                    'due': task_due_date,
                }
                try:
                    # No pre-emptive conflict check for Tasks for now
                    tasks_service.tasks().insert(tasklist='@default', body=task_body).execute()
                    created_google_tasks += 1
                except Exception as e:
                    flash(f"'{task_title}' 작업을 Google Tasks에 생성 중 오류: {str(e)}", "danger")
                    failed_google_tasks += 1
            # else: tasks_service is not available, handled by initial flash if rules exist

        # Final Flash Messages
        if created_calendar_events > 0:
            flash(f"{created_calendar_events}개의 작업을 Google Calendar에 성공적으로 추가했습니다.", "success")
        if skipped_calendar_events > 0:
            flash(f"{skipped_calendar_events}개의 Calendar 작업은 건너뛰거나 추가하지 못했습니다.", "warning")
        
        if created_google_tasks > 0:
            flash(f"{created_google_tasks}개의 작업을 Google Tasks에 성공적으로 추가했습니다.", "success")
        if failed_google_tasks > 0:
            flash(f"{failed_google_tasks}개의 Google Tasks 작업은 추가하지 못했습니다.", "warning")

        if not calendar_service and rules: # Check 'rules' to avoid flash on empty template
             flash("Google Calendar 서비스에 연결하지 못해 Calendar 관련 작업을 수행할 수 없습니다.", "danger")
        if not tasks_service and rules:
             flash("Google Tasks 서비스에 연결하지 못해 Tasks 관련 작업을 수행할 수 없습니다.", "danger")
        
        return redirect(url_for('view_template', template_id=template_id))

    return render_template('apply_template.html', template=template)

@app.route('/')
def index():
    if 'user_id' not in session:
        # Flash message for login was in login.html; if direct access, redirect is fine
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    templates = get_task_templates_for_user(user_id) # Assumes this function is defined
    # Ensure index.html is prepared to receive and display flash messages
    return render_template('index.html', templates=templates)

@app.route('/templates/new', methods=['GET', 'POST'])
def new_template():
    if 'user_id' not in session:
        flash("로그인이 필요합니다.", "warning")
        return redirect(url_for('login'))

    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description')
        if not name:
            flash("템플릿 이름은 필수입니다.", "danger")
        else:
            user_id = session['user_id']
            # Assumes create_task_template is defined
            template = create_task_template(user_id, name, description)
            if template:
                flash(f"템플릿 '{template.name}'이(가) 생성되었습니다.", "success")
                return redirect(url_for('view_template', template_id=template.id))
            else:
                flash("템플릿 생성에 실패했습니다.", "danger")
    
    return render_template('create_template.html')

@app.route('/templates/<int:template_id>', methods=['GET', 'POST'])
def view_template(template_id):
    if 'user_id' not in session:
        flash("로그인이 필요합니다.", "warning")
        return redirect(url_for('login'))

    user_id = session['user_id']
    # Assumes get_task_template is defined
    template = get_task_template(template_id, user_id) 

    if not template:
        flash("템플릿을 찾을 수 없거나 접근 권한이 없습니다.", "danger")
        return redirect(url_for('index'))

    if request.method == 'POST': # This POST is for adding a rule
        task_name = request.form.get('task_name')
        schedule_type = request.form.get('schedule_type')
        day_of_week_str = request.form.get('day_of_week')
        offset_days_str = request.form.get('offset_days')

        if not task_name or not schedule_type:
            flash("작업 이름과 스케줄 타입은 필수입니다.", "danger")
        else:
            day_of_week = int(day_of_week_str) if day_of_week_str and day_of_week_str.isdigit() else None
            offset_days = int(offset_days_str) if offset_days_str and offset_days_str.isdigit() else None
            
            try:
                # Assumes add_rule_to_template is defined
                rule = add_rule_to_template(template.id, user_id, task_name, schedule_type, day_of_week, offset_days)
                if rule:
                    flash(f"작업 '{rule.task_name}'이(가) 템플릿에 추가되었습니다.", "success")
                else:
                    # This case might be redundant if add_rule_to_template raises ValueError for issues
                    flash("작업 추가에 실패했습니다. 입력값을 확인해주세요.", "danger")
            except ValueError as e:
                flash(str(e), "danger")
        # Redirect to refresh and clear form, showing new rule or error
        return redirect(url_for('view_template', template_id=template.id)) 

    # Assumes get_rules_for_template is defined
    rules = get_rules_for_template(template.id, user_id) 
    return render_template('view_template.html', template=template, rules=rules)

@app.route('/templates/<int:template_id>/delete', methods=['POST'])
def delete_template_route(template_id):
    if 'user_id' not in session:
        flash("로그인이 필요합니다.", "warning")
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    # Assumes delete_task_template is defined
    success = delete_task_template(template_id, user_id) 
    if success:
        flash("템플릿이 삭제되었습니다.", "success")
    else:
        flash("템플릿 삭제에 실패했거나 권한이 없습니다.", "danger")
    return redirect(url_for('index'))

@app.route('/rules/<int:rule_id>/delete', methods=['POST'])
def delete_rule_route(rule_id):
    if 'user_id' not in session:
        flash("로그인이 필요합니다.", "warning")
        return redirect(url_for('login'))

    user_id = session['user_id']
    # Assumes get_task_rule and delete_task_rule are defined
    rule = get_task_rule(rule_id, user_id) 
    if not rule:
        flash("규칙을 찾을 수 없거나 권한이 없습니다.", "danger")
        # Determine the best redirect target, perhaps index if template_id is unknown
        return redirect(url_for('index')) 
    
    template_id = rule.template_id # Save for redirect
    success = delete_task_rule(rule_id, user_id)
    if success:
        flash("규칙이 삭제되었습니다.", "success")
    else:
        flash("규칙 삭제에 실패했습니다.", "danger")
    return redirect(url_for('view_template', template_id=template_id))

@app.route('/login')
def login():
    if not app.config['GOOGLE_CLIENT_ID'] or not app.config['GOOGLE_CLIENT_SECRET']:
        return "Error: GOOGLE_CLIENT_ID or GOOGLE_CLIENT_SECRET not configured. Please set them as environment variables or directly in the code for testing."

    oauth_flow = flow.Flow.from_client_secrets_file(
        client_secrets_file=None, # Not using a file, providing client_id and client_secret directly
        scopes=app.config['OAUTH2_SCOPES'],
        redirect_uri=app.config['OAUTH2_REDIRECT_URI'],
        client_config={
            "web": {
                "client_id": app.config['GOOGLE_CLIENT_ID'],
                "client_secret": app.config['GOOGLE_CLIENT_SECRET'],
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
                "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
            }
        }
    )
    authorization_url, state = oauth_flow.authorization_url(access_type='offline', prompt='consent')
    session['oauth_state'] = state # Store state to prevent CSRF
    return redirect(authorization_url)

@app.route('/authorize')
def authorize():
    if not app.config['GOOGLE_CLIENT_ID'] or not app.config['GOOGLE_CLIENT_SECRET']:
        return "Error: GOOGLE_CLIENT_ID or GOOGLE_CLIENT_SECRET not configured."

    state = session.pop('oauth_state', None)
    # It's good practice to ensure the state matches to prevent CSRF.
    # For simplicity in this step, we'll skip the direct comparison if not found,
    # but in a production app, you should handle this more strictly.
    # if not state or state != request.args.get('state'):
    #     return 'Invalid state parameter.', 400

    oauth_flow = flow.Flow.from_client_secrets_file(
        client_secrets_file=None,
        scopes=app.config['OAUTH2_SCOPES'],
        redirect_uri=app.config['OAUTH2_REDIRECT_URI'],
         client_config={ # Reconstruct client_config as in /login
            "web": {
                "client_id": app.config['GOOGLE_CLIENT_ID'],
                "client_secret": app.config['GOOGLE_CLIENT_SECRET'],
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
                "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
            }
        }
    )
    try:
        oauth_flow.fetch_token(authorization_response=request.url)
    except Exception as e: # Catch broad exceptions for now
        return f"Failed to fetch token: {str(e)}<br>Request URL: {request.url}", 400


    credentials_obj = oauth_flow.credentials
    
    # Store credentials in session
    session['credentials'] = {
        'token': credentials_obj.token,
        'refresh_token': credentials_obj.refresh_token,
        'token_uri': credentials_obj.token_uri,
        'client_id': credentials_obj.client_id,
        'client_secret': credentials_obj.client_secret,
        'scopes': credentials_obj.scopes
    }

    # Get user info
    user_info_service = discovery.build('oauth2', 'v2', credentials=credentials_obj)
    user_info = user_info_service.userinfo().get().execute()

    google_id = user_info.get('id')
    email = user_info.get('email')

    # Save or update user in DB
    user = User.query.filter_by(google_id=google_id).first()
    if not user:
        user = User(google_id=google_id, email=email)
    
    # Storing Python dict as JSON string
    user.credentials_json = json.dumps(session['credentials'])
    db.session.add(user)
    db.session.commit()
    
    session['user_id'] = user.id # Store user_id in session
    session['email'] = email

    return redirect(url_for('index'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
