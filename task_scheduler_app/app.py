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

def get_task_lists(user_id):
    task_lists = []
    tasks_service = get_tasks_service(user_id) # Assumes this helper exists
    if tasks_service:
        try:
            response = tasks_service.tasklists().list().execute()
            items = response.get('items', [])
            for item in items:
                task_lists.append({'id': item.get('id'), 'title': item.get('title', '제목 없음')})
        except Exception as e:
            flash(f"Google Task 목록을 가져오는 중 오류 발생: {str(e)}", "danger")
            # Return empty list or handle error as appropriate
    else:
        flash("Google Tasks 서비스에 연결할 수 없어 작업 목록을 가져올 수 없습니다.", "warning")
    return task_lists

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

        session['apply_template_start_date'] = start_date_str
        session['apply_template_id'] = template_id
        
        proposed_actions = []
        calendar_service = get_calendar_service(user_id)
        # tasks_service = get_tasks_service(user_id) # Get this only in confirmation step if needed

        if not calendar_service: # If calendar is essential for conflict checking, stop early
            flash("Google Calendar 서비스에 연결할 수 없어 충돌 확인을 진행할 수 없습니다. 다시 시도해주세요.", "danger")
            return render_template('apply_template.html', template=template)

        rules = get_rules_for_template(template.id, user_id)

        for rule in rules:
            target_date = None
            rule_schedule_info = f"{rule.schedule_type} - 요일: {rule.day_of_week}, 오프셋: {rule.offset_days}"
            
            if rule.schedule_type == 'fixed_day':
                if rule.day_of_week:
                    target_date = calculate_target_date_for_fixed_day(start_date_obj, rule.day_of_week)
            elif rule.schedule_type == 'offset':
                if rule.offset_days is not None:
                    target_date = start_date_obj + timedelta(days=rule.offset_days)
            
            if not target_date:
                error_msg = '규칙에 날짜를 계산할 수 있는 충분한 정보가 없습니다.'
                proposed_actions.append({
                    'rule_id': rule.id, 'task_name': rule.task_name, 'schedule_info': rule_schedule_info,
                    'target_date_iso': None, 'type': 'calendar', 'action': 'skip_invalid_rule',
                    'conflict_details': None, 'error_message': error_msg
                })
                proposed_actions.append({
                    'rule_id': rule.id, 'task_name': rule.task_name, 'schedule_info': rule_schedule_info,
                    'target_date_iso': None, 'type': 'task', 'action': 'skip_invalid_rule',
                    'conflict_details': None, 'error_message': error_msg
                })
                continue

            # --- Calendar Event Proposal ---
            calendar_action = {
                'rule_id': rule.id, 'task_name': rule.task_name, 
                'target_date_iso': target_date.isoformat(), 'type': 'calendar',
                'action': 'create', 'conflict_details': None
            }
            event_summary = rule.task_name
            # Using datetime.combine and then isoformat() + 'Z' for robust RFC3339 UTC timestamps
            time_min_dt = datetime.combine(target_date, datetime.min.time())
            time_max_dt = datetime.combine(target_date + timedelta(days=1), datetime.min.time())
            time_min_iso = time_min_dt.isoformat() + 'Z'
            time_max_iso = time_max_dt.isoformat() + 'Z'
            
            try:
                existing_events_response = calendar_service.events().list(
                    calendarId='primary', q=event_summary,
                    timeMin=time_min_iso, timeMax=time_max_iso,
                    singleEvents=True
                ).execute()
                
                if 'items' in existing_events_response:
                    for item in existing_events_response['items']:
                        if item['summary'] == event_summary:
                            calendar_action['conflict_details'] = {
                                'id': item.get('id'), 'summary': item.get('summary'),
                                'start': item.get('start'), 'end': item.get('end')
                            }
                            # Action remains 'create', user will choose 'skip' or 'overwrite' on confirm page
                            break 
            except Exception as e:
                calendar_action['error_message'] = f"Calendar 중복 확인 중 오류: {str(e)}"
                # Action remains 'create', user might still want to try
            proposed_actions.append(calendar_action)

            # --- Google Task Proposal (basic structure for now) ---
            task_action = {
                'rule_id': rule.id, 'task_name': rule.task_name,
                'target_date_iso': target_date.isoformat(), 'type': 'task',
                'action': 'create', 'conflict_details': None 
                # No conflict check for tasks in this phase.
                # tasks_service is not called here to avoid using it if user cancels.
            }
            proposed_actions.append(task_action)

        session['proposed_actions'] = proposed_actions
        session.pop('apply_results', None) # Clear any old results
        
        return redirect(url_for('confirm_apply_route', template_id=template_id))

    # GET request still renders the initial apply_template page
    return render_template('apply_template.html', template=template)

@app.route('/confirm_apply/<int:template_id>', methods=['GET', 'POST'])
def confirm_apply_route(template_id): # template_id from URL for context, but real data is from session
    if 'user_id' not in session:
        flash("로그인이 필요합니다.", "warning")
        return redirect(url_for('login'))

    actual_template_id = session.get('apply_template_id')
    proposed_actions = session.get('proposed_actions')
    start_date_str = session.get('apply_template_start_date')

    if not proposed_actions or not actual_template_id or actual_template_id != template_id:
        flash("적용할 작업 세부 정보가 없거나 만료되었습니다. 다시 시도해주세요.", "warning")
        return redirect(url_for('view_template', template_id=template_id))

    template = get_task_template(actual_template_id, session['user_id'])
    if not template: # Should not happen if session is consistent
        flash("템플릿을 찾을 수 없습니다.", "danger")
        return redirect(url_for('index'))

    if request.method == 'POST':
        selected_task_list_id = request.form.get('selected_task_list_id', '@default')
        # Pop from session immediately to prevent re-processing
        final_actions = session.pop('proposed_actions', []) 
        session.pop('apply_template_start_date', None)
        session.pop('apply_template_id', None)

        calendar_service = get_calendar_service(session['user_id'])
        tasks_service = get_tasks_service(session['user_id'])
        
        apply_results = [] # To store detailed results for the summary page

        for action in final_actions:
            result_action = action.copy() # Start with the proposed action details
            result_action['status_message'] = '' # Initialize status message

            # Handle user choices for Calendar conflicts
            if action['type'] == 'calendar' and action.get('conflict_details') and action['action'] == 'create' and not action.get('error_message'):
                user_choice = request.form.get(f"calendar_conflict_resolution_{action['rule_id']}")
                if user_choice == 'skip':
                    action['action'] = 'skip' # Update action based on user choice
            
            # Execute actions
            if action['action'] == 'skip_invalid_rule':
                result_action['status_message'] = action.get('error_message', "규칙 오류로 건너뜁니다.")
                apply_results.append(result_action)
                continue
            if action['action'] == 'skip_service_unavailable': # This was not set in step 12, but good to handle
                result_action['status_message'] = action.get('error_message', "서비스 사용 불가로 건너뜁니다.")
                apply_results.append(result_action)
                continue
            if action['action'] == 'skip':
                result_action['status_message'] = "사용자 선택으로 건너뛰었습니다." if action['type'] == 'calendar' else "건너뛰었습니다."
                apply_results.append(result_action)
                continue

            # Process Calendar Event Creation
            if action['type'] == 'calendar' and action['action'] == 'create':
                if not calendar_service:
                    result_action['status_message'] = "Google Calendar 서비스 사용 불가로 생성 실패."
                elif action.get('target_date_iso'):
                    event_body = {
                        'summary': action['task_name'],
                        'description': f"'{template.name}' 템플릿에서 생성됨.",
                        'start': {'date': action['target_date_iso']},
                        'end': {'date': (datetime.strptime(action['target_date_iso'], '%Y-%m-%d').date() + timedelta(days=1)).isoformat()},
                    }
                    try:
                        created_event = calendar_service.events().insert(calendarId='primary', body=event_body).execute()
                        result_action['status_message'] = f"Calendar 이벤트 생성됨 (ID: {created_event.get('id')})."
                        result_action['created_item_id'] = created_event.get('id')
                    except Exception as e:
                        result_action['status_message'] = f"Calendar 이벤트 생성 오류: {str(e)}"
                else: # Should have been caught by skip_invalid_rule
                    result_action['status_message'] = "Calendar 이벤트 생성 오류: 대상 날짜 없음."
                apply_results.append(result_action)

            # Process Google Task Creation
            elif action['type'] == 'task' and action['action'] == 'create':
                if not tasks_service:
                    result_action['status_message'] = "Google Tasks 서비스 사용 불가로 생성 실패."
                elif action.get('target_date_iso'):
                    task_body = {
                        'title': action['task_name'],
                        'notes': f"'{template.name}' 템플릿에서 생성됨.",
                        'due': action['target_date_iso'] + 'T00:00:00.000Z',
                    }
                    # Use the selected_task_list_id obtained from the form
                    try:
                        # Ensure task_list_id is the selected one
                        created_task = tasks_service.tasks().insert(tasklist=selected_task_list_id, body=task_body).execute()
                        result_action['status_message'] = f"Task 생성됨 (목록 ID: {selected_task_list_id}, 작업 ID: {created_task.get('id')})."
                        # Store the list ID in the result for the summary page
                        result_action['task_list_id_used'] = selected_task_list_id 
                        result_action['created_item_id'] = created_task.get('id')
                    except Exception as e:
                        result_action['status_message'] = f"Task 생성 오류: {str(e)}"
                else: # Should have been caught by skip_invalid_rule
                    result_action['status_message'] = "Task 생성 오류: 대상 날짜 없음."
                apply_results.append(result_action)
        
        session['apply_results'] = apply_results
        # The redirect should be to a new summary route, which is not yet defined.
        # For now, redirecting to view_template with a generic message or a placeholder route.
        # flash("작업 적용 처리가 완료되었습니다. 요약 정보는 곧 제공될 예정입니다.", "success")
        return redirect(url_for('apply_summary_route', template_id=template.id)) # Placeholder for next step

    # GET request
    user_task_lists = get_task_lists(session['user_id'])
    session['start_date_for_summary_display'] = start_date_str # Store for summary page
    return render_template('confirm_apply.html', 
                           proposed_actions=proposed_actions, 
                           template=template, 
                           start_date_str=start_date_str,
                           user_task_lists=user_task_lists) # Added

@app.route('/cancel_apply/<int:template_id>', methods=['GET'])
def cancel_apply_route(template_id):
    if 'user_id' not in session:
        # flash("로그인이 필요합니다.", "warning") # Optional: usually not needed for cancel
        return redirect(url_for('login'))
    
    # Clear session variables related to this apply process
    session.pop('proposed_actions', None)
    session.pop('apply_template_start_date', None)
    session.pop('apply_template_id', None)
    session.pop('apply_results', None) # Clear any stale results too

    flash("작업 적용이 취소되었습니다.", "info")
    # template_id from URL is reliable here as it's for redirect context
    return redirect(url_for('view_template', template_id=template_id)) 

@app.route('/apply_summary/<int:template_id>')
def apply_summary_route(template_id):
    if 'user_id' not in session:
        flash("로그인이 필요합니다.", "warning")
        return redirect(url_for('login'))
    
    template = get_task_template(template_id, session['user_id'])
    # Note: template might be None if it was deleted after apply started,
    # but we still want to show results. apply_summary.html handles template being None.
            
    apply_results = session.pop('apply_results', [])
    start_date_str_for_display = session.pop('start_date_for_summary_display', '날짜 정보 없음')

    if not apply_results:
        flash("표시할 적용 결과가 없습니다. 만료되었거나 직접 접근하셨을 수 있습니다.", "info")
        return redirect(url_for('view_template', template_id=template_id) if template else url_for('index'))

    return render_template('apply_summary.html', 
                           apply_results=apply_results, 
                           template=template, 
                           original_template_id=template_id, 
                           start_date_applied=start_date_str_for_display)

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

@app.route('/rule/<int:rule_id>/edit', methods=['GET'])
def edit_task_rule_form_route(rule_id):
    if 'user_id' not in session:
        flash("로그인이 필요합니다.", "warning")
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    rule_to_edit = get_task_rule(rule_id, user_id) 

    if not rule_to_edit:
        flash("수정할 규칙을 찾을 수 없거나 접근 권한이 없습니다.", "danger")
        return redirect(url_for('index')) 

    template = get_task_template(rule_to_edit.template_id, user_id)
    if not template: 
        flash("템플릿을 찾을 수 없습니다.", "danger")
        return redirect(url_for('index'))
    
    rules = get_rules_for_template(template.id, user_id) 

    form_action_url = url_for('update_task_rule_submit_route', rule_id=rule_to_edit.id)
    form_submit_button_text = "규칙 저장"
    
    return render_template('view_template.html', 
                           template=template, 
                           rules=rules, 
                           rule_to_edit=rule_to_edit,
                           form_action_url=form_action_url,
                           form_submit_button_text=form_submit_button_text)

@app.route('/rule/<int:rule_id>/update', methods=['POST'])
def update_task_rule_submit_route(rule_id):
    if 'user_id' not in session:
        flash("로그인이 필요합니다.", "warning")
        return redirect(url_for('login'))

    user_id = session['user_id']
    rule = get_task_rule(rule_id, user_id) 

    if not rule:
        flash("업데이트할 규칙을 찾을 수 없거나 접근 권한이 없습니다.", "danger")
        return redirect(url_for('index')) 

    task_name = request.form.get('task_name')
    schedule_type = request.form.get('schedule_type')
    day_of_week_str = request.form.get('day_of_week')
    offset_days_str = request.form.get('offset_days')

    if not task_name or not schedule_type:
        flash("작업 이름과 스케줄 타입은 필수입니다.", "danger")
        # To redirect back to the edit form properly, we need to re-render it with context
        # This is a simplified redirect, losing immediate form values but showing flash.
        # A more robust solution might store form data in session or re-render directly.
        return redirect(url_for('edit_task_rule_form_route', rule_id=rule_id))


    day_of_week = int(day_of_week_str) if day_of_week_str and day_of_week_str.isdigit() else None
    offset_days = int(offset_days_str) if offset_days_str and offset_days_str.isdigit() else None

    try:
        updated_rule = update_task_rule( 
            rule_id=rule.id, 
            user_id=user_id, 
            task_name=task_name, 
            schedule_type=schedule_type, 
            day_of_week=day_of_week, 
            offset_days=offset_days
        )
        if updated_rule:
            flash(f"규칙 '{updated_rule.task_name}'이(가) 성공적으로 업데이트되었습니다.", "success")
        else:
            flash("규칙 업데이트에 실패했습니다. (함수에서 None 반환)", "danger")
    except ValueError as e:
        flash(str(e), "danger") 
    
    return redirect(url_for('view_template', template_id=rule.template_id))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
