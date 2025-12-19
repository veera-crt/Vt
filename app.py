from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
import os
import psycopg2
import random
import string
import threading
from datetime import datetime, timedelta
from dotenv import load_dotenv
from flask_mail import Mail, Message
from flask_bcrypt import Bcrypt
from utils import encrypt_data, decrypt_data
import re

load_dotenv()

# Thread-local storage for DB connections - FAST and REUSABLE
local_data = threading.local()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')





def get_db_connection():
    if not hasattr(local_data, 'conn') or local_data.conn.closed != 0:
        local_data.conn = psycopg2.connect(os.getenv('DATABASE_URL'))
    return local_data.conn

def release_db_connection(conn):
    # We keep the connection open in thread-local storage for reuse
    # Just need to make sure any pending transactions are handled if needed
    pass

# Mail Configuration
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT') or 587)
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS') == 'True'
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['BCRYPT_LOG_ROUNDS'] = 4 # Faster hashing for development/speed
mail = Mail(app)
bcrypt = Bcrypt(app)



# --- Helper Functions ---
def generate_otp():
    return ''.join(random.choices(string.digits, k=6))



def send_email(to, subject, body):
    msg = Message(subject, sender=app.config['MAIL_USERNAME'], recipients=[to])
    msg.body = body
    try:
        mail.send(msg)
        return True
    except Exception as e:
        print(f"Failed to send email to {to}: {e}")
        return False

# --- Routes ---

@app.route('/')
def index():
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        
        # Get latest active election
        cur.execute("SELECT id, title, status FROM elections WHERE status = 'active' ORDER BY created_at DESC LIMIT 1")
        election = cur.fetchone()
        
        election_data = None
        if election:
            # Optimized: Get candidates and total votes in one query using a window function or subquery
            cur.execute("""
                SELECT name, vote_count, (SELECT SUM(vote_count) FROM candidates WHERE election_id = %s) 
                FROM candidates 
                WHERE election_id = %s 
                ORDER BY vote_count DESC 
                LIMIT 2
            """, (election[0], election[0]))
            candidates = cur.fetchall()
            
            election_total_votes = 0
            if candidates:
                election_total_votes = candidates[0][2] or 0
                
            cand_list = []
            for c in candidates:
                percentage = 0
                if election_total_votes > 0:
                    percentage = round((c[1] / election_total_votes) * 100, 1)
                cand_list.append({'name': c[0], 'percentage': percentage})
                
            election_data = {
                'title': election[1],
                'status': election[2],
                'candidates': cand_list
            }
            
        cur.close()
        return render_template('index.html', election=election_data)
    finally:
        release_db_connection(conn)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        full_name = request.form['fullname']
        voter_id = request.form['voter_id']
        email = request.form['email']
        password = request.form['password']
        
        # Encrypt sensitive data
        enc_name = encrypt_data(full_name)
        enc_voter_id = encrypt_data(voter_id)
        hashed_pw = bcrypt.generate_password_hash(password).decode('utf-8')
        
        otp = generate_otp()
        otp_expiry = datetime.now() + timedelta(minutes=10)
        
        conn = get_db_connection()
        cur = conn.cursor()
        try:
            cur.execute("""
                INSERT INTO users (full_name, voter_id, email, password_hash, otp_code, otp_expiry)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (enc_name, enc_voter_id, email, hashed_pw, otp, otp_expiry))
            conn.commit()
            
            # Send OTP Asynchronously
            send_email(email, "Verify your Email - SecureVote", f"Your OTP is: {otp}")
            
            session['email_to_verify'] = email
            return redirect(url_for('verify_otp'))
            
        except psycopg2.IntegrityError:
            conn.rollback()
            flash('Email or Voter ID already exists.', 'error')
        finally:
            cur.close()
            release_db_connection(conn)
            
    return render_template('register.html')

@app.route('/resend-otp')
def resend_otp():
    email = session.get('email_to_verify')
    if not email:
        flash('Session expired. Please login or register again.', 'error')
        return redirect(url_for('login'))
        
    otp = generate_otp()
    otp_expiry = datetime.now() + timedelta(minutes=10)
    
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute("UPDATE users SET otp_code = %s, otp_expiry = %s WHERE email = %s", (otp, otp_expiry, email))
        conn.commit()
        cur.close()
        
        send_email(email, "Resend OTP - SecureVote", f"Your new OTP is: {otp}")
        flash('A new OTP has been sent to your email.', 'info')
        return redirect(url_for('verify_otp'))
    finally:
        release_db_connection(conn)

@app.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():
    if request.method == 'POST':
        otp_input = request.form['otp']
        email = session.get('email_to_verify')
        
        if not email:
            return redirect(url_for('login'))
            
        conn = get_db_connection()
        try:
            cur = conn.cursor()
            cur.execute("SELECT otp_code, otp_expiry FROM users WHERE email = %s", (email,))
            user = cur.fetchone()
            
            if user and user[0] == otp_input and user[1] > datetime.now():
                cur.execute("UPDATE users SET is_email_verified = TRUE, otp_code = NULL WHERE email = %s", (email,))
                conn.commit()
                flash('Email verified! Waiting for Admin Approval.', 'success')
                return redirect(url_for('login'))
            else:
                flash('Invalid or Expired OTP', 'error')
            
            cur.close()
        finally:
            release_db_connection(conn)
        
    return render_template('verify_otp.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        identifier = request.form.get('voter_id') # Can be email or voter_id logic
        password = request.form['password']
        
        # Note: Since voter_id is encrypted, we can't search by it easily unless we use email for login
        # Or we encrypt the input and search (deterministic encryption needed)
        # For this demo, let's assume login is by EMAIL for simplicity, or we fetch all and check (slow)
        # Better: Login by Email.
        
        # If the form sends 'voter_id' as name but user types email:
        email_input = identifier 
        
        conn = get_db_connection()
        cur = conn.cursor()
        try:
            cur.execute("SELECT id, password_hash, is_email_verified, is_approved, is_admin, full_name FROM users WHERE email = %s", (email_input,))
            user = cur.fetchone()
            
            if user and bcrypt.check_password_hash(user[1], password):
                if not user[2]:
                    session['email_to_verify'] = email_input
                    return redirect(url_for('verify_otp'))
                if not user[3] and not user[4]: # Not approved and not admin
                    flash('Account pending admin approval.', 'warning')
                    return redirect(url_for('login'))
                    
                # 2FA Step
                otp = generate_otp()
                # Update DB with new OTP - REUSE CONNECTION
                cur.execute("UPDATE users SET otp_code = %s, otp_expiry = %s WHERE id = %s", (otp, datetime.now() + timedelta(minutes=5), user[0]))
                conn.commit()
                
                send_email(email_input, "Login OTP - SecureVote", f"Your Login OTP is: {otp}")
                session['user_id_temp'] = user[0]
                session['is_admin_temp'] = user[4]
                return redirect(url_for('login_2fa'))
                
            else:
                flash('Invalid credentials', 'error')
        finally:
            cur.close()
            release_db_connection(conn)
            
    return render_template('login.html')

@app.route('/login-2fa', methods=['GET', 'POST'])
def login_2fa():
    if request.method == 'POST':
        otp = request.form['otp']
        user_id = session.get('user_id_temp')
        
        conn = get_db_connection()
        try:
            cur = conn.cursor()
            cur.execute("SELECT otp_code, otp_expiry, full_name FROM users WHERE id = %s", (user_id,))
            user = cur.fetchone()
            
            if user and user[0] == otp and user[1] > datetime.now():
                # Success
                session['user_id'] = user_id
                session['is_admin'] = session.get('is_admin_temp')
                session.pop('user_id_temp', None)
                session.pop('is_admin_temp', None)
                
                if session['is_admin']:
                    return redirect(url_for('admin_dashboard'))
                return redirect(url_for('dashboard'))
            else:
                flash('Invalid OTP', 'error')
        finally:
            release_db_connection(conn)
            
    return render_template('verify_otp.html', title="Login Verification")

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session: return redirect(url_for('login'))
    
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        
        # Get Elections
        cur.execute("SELECT * FROM elections WHERE status != 'hidden'")
        elections = cur.fetchall()
        
        # Check if user voted in these
        user_votes = []
        cur.execute("SELECT election_id FROM votes WHERE voter_id = %s", (session['user_id'],))
        votes = cur.fetchall()
        user_votes = [v[0] for v in votes]
        
        cur.close()
        return render_template('dashboard.html', elections=elections, user_votes=user_votes)
    finally:
        release_db_connection(conn)

@app.route('/vote/<int:election_id>', methods=['GET', 'POST'])
def vote(election_id):
    if 'user_id' not in session: return redirect(url_for('login'))
    
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        
        if request.method == 'POST':
            candidate_id = request.form['candidate_id']
            try:
                cur.execute("INSERT INTO votes (election_id, voter_id, candidate_id) VALUES (%s, %s, %s)", 
                            (election_id, session['user_id'], candidate_id))
                cur.execute("UPDATE candidates SET vote_count = vote_count + 1 WHERE id = %s", (candidate_id,))
                conn.commit()
                flash('Vote cast successfully!', 'success')
                return redirect(url_for('dashboard'))
            except psycopg2.IntegrityError:
                conn.rollback()
                flash('You have already voted in this election.', 'error')
                
        # Get Election Details
        cur.execute("SELECT * FROM elections WHERE id = %s", (election_id,))
        election = cur.fetchone()
        
        if not election:
            flash('Election not found.', 'error')
            return redirect(url_for('dashboard'))

        # Get Candidates
        cur.execute("SELECT * FROM candidates WHERE election_id = %s", (election_id,))
        candidates = cur.fetchall()
        
        cur.close()
        return render_template('vote.html', candidates=candidates, election=election)
    finally:
        release_db_connection(conn)

# --- Admin Routes ---
@app.route('/admin/login')
def admin_login():
    flash('Please login with your admin credentials.', 'info')
    return redirect(url_for('login'))

@app.route('/admin/dashboard')
def admin_dashboard():
    if not session.get('is_admin'): return redirect(url_for('login'))
    
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        
        # Optimized Stats: Multiple counts in one query
        cur.execute("""
            SELECT 
                (SELECT COUNT(*) FROM users WHERE is_admin = FALSE) as total_voters,
                (SELECT COUNT(*) FROM votes) as total_votes,
                (SELECT COUNT(*) FROM elections WHERE status = 'active') as active_elections
        """)
        stats = cur.fetchone()
        total_voters = stats[0]
        total_votes = stats[1]
        active_elections = stats[2]
        
        # Pending Approvals
        cur.execute("SELECT id, full_name, voter_id, email FROM users WHERE is_approved = FALSE AND is_email_verified = TRUE AND is_admin = FALSE")
        pending_users = cur.fetchall()
        
        # Decrypt data for display
        decrypted_users = []
        for u in pending_users:
            decrypted_users.append({
                'id': u[0],
                'name': decrypt_data(u[1]),
                'voter_id': decrypt_data(u[2]),
                'email': u[3]
            })
            
        cur.close()
        return render_template('admin_dashboard.html', 
                            total_voters=total_voters, 
                            total_votes=total_votes,
                            active_elections=active_elections,
                            pending_users=decrypted_users)
    finally:
        release_db_connection(conn)

@app.route('/admin/approve/<int:user_id>')
def approve_user(user_id):
    if not session.get('is_admin'): return redirect(url_for('login'))
    
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute("UPDATE users SET is_approved = TRUE WHERE id = %s RETURNING email", (user_id,))
        email = cur.fetchone()[0]
        conn.commit()
        cur.close()
        
        send_email(email, "Account Approved - SecureVote", "Your account has been approved by the admin. You can now log in and vote.")
        return redirect(url_for('admin_dashboard'))
    finally:
        release_db_connection(conn)

@app.route('/admin/reject/<int:user_id>')
def reject_user(user_id):
    if not session.get('is_admin'): return redirect(url_for('login'))
    # In a real app, you'd ask for a reason via a form
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        
        # Decrement vote counts for candidates voted by this user
        cur.execute("SELECT candidate_id FROM votes WHERE voter_id = %s", (user_id,))
        user_votes = cur.fetchall()
        for v in user_votes:
            cur.execute("UPDATE candidates SET vote_count = vote_count - 1 WHERE id = %s", (v[0],))
            
        cur.execute("DELETE FROM users WHERE id = %s RETURNING email", (user_id,))
        email = cur.fetchone()[0]
        conn.commit()
        cur.close()
        
        send_email(email, "Account Rejected - SecureVote", "Your account registration was rejected. Please contact support.")
        return redirect(url_for('admin_dashboard'))
    finally:
        release_db_connection(conn)

@app.route('/admin/elections', methods=['GET', 'POST'])
def admin_elections():
    if not session.get('is_admin'): return redirect(url_for('login'))
    
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        
        if request.method == 'POST':
            title = request.form['title']
            description = request.form['description']
            start_date = request.form['start_date']
            end_date = request.form['end_date']
            status = request.form['status']
            
            try:
                cur.execute("""
                    INSERT INTO elections (title, description, start_date, end_date, status)
                    VALUES (%s, %s, %s, %s, %s)
                """, (title, description, start_date, end_date, status))
                conn.commit()
                flash('Election created successfully!', 'success')
                return redirect(url_for('admin_elections'))
            except Exception as e:
                conn.rollback()
                flash(f'Error creating election: {e}', 'error')
                
        # Fetch all elections
        cur.execute("SELECT * FROM elections ORDER BY created_at DESC")
        elections = cur.fetchall()
        
        cur.close()
        return render_template('admin_elections.html', elections=elections)
    finally:
        release_db_connection(conn)

@app.route('/admin/elections/edit/<int:election_id>', methods=['GET', 'POST'])
def edit_election(election_id):
    if not session.get('is_admin'): return redirect(url_for('login'))
    
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        
        if request.method == 'POST':
            title = request.form['title']
            description = request.form['description']
            start_date = request.form['start_date']
            end_date = request.form['end_date']
            status = request.form['status']
            
            try:
                cur.execute("""
                    UPDATE elections 
                    SET title = %s, description = %s, start_date = %s, end_date = %s, status = %s
                    WHERE id = %s
                """, (title, description, start_date, end_date, status, election_id))
                conn.commit()
                flash('Election updated successfully!', 'success')
                return redirect(url_for('admin_elections'))
            except Exception as e:
                conn.rollback()
                flash(f'Error updating election: {e}', 'error')
                
        # Fetch election details
        cur.execute("SELECT * FROM elections WHERE id = %s", (election_id,))
        election = cur.fetchone()
        
        cur.close()
        return render_template('admin_edit_election.html', election=election)
    finally:
        release_db_connection(conn)

@app.route('/admin/elections/delete/<int:election_id>')
def delete_election(election_id):
    if not session.get('is_admin'): return redirect(url_for('login'))
    
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("DELETE FROM elections WHERE id = %s", (election_id,))
        conn.commit()
        flash('Election deleted successfully.', 'success')
    except Exception as e:
        conn.rollback()
        flash(f'Error deleting election: {e}', 'error')
    finally:
        cur.close()
        release_db_connection(conn)
        
    return redirect(url_for('admin_elections'))

@app.route('/admin/candidates/<int:election_id>', methods=['GET', 'POST'])
def admin_candidates(election_id):
    if not session.get('is_admin'): return redirect(url_for('login'))
    
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        
        # Get Election Details
        cur.execute("SELECT * FROM elections WHERE id = %s", (election_id,))
        election = cur.fetchone()
        
        if not election:
            flash('Election not found', 'error')
            return redirect(url_for('admin_elections'))
        
        if request.method == 'POST':
            name = request.form['name']
            party = request.form['party']
            manifesto = request.form['manifesto']
            image_url = request.form['image_url']
            
            # Smart Google Drive Link Fix
            if image_url:
                drive_pattern = r'drive\.google\.com\/file\/d\/([a-zA-Z0-9_-]+)\/'
                match = re.search(drive_pattern, image_url)
                if match:
                    file_id = match.group(1)
                    image_url = f'https://drive.google.com/uc?export=view&id={file_id}'
            
            try:
                cur.execute("""
                    INSERT INTO candidates (election_id, name, party, manifesto, image_url)
                    VALUES (%s, %s, %s, %s, %s)
                """, (election_id, name, party, manifesto, image_url))
                conn.commit()
                conn.commit()
                flash('Candidate added successfully!', 'success')
                return redirect(url_for('admin_candidates', election_id=election_id))
            except Exception as e:
                conn.rollback()
                flash(f'Error adding candidate: {e}', 'error')
                
        # Fetch Candidates
        cur.execute("SELECT * FROM candidates WHERE election_id = %s", (election_id,))
        candidates = cur.fetchall()
        
        cur.close()
        return render_template('admin_candidates.html', election=election, candidates=candidates)
    finally:
        release_db_connection(conn)

    return render_template('admin_candidates.html', election=election, candidates=candidates)

@app.route('/admin/candidates/delete/<int:candidate_id>')
def delete_candidate(candidate_id):
    if not session.get('is_admin'): return redirect(url_for('login'))
    
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        
        # Get election_id before deleting to redirect back correctly
        cur.execute("SELECT election_id FROM candidates WHERE id = %s", (candidate_id,))
        result = cur.fetchone()
        
        if result:
            election_id = result[0]
            cur.execute("DELETE FROM candidates WHERE id = %s", (candidate_id,))
            conn.commit()
            flash('Candidate deleted successfully.', 'success')
            return redirect(url_for('admin_candidates', election_id=election_id))
        else:
            flash('Candidate not found.', 'error')
            return redirect(url_for('admin_elections'))
            
        cur.close()
    finally:
        release_db_connection(conn)

@app.route('/admin/all-candidates')
def admin_all_candidates():
    if not session.get('is_admin'): return redirect(url_for('login'))
    
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        
        cur.execute("""
            SELECT c.id, c.name, c.party, c.vote_count, e.title, e.id
            FROM candidates c
            JOIN elections e ON c.election_id = e.id
            ORDER BY e.created_at DESC
        """)
        rows = cur.fetchall()
        
        candidates = []
        for r in rows:
            candidates.append({
                'id': r[0],
                'name': r[1],
                'party': r[2],
                'votes': r[3],
                'election_title': r[4],
                'election_id': r[5]
            })
            
        cur.close()
        return render_template('admin_all_candidates.html', candidates=candidates)
    finally:
        release_db_connection(conn)

@app.route('/admin/voters')
def admin_voters():
    if not session.get('is_admin'): return redirect(url_for('login'))
    
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        
        cur.execute("SELECT id, full_name, voter_id, email, is_approved, is_email_verified FROM users WHERE is_admin = FALSE ORDER BY created_at DESC")
        rows = cur.fetchall()
        
        voters = []
        for r in rows:
            voters.append({
                'id': r[0],
                'name': decrypt_data(r[1]),
                'voter_id': decrypt_data(r[2]),
                'email': r[3],
                'is_approved': r[4],
                'is_email_verified': r[5]
            })
            
        cur.close()
        return render_template('admin_voters.html', voters=voters)
    finally:
        release_db_connection(conn)

@app.route('/admin/voters/delete/<int:user_id>')
def delete_voter(user_id):
    if not session.get('is_admin'): return redirect(url_for('login'))
    
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        
        # Decrement vote counts for candidates voted by this user
        cur.execute("SELECT candidate_id FROM votes WHERE voter_id = %s", (user_id,))
        user_votes = cur.fetchall()
        for v in user_votes:
            cur.execute("UPDATE candidates SET vote_count = vote_count - 1 WHERE id = %s", (v[0],))
            
        cur.execute("DELETE FROM users WHERE id = %s", (user_id,))
        conn.commit()
        cur.close()
        
        flash('Voter deleted successfully.', 'success')
        return redirect(url_for('admin_voters'))
    finally:
        release_db_connection(conn)

@app.route('/admin/results')
def admin_results():
    if not session.get('is_admin'): return redirect(url_for('login'))
    
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        
        # Get all elections
        cur.execute("SELECT id, title, status FROM elections ORDER BY created_at DESC")
        elections_rows = cur.fetchall()
        
        results = []
        for e_row in elections_rows:
            e_id = e_row[0]
            e_title = e_row[1]
            e_status = e_row[2]
            
            # Get candidates and votes
            cur.execute("SELECT name, party, vote_count FROM candidates WHERE election_id = %s ORDER BY vote_count DESC", (e_id,))
            cand_rows = cur.fetchall()
            
            total_votes = sum([c[2] for c in cand_rows])
            candidates = []
            for c in cand_rows:
                percentage = 0
                if total_votes > 0:
                    percentage = round((c[2] / total_votes) * 100, 1)
                candidates.append({
                    'name': c[0],
                    'party': c[1],
                    'votes': c[2],
                    'percentage': percentage
                })
                
            results.append({
                'title': e_title,
                'status': e_status,
                'total_votes': total_votes,
                'candidates': candidates
            })
            
        cur.close()
        return render_template('admin_results.html', results=results)
    finally:
        release_db_connection(conn)

@app.route('/admin/settings', methods=['GET', 'POST'])
def admin_settings():
    if not session.get('is_admin'): return redirect(url_for('login'))
    
    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        
        if new_password != confirm_password:
            flash('New passwords do not match.', 'error')
            return redirect(url_for('admin_settings'))
            
        conn = get_db_connection()
        try:
            cur = conn.cursor()
            
            # Verify current password
            cur.execute("SELECT password_hash FROM users WHERE id = %s", (session['user_id'],))
            user_pw = cur.fetchone()[0]
            
            if bcrypt.check_password_hash(user_pw, current_password):
                hashed_pw = bcrypt.generate_password_hash(new_password).decode('utf-8')
                cur.execute("UPDATE users SET password_hash = %s WHERE id = %s", (hashed_pw, session['user_id']))
                conn.commit()
                flash('Password updated successfully.', 'success')
            else:
                flash('Incorrect current password.', 'error')
                
            cur.close()
        finally:
            release_db_connection(conn)
        
    return render_template('admin_settings.html')

    return render_template('admin_settings.html')

@app.route('/profile')
def profile():
    if 'user_id' not in session: return redirect(url_for('login'))
    
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        
        cur.execute("SELECT full_name, voter_id, email FROM users WHERE id = %s", (session['user_id'],))
        user_data = cur.fetchone()
        
        user = {
            'name': decrypt_data(user_data[0]),
            'voter_id': decrypt_data(user_data[1]),
            'email': user_data[2]
        }
        
        cur.close()
        return render_template('profile.html', user=user)
    finally:
        release_db_connection(conn)

@app.route('/initiate-password-change', methods=['POST'])
def initiate_password_change():
    if 'user_id' not in session: return redirect(url_for('login'))
    
    current_password = request.form['current_password']
    
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT password_hash, email FROM users WHERE id = %s", (session['user_id'],))
        user = cur.fetchone()
        
        if user and bcrypt.check_password_hash(user[0], current_password):
            otp = generate_otp()
            cur.execute("UPDATE users SET otp_code = %s, otp_expiry = %s WHERE id = %s", (otp, datetime.now() + timedelta(minutes=10), session['user_id']))
            conn.commit()
            
            send_email(user[1], "Change Password OTP - SecureVote", f"Your OTP to change password is: {otp}")
            session['password_change_verified'] = False
            return redirect(url_for('verify_password_change_otp'))
        else:
            flash('Incorrect current password.', 'error')
            return redirect(url_for('profile'))
        
        cur.close()
    finally:
        release_db_connection(conn)

@app.route('/verify-password-change-otp', methods=['GET', 'POST'])
def verify_password_change_otp():
    if 'user_id' not in session: return redirect(url_for('login'))
    
    if request.method == 'POST':
        otp = request.form['otp']
        
        conn = get_db_connection()
        try:
            cur = conn.cursor()
            cur.execute("SELECT otp_code, otp_expiry FROM users WHERE id = %s", (session['user_id'],))
            user = cur.fetchone()
            
            if user and user[0] == otp and user[1] > datetime.now():
                session['password_change_verified'] = True
                return redirect(url_for('change_password_new'))
            else:
                flash('Invalid or Expired OTP', 'error')
                
            cur.close()
        finally:
            release_db_connection(conn)
        
    return render_template('verify_otp.html', title="Verify Identity")

@app.route('/change-password-new', methods=['GET', 'POST'])
def change_password_new():
    if 'user_id' not in session or not session.get('password_change_verified'):
        return redirect(url_for('profile'))
        
    if request.method == 'POST':
        new_password = request.form['password']
        hashed_pw = bcrypt.generate_password_hash(new_password).decode('utf-8')
        
        conn = get_db_connection()
        try:
            cur = conn.cursor()
            cur.execute("UPDATE users SET password_hash = %s, otp_code = NULL WHERE id = %s", (hashed_pw, session['user_id']))
            conn.commit()
            cur.close()
        finally:
            release_db_connection(conn)
        
        session.pop('password_change_verified', None)
        flash('Password changed successfully!', 'success')
        return redirect(url_for('profile'))
        
    return render_template('verify_otp.html', title="Set New Password", show_password=True)

@app.route('/results')
def user_results():
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        
        # Get all elections (even ended ones)
        cur.execute("SELECT id, title, status FROM elections WHERE status != 'hidden' ORDER BY created_at DESC")
        elections_rows = cur.fetchall()
        
        results = []
        for e_row in elections_rows:
            e_id = e_row[0]
            e_title = e_row[1]
            e_status = e_row[2]
            
            # Get candidates and votes
            cur.execute("SELECT name, party, vote_count FROM candidates WHERE election_id = %s ORDER BY vote_count DESC", (e_id,))
            cand_rows = cur.fetchall()
            
            total_votes = sum([c[2] for c in cand_rows])
            candidates = []
            for c in cand_rows:
                percentage = 0
                if total_votes > 0:
                    percentage = round((c[2] / total_votes) * 100, 1)
                candidates.append({
                    'name': c[0],
                    'party': c[1],
                    'votes': c[2],
                    'percentage': percentage
                })
                
            results.append({
                'title': e_title,
                'status': e_status,
                'total_votes': total_votes,
                'candidates': candidates
            })
            
        cur.close()
        return render_template('user_results.html', results=results)
    finally:
        release_db_connection(conn)

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['identifier']
        # Verify email exists
        conn = get_db_connection()
        try:
            cur = conn.cursor()
            cur.execute("SELECT id FROM users WHERE email = %s", (email,))
            user = cur.fetchone()
            
            if user:
                otp = generate_otp()
                cur.execute("UPDATE users SET otp_code = %s, otp_expiry = %s WHERE id = %s", (otp, datetime.now() + timedelta(minutes=10), user[0]))
                conn.commit()
                send_email(email, "Reset Password - SecureVote", f"Your Password Reset OTP is: {otp}")
                session['reset_email'] = email
                return redirect(url_for('reset_password_verify'))
            else:
                flash('Email not found', 'error')
            cur.close()
        finally:
            release_db_connection(conn)
            
    return render_template('forgot_password.html')

@app.route('/reset-password-verify', methods=['GET', 'POST'])
def reset_password_verify():
    if request.method == 'POST':
        otp = request.form['otp']
        new_password = request.form['password']
        email = session.get('reset_email')
        
        conn = get_db_connection()
        try:
            cur = conn.cursor()
            cur.execute("SELECT otp_code, otp_expiry FROM users WHERE email = %s", (email,))
            user = cur.fetchone()
            
            if user and user[0] == otp and user[1] > datetime.now():
                hashed_pw = bcrypt.generate_password_hash(new_password).decode('utf-8')
                cur.execute("UPDATE users SET password_hash = %s, otp_code = NULL WHERE email = %s", (hashed_pw, email))
                conn.commit()
                flash('Password reset successfully. Please login.', 'success')
                return redirect(url_for('login'))
            else:
                flash('Invalid OTP', 'error')
            cur.close()
        finally:
            release_db_connection(conn)
            
    return render_template('verify_otp.html', title="Reset Password", show_password=True)

if __name__ == '__main__':
    app.run(debug=True, port=5001)
