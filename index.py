from flask import Flask, jsonify, request, send_from_directory
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import secrets
import datetime
import yt_dlp

# --- SETUP ---
current_dir = os.path.dirname(os.path.abspath(__file__))
env_path = os.path.join(current_dir, '..', '.env')
load_dotenv(dotenv_path=env_path)

app = Flask(__name__)

MONGO_URI = os.environ.get("MONGODB_URI")
EMAIL_USER = os.environ.get("EMAIL_USER")
EMAIL_PASS = os.environ.get("EMAIL_PASS")
BASE_URL = os.environ.get("BASE_URL", "http://localhost:5000")

try:
    client = MongoClient(MONGO_URI)
    db = client["all_in_one_app"]
    users_collection = db["users"]
    stats_collection = db["stats"]
    print("✅ Connected to MongoDB successfully!")
except Exception as e:
    print(f"❌ Database Error: {e}")

# --- HELPERS ---


def track_visit():
    try:
        today = datetime.datetime.now().strftime("%Y-%m-%d")
        stats_collection.update_one(
            {"date": today},
            {"$inc": {"visits": 1}},
            upsert=True
        )
    except Exception as e:
        print(f"Tracking Error: {e}")


def send_verification_email(to_email, token):
    if not EMAIL_USER or not EMAIL_PASS:
        return False
    verification_link = f"{BASE_URL}/api/verify?token={token}"
    msg = MIMEMultipart()
    msg['From'] = EMAIL_USER
    msg['To'] = to_email
    msg['Subject'] = "Verify Account"
    body = f'<a href="{verification_link}">Verify Account</a>'
    msg.attach(MIMEText(body, 'html'))
    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(EMAIL_USER, EMAIL_PASS)
        server.sendmail(EMAIL_USER, to_email, msg.as_string())
        server.quit()
        return True
    except Exception as e:
        print(f"Email Error: {e}")
        return False

# --- ROUTES ---


@app.route('/api/health')
def health_check():
    return jsonify({"status": "active"}), 200

# 1. AUTHENTICATION (Signup/Login/Verify)


@app.route('/api/signup', methods=['POST'])
def signup():
    data = request.json
    email = data.get('email')
    username = data.get('username')
    password = data.get('password')
    name = data.get('name')

    if not email or not username or not password:
        return jsonify({"error": "Missing fields"}), 400

    if users_collection.find_one({"email": email}):
        return jsonify({"error": "Email already registered"}), 400
    if users_collection.find_one({"username": username}):
        return jsonify({"error": "Username taken"}), 400

    hashed_password = generate_password_hash(password)
    verification_token = secrets.token_hex(16)

    new_user = {
        "name": name,
        "username": username,
        "email": email,
        "password": hashed_password,
        "is_verified": False,
        "verification_token": verification_token
    }

    users_collection.insert_one(new_user)
    send_verification_email(email, verification_token)
    return jsonify({"message": "Account created! Check email."}), 201


@app.route('/api/verify', methods=['GET'])
def verify_account():
    token = request.args.get('token')
    user = users_collection.find_one({"verification_token": token})
    if not user:
        return "Invalid token", 400
    users_collection.update_one({"_id": user["_id"]}, {
                                "$set": {"is_verified": True}, "$unset": {"verification_token": ""}})
    return "<h1>Verified! You can login now.</h1>"


@app.route('/api/login', methods=['POST'])
def login():
    track_visit()
    data = request.json
    login_input = data.get('email_or_username')
    password = data.get('password')

    user = users_collection.find_one(
        {"$or": [{"email": login_input}, {"username": login_input}]})
    if not user:
        return jsonify({"error": "User not found"}), 404
    if not check_password_hash(user['password'], password):
        return jsonify({"error": "Invalid password"}), 401
    if not user.get('is_verified'):
        return jsonify({"error": "Verify email first"}), 403

    return jsonify({
        "message": "Login successful",
        "username": user['username'],
        "name": user['name'],
        "is_admin": user.get('role') == 'admin'
    }), 200

# 2. PASSWORD RESET


@app.route('/api/forgot-password', methods=['POST'])
def forgot_password():
    data = request.json
    email = data.get('email')
    user = users_collection.find_one({"email": email})
    if not user:
        return jsonify({"message": "Sent"}), 200  # Fake success for security

    reset_token = secrets.token_hex(16)
    users_collection.update_one(
        {"email": email}, {"$set": {"reset_token": reset_token}})

    reset_link = f"{BASE_URL}/reset_password.html?token={reset_token}"
    # (Simplified email sending for brevity - re-use your helper logic in real app)
    # ... Send email code here ...
    return jsonify({"message": "Sent"}), 200


@app.route('/api/reset-password', methods=['POST'])
def reset_password():
    data = request.json
    token = data.get('token')
    new_password = data.get('password')
    user = users_collection.find_one({"reset_token": token})
    if not user:
        return jsonify({"error": "Invalid token"}), 400

    hashed = generate_password_hash(new_password)
    users_collection.update_one({"_id": user["_id"]}, {
                                "$set": {"password": hashed}, "$unset": {"reset_token": ""}})
    return jsonify({"message": "Password updated"}), 200

# 3. ADMIN DATA


@app.route('/api/admin/data', methods=['POST'])
def get_admin_data():
    data = request.json
    user = users_collection.find_one({"username": data.get('username')})
    if not user or user.get('role') != 'admin':
        return jsonify({"error": "Unauthorized"}), 403

    users_list = list(users_collection.find(
        {}, {"password": 0, "verification_token": 0}))
    for u in users_list:
        u['_id'] = str(u['_id'])

    total_visits = list(stats_collection.aggregate(
        [{"$group": {"_id": None, "total": {"$sum": "$visits"}}}]))
    visits = total_visits[0]['total'] if total_visits else 0

    start = datetime.datetime.now()
    client.admin.command('ping')
    latency = (datetime.datetime.now() - start).total_seconds() * 1000

    return jsonify({"users": users_list, "stats": {"total_users": len(users_list), "total_visits": visits, "db_latency_ms": round(latency, 2)}}), 200

# 4. CALENDAR (Public Admin Events)


@app.route('/api/calendar/events', methods=['POST'])
def get_events():
    data = request.json
    query = {"$or": [{"username": data.get('username')}, {
        "username": "admin"}]}
    events = list(db["events"].find(query, {"_id": 0}))
    return jsonify(events), 200


@app.route('/api/calendar/add', methods=['POST'])
def add_event():
    data = request.json
    event = {
        "username": data.get('username'),
        "date": data.get('date'),
        "title": data.get('title'),
        "description": data.get('description', ''),
        "id": secrets.token_hex(4)
    }
    db["events"].insert_one(event)
    return jsonify({"message": "Added"}), 201


@app.route('/api/calendar/delete', methods=['POST'])
def delete_event():
    data = request.json
    event = db["events"].find_one({"id": data.get('id')})
    if not event:
        return jsonify({"error": "Not found"}), 404

    if data.get('username') == 'admin' or event['username'] == data.get('username'):
        db["events"].delete_one({"id": data.get('id')})
        return jsonify({"message": "Deleted"}), 200
    return jsonify({"error": "Unauthorized"}), 403

# --- UPDATED DOWNLOADER ROUTE FOR VERCEL ---


@app.route('/api/downloader/info', methods=['POST'])
def get_video_info():
    data = request.json
    url = data.get('url')
    if not url:
        return jsonify({"error": "No URL provided"}), 400

    # VERCEL CONFIGURATION
    # 1. 'format': 'best' forces a single file (no FFmpeg needed)
    # 2. 'noplaylist': True prevents downloading huge lists
    # 3. 'cookiefile': None (Vercel can't use local cookie files easily)

    ydl_opts = {
        'noplaylist': True,
        'quiet': True,
        'default_search': 'ytsearch',
        'no_warnings': True,
        'geo_bypass': True,
    }

    if data.get('type') == 'audio':
        # Get best audio-only file (m4a/webm usually)
        ydl_opts['format'] = 'bestaudio/best'
    else:
        # CRITICAL FIX: Request 'best' (single file) instead of 'bestvideo+bestaudio'
        # This prevents yt-dlp from trying to use FFmpeg to merge files
        ydl_opts['format'] = 'best[ext=mp4]/best'

    try:
        # Handle Spotify Links (Basic Search)
        if "spotify.com" in url:
            with yt_dlp.YoutubeDL({'quiet': True}) as ydl_meta:
                try:
                    # Spotify downloading is hard; we search the song name on YT instead
                    meta = ydl_meta.extract_info(url, download=False)
                    search_query = f"{meta.get('artist', '')} {meta.get('title', '')} audio"
                    url = search_query
                except:
                    return jsonify({"error": "Spotify link failed. Try typing the song name directly."}), 400

        with yt_dlp.YoutubeDL(ydl_opts) as ydl:
            # Extract info without downloading (download=False)
            info = ydl.extract_info(url, download=False)

            # If it was a search, take the first result
            if 'entries' in info:
                info = info['entries'][0]

            # Get the direct download link
            download_url = info.get('url')

            # If no URL found, fail gracefully
            if not download_url:
                return jsonify({"error": "Could not fetch download link. (IP Blocked?)"}), 403

            return jsonify({
                "title": info.get('title', 'Unknown Title'),
                "thumbnail": info.get('thumbnail', ''),
                "duration": info.get('duration_string', '0:00'),
                "download_url": download_url,
                "site": info.get('extractor_key', 'Unknown'),
                "is_audio": data.get('type') == 'audio'
            }), 200

    except Exception as e:
        print(f"Downloader Error: {e}")
        # DEBUG MODE: Send the actual error string to the frontend
        return jsonify({"error": str(e)}), 500


# --- PROFILE UPDATE ROUTE ---
@app.route('/api/update-profile', methods=['POST'])
def update_profile():
    data = request.json
    old_username = data.get('old_username')  # To find the user
    current_password = data.get('current_password')

    new_name = data.get('name')
    new_username = data.get('username')
    new_password = data.get('new_password')

    # 1. Find User
    user = users_collection.find_one({"username": old_username})
    if not user:
        return jsonify({"error": "User not found"}), 404

    # 2. Security Check: Verify Current Password
    if not check_password_hash(user['password'], current_password):
        return jsonify({"error": "Incorrect current password"}), 401

    updates = {}

    # 3. Update Name
    if new_name:
        updates['name'] = new_name

    # 4. Update Username (Check uniqueness)
    if new_username and new_username != old_username:
        if users_collection.find_one({"username": new_username}):
            return jsonify({"error": "Username already taken"}), 400
        updates['username'] = new_username

    # 5. Update Password (Hash it)
    if new_password:
        updates['password'] = generate_password_hash(new_password)

    # 6. Save to DB
    if updates:
        users_collection.update_one({"_id": user["_id"]}, {"$set": updates})

        # Return updated user info so frontend can update LocalStorage
        updated_user = users_collection.find_one({"_id": user["_id"]})
        return jsonify({
            "message": "Profile updated successfully!",
            "user": {
                "name": updated_user['name'],
                "username": updated_user['username'],
                "email": updated_user['email'],
                "is_admin": updated_user.get('role') == 'admin'
            }
        }), 200

    return jsonify({"message": "No changes made."}), 200


if __name__ == '__main__':
    app.run(debug=True, port=5000)
