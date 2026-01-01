from flask import Flask, jsonify, request, send_from_directory
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
import os
import datetime
import secrets

# --- 1. SAFE IMPORTS (Prevents Server Crash) ---
try:
    import yt_dlp
except ImportError:
    yt_dlp = None
    print("WARNING: yt_dlp not found. Downloader will not work.")

# --- 2. SETUP & CONFIG ---
app = Flask(__name__)

# Load Environment Variables
load_dotenv()
MONGO_URI = os.environ.get("MONGODB_URI")
SECRET_KEY = os.environ.get("SECRET_KEY", "dev_secret_key")

# Database Connection
try:
    client = MongoClient(MONGO_URI)
    db = client["all_in_one_app"]
    users_collection = db["users"]
    events_collection = db["events"]
    # Test connection
    client.admin.command('ping')
    print("✅ Connected to MongoDB")
except Exception as e:
    print(f"❌ DB Connection Failed: {e}")

# --- 3. STATIC FILE ROUTES (Serves HTML/CSS) ---


@app.route('/')
def home():
    return send_from_directory('../', 'index.html')


@app.route('/<path:filename>')
def serve_static(filename):
    return send_from_directory('../', filename)

# --- 4. AUTH ROUTES (Login/Signup) ---


@app.route('/api/signup', methods=['POST'])
def signup():
    data = request.json
    if users_collection.find_one({"username": data['username']}):
        return jsonify({"error": "Username taken"}), 400
    if users_collection.find_one({"email": data['email']}):
        return jsonify({"error": "Email already registered"}), 400

    new_user = {
        "name": data['name'],
        "username": data['username'],
        "email": data['email'],
        "password": generate_password_hash(data['password']),
        "is_verified": False,  # Set to True if you want instant verification
        "role": "user",
        "created_at": datetime.datetime.utcnow()
    }
    users_collection.insert_one(new_user)
    return jsonify({"message": "Account created!"}), 201


@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    user = users_collection.find_one({"username": data['username']})

    if user and check_password_hash(user['password'], data['password']):
        return jsonify({
            "message": "Login successful",
            "user": {
                "name": user['name'],
                "username": user['username'],
                "email": user['email'],
                "is_admin": user.get('role') == 'admin'
            }
        }), 200
    return jsonify({"error": "Invalid credentials"}), 401

# --- 5. PROFILE & ADMIN ROUTES ---


@app.route('/api/update-profile', methods=['POST'])
def update_profile():
    data = request.json
    user = users_collection.find_one({"username": data.get('old_username')})
    if not user:
        return jsonify({"error": "User not found"}), 404

    if not check_password_hash(user['password'], data.get('current_password')):
        return jsonify({"error": "Incorrect password"}), 401

    updates = {}
    if data.get('name'):
        updates['name'] = data['name']
    if data.get('username') and data['username'] != user['username']:
        if users_collection.find_one({"username": data['username']}):
            return jsonify({"error": "Username taken"}), 400
        updates['username'] = data['username']
    if data.get('new_password'):
        updates['password'] = generate_password_hash(data['new_password'])

    if updates:
        users_collection.update_one({"_id": user["_id"]}, {"$set": updates})
        updated = users_collection.find_one({"_id": user["_id"]})
        return jsonify({
            "message": "Updated!",
            "user": {
                "name": updated['name'],
                "username": updated['username'],
                "email": updated['email'],
                "is_admin": updated.get('role') == 'admin'
            }
        }), 200
    return jsonify({"message": "No changes"}), 200


@app.route('/api/admin/data', methods=['POST'])
def admin_data():
    username = request.json.get('username')
    admin = users_collection.find_one({"username": username})
    if not admin or admin.get('role') != 'admin':
        return jsonify({"error": "Unauthorized"}), 403

    users = list(users_collection.find({}, {"_id": 0, "password": 0}))
    stats = {
        "total_users": len(users),
        "total_visits": 1000,  # Placeholder
        "db_latency_ms": 25
    }
    return jsonify({"users": users, "stats": stats}), 200


@app.route('/api/admin/promote', methods=['POST'])
def promote_user():
    data = request.json
    requester = users_collection.find_one(
        {"username": data.get('admin_username')})
    if not requester or requester.get('role') != 'admin':
        return jsonify({"error": "Unauthorized"}), 403

    users_collection.update_one(
        {"username": data.get('target_username')},
        {"$set": {"role": "admin"}}
    )
    return jsonify({"message": "User promoted"}), 200

# --- 6. CALENDAR ROUTES ---


@app.route('/api/calendar/events', methods=['POST'])
def get_events():
    # Return all events (public + private)
    # Ideally filter by user, but for now returning all for simplicity
    events = list(events_collection.find({}, {"_id": 0}))
    return jsonify(events), 200


@app.route('/api/calendar/add', methods=['POST'])
def add_event():
    data = request.json
    event = {
        "id": secrets.token_hex(4),
        "username": data['username'],
        "date": data['date'],
        "title": data['title'],
        "description": data.get('description', '')
    }
    events_collection.insert_one(event)
    return jsonify({"message": "Event added"}), 201


@app.route('/api/calendar/delete', methods=['POST'])
def delete_event():
    data = request.json
    # Allow deletion if user owns event OR user is admin
    user = users_collection.find_one({"username": data['username']})
    is_admin = user and user.get('role') == 'admin'

    query = {"id": data['id']}
    if not is_admin:
        query["username"] = data['username']  # Restrict to owner

    result = events_collection.delete_one(query)
    if result.deleted_count > 0:
        return jsonify({"message": "Deleted"}), 200
    return jsonify({"error": "Permission denied or not found"}), 403

# downloader


@app.route('/api/downloader/info', methods=['POST'])
def get_video_info():
    if not yt_dlp:
        return jsonify({"error": "Server Error: yt_dlp library missing."}), 500

    data = request.json
    url = data.get('url')
    if not url:
        return jsonify({"error": "No URL provided"}), 400

    print(f"📥 Processing: {url}")

    # 1. PATH TO COOKIES
    # We look for cookies.txt in the main folder (where index.html is)
    cookies_path = os.path.join(os.getcwd(), 'cookies.txt')

    # 2. ADVANCED CONFIG TO BYPASS YOUTUBE
    ydl_opts = {
        'format': 'best[ext=mp4]/best',
        'noplaylist': True,
        'quiet': True,
        'no_warnings': True,
        'geo_bypass': True,
        'extract_flat': False,

        # SPOOFING (Look like a real Chrome Browser on Windows)
        'http_headers': {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-us,en;q=0.5',
            'Sec-Fetch-Mode': 'navigate',
        }
    }

    # 3. USE COOKIES IF FILE EXISTS
    if os.path.exists(cookies_path):
        print("🍪 Found cookies.txt! Using it to bypass bot check.")
        ydl_opts['cookiefile'] = cookies_path
    else:
        print("⚠️ No cookies.txt found. YouTube might block this.")

    if data.get('type') == 'audio':
        ydl_opts['format'] = 'bestaudio/best'

    try:
        with yt_dlp.YoutubeDL(ydl_opts) as ydl:
            info = ydl.extract_info(url, download=False)
            if 'entries' in info:
                info = info['entries'][0]

            return jsonify({
                "title": info.get('title', 'Unknown Title'),
                "thumbnail": info.get('thumbnail', ''),
                "duration": info.get('duration_string', ''),
                "download_url": info.get('url'),
                "site": info.get('extractor_key', 'Unknown'),
                "is_audio": data.get('type') == 'audio'
            }), 200

    except Exception as e:
        error_msg = str(e)
        print(f"⚠️ Downloader Error: {error_msg}")

        if "Sign in" in error_msg or "403" in error_msg:
            return jsonify({"error": "YouTube blocked the server. Please add cookies.txt to fix this!"}), 500
        else:
            return jsonify({"error": f"Failed: {error_msg}"}), 500


# --- 8. RUN ---
if __name__ == '__main__':
    app.run(debug=True)
