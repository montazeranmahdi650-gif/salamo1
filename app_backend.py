from flask import Flask, request, jsonify
from flask_cors import CORS
import json
import re
from threading import Lock
import requests
import hashlib
import os
import sys
import time
from datetime import datetime, timedelta
from collections import defaultdict

app = Flask(__name__)
# فعال‌سازی CORS برای اجازه دادن به درخواست از افزونه کروم
CORS(app)

FORBIDDEN_HOSTS = ["melliun.org", "nejatngo.org", "dw.com", "hammihanonline.ir"]
keyword_lock = Lock()
image_hash_lock = Lock()

# 🚨 شبیه سازی دیتابیس: این متغیرها پس از هر بار خاموش شدن سرور (Cold Start) ریست می شوند.
CONTENT_HISTORY = {}
CONTENT_HISTORY_LOCK = Lock()

# 🚨 فهرست جدید: فهرست هَش‌های تصاویر ممنوعه (SHA256) که به طور خودکار یاد گرفته شده‌اند.
# در محیط واقعی، اینها باید در یک دیتابیس دائمی ذخیره شوند.
FORBIDDEN_IMAGE_HASHES = set()

# 🚨 سیستم لاگ‌گیری: ذخیره لاگ‌های کاربران بر اساس IP
USER_LOGS = defaultdict(list)
USER_LOGS_LOCK = Lock()
# محدودیت تعداد لاگ‌های هر کاربر
MAX_LOGS_PER_USER = 1000
# مدت زمان نگهداری لاگ‌ها (روز)
LOG_RETENTION_DAYS = 30

# تنظیمات هدر برای جلوگیری از مسدود شدن توسط سرورهای عکس
REQUEST_HEADERS = {
    'User-Agent': 'Mozilla/5.0 (compatible; Content-Guard-Bot/1.0;)'
}
# محدودیت زمانی برای دانلود هر عکس
DOWNLOAD_TIMEOUT = 3

# تعریف مجموعه کلمات ممنوعه (کلمات اولیه) - استفاده از الگوهای قوی Regex برای تشخیص مرز کلمه
SENSITIVE_KEYWORDS = {
    r'(?:\s|^)شورش', r'(?:\s|^)تحریم', r'(?:\s|^)بحران', r'(?:\s|^)سقوط',
    r'(?:\s|^)ضدنظام', r'(?:\s|^)اعتراض', r'(?:\s|^)برانداز',
    r'(?:\s|^)قیام', r'(?:\s|^)آزادی', r'(?:\s|^)رهبر', r'(?:\s|^)خامنه‌ای',
    r'(?:\s|^)انقلاب', r'(?:\s|^)سپاه', r'(?:\s|^)بسیج', r'(?:\s|^)گشت\sارشاد',
    r'(?:\s|^)سرکوب', r'(?:\s|^)فتنه', r'(?:\s|^)رژیم', r'(?:\s|^)جمهوری',
    r'(?:\s|^)اعدام', r'(?:\s|^)نظام', r'(?:\s|^)ولایت\sفقیه', r'(?:\s|^)ملا',
    r'(?:\s|^)قوه\sقضاییه', r'(?:\s|^)زندانی\sسیاسی', r'(?:\s|^)دیکتاتور'
}


def get_client_ip():
    """دریافت IP کاربر از هدرهای درخواست"""
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0]
    elif request.headers.get('X-Real-IP'):
        return request.headers.get('X-Real-IP')
    return request.remote_addr


def log_user_activity(ip_address, activity_type, details):
    """ذخیره فعالیت کاربر در سیستم لاگ"""
    with USER_LOGS_LOCK:
        # پاک کردن لاگ‌های قدیمی
        current_time = time.time()
        if ip_address in USER_LOGS:
            USER_LOGS[ip_address] = [
                log for log in USER_LOGS[ip_address]
                if current_time - log['timestamp'] <= LOG_RETENTION_DAYS * 86400
            ]

        # ایجاد لاگ جدید
        log_entry = {
            'timestamp': current_time,
            'datetime': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'activity_type': activity_type,
            'details': details,
            'user_agent': request.headers.get('User-Agent', 'Unknown'),
            'url': request.url if request.method == 'GET' else None
        }

        # اضافه کردن لاگ جدید
        USER_LOGS[ip_address].append(log_entry)

        # محدود کردن تعداد لاگ‌ها
        if len(USER_LOGS[ip_address]) > MAX_LOGS_PER_USER:
            USER_LOGS[ip_address] = USER_LOGS[ip_address][-MAX_LOGS_PER_USER:]

        return log_entry


def cleanup_old_logs():
    """پاک‌سازی لاگ‌های قدیمی"""
    with USER_LOGS_LOCK:
        current_time = time.time()
        cutoff_time = current_time - (LOG_RETENTION_DAYS * 86400)

        for ip in list(USER_LOGS.keys()):
            USER_LOGS[ip] = [
                log for log in USER_LOGS[ip]
                if log['timestamp'] > cutoff_time
            ]
            if not USER_LOGS[ip]:
                del USER_LOGS[ip]


def get_image_hash(url):
    """
    تلاش برای دانلود تصویر و محاسبه هش SHA256 آن.
    اگر دانلود موفقیت‌آمیز نبود، None برمی‌گرداند.
    """
    try:
        # فیلتر کردن URLهای غیرمعتبر
        if not url.startswith('http'):
            return None

            # دانلود محتوای تصویر با استریم و محدودیت زمانی
        response = requests.get(url, headers=REQUEST_HEADERS, timeout=DOWNLOAD_TIMEOUT, stream=True)
        response.raise_for_status()  # خطاهای HTTP را پرتاب می کند

        # فقط تصاویر را پردازش کن (برای کاهش بار)
        content_type = response.headers.get('Content-Type', '')
        if 'image' not in content_type:
            return None

        # محاسبه هش SHA256
        sha256_hash = hashlib.sha256()
        for chunk in response.iter_content(chunk_size=4096):
            sha256_hash.update(chunk)

        return sha256_hash.hexdigest()

    except requests.exceptions.RequestException:
        # خطای اتصال، Timeout یا سایر مشکلات دانلود
        return None
    except Exception:
        # خطاهای ناشناخته
        return None


def normalize_text(text):
    """
    متن را برای بهبود دقت فیلترینگ عادی‌سازی (نرمالایز) می‌کند (مثلاً تبدیل ی عربی به فارسی).
    """
    text = str(text).lower()
    text = text.replace('ي', 'ی').replace('ك', 'ک')
    # حذف علائم نگارشی برای دقت بیشتر در Regex
    text = re.sub(r'[^\w\s]', '', text)
    text = re.sub(r'\s+', ' ', text).strip()
    return text


def check_keyword_robust(article_text):
    """
    جستجوی قوی کلمات کلیدی با استفاده از Regex پس از نرمال‌سازی.
    """
    normalized_text = normalize_text(article_text)

    with keyword_lock:
        for pattern in SENSITIVE_KEYWORDS:
            if re.search(pattern, normalized_text):
                return True
    return False


def simulate_learning(content_data):
    """
    شبیه سازی مکانیسم یادگیری خودکار: اگر محتوای جدیدی از منبع ممنوعه پیدا شود،
    کلمات و هَش‌های جدید آن را به لیست فیلترهای عمومی اضافه می کند.
    """
    article_text = content_data.get('text', '')
    image_sources = content_data.get('imageSources', [])

    # 1. تشخیص محتوای جدید با استفاده از هش (برای شبیه سازی دیتابیس)
    normalized_text = normalize_text(article_text)
    # هش کردن 500 کاراکتر اول برای کاهش بار
    content_hash = hashlib.md5(normalized_text[:500].encode('utf-8')).hexdigest()

    with CONTENT_HISTORY_LOCK:
        if content_hash in CONTENT_HISTORY:
            # محتوا تکراری است، یادگیری انجام نمی‌شود.
            return 0, 0
        CONTENT_HISTORY[content_hash] = True

    # --- یادگیری کلمات کلیدی ---
    # یافتن کلمات فارسی/عربی با طول 4 کاراکتر یا بیشتر
    all_words = set(re.findall(r'[\u0600-\u06FF\u0750-\u077F]{4,}', normalized_text))
    newly_added_keywords = 0
    with keyword_lock:
        for word in all_words:
            safe_term = r'(?:\s|^)' + re.escape(word)  # اطمینان از مرز کلمه
            if safe_term not in SENSITIVE_KEYWORDS:
                SENSITIVE_KEYWORDS.add(safe_term)
                newly_added_keywords += 1

    # --- یادگیری هَش‌های تصاویر ---
    newly_added_hashes = 0
    with image_hash_lock:
        for src in image_sources:
            # فقط URLهایی را یاد بگیر که از یکی از FORBIDDEN_HOSTS می آیند
            if any(host in src for host in FORBIDDEN_HOSTS):  # 🚨 تغییر این خط
                img_hash = get_image_hash(src)
                if img_hash and img_hash not in FORBIDDEN_IMAGE_HASHES:
                    FORBIDDEN_IMAGE_HASHES.add(img_hash)
                    newly_added_hashes += 1

    return newly_added_keywords, newly_added_hashes


def check_nested_api_logic(content_data, ip_address=None):
    """
    اجرای منطق API تودرتوی چندلایه با منطق فیلترینگ تقویت شده و یادگیری خودکار.
    """
    article_text = content_data.get('text', '')
    links_to_check = content_data.get('links', [])
    image_sources = content_data.get('imageSources', [])

    # 0. بررسی اولیه برای اجرای یادگیری
    has_forbidden_source = any(any(host in src for host in FORBIDDEN_HOSTS) for src in image_sources) or any(
        any(host in link for host in FORBIDDEN_HOSTS) for link in links_to_check)

    if has_forbidden_source:
        new_k, new_i = simulate_learning(content_data)
        if new_k > 0 or new_i > 0:
            print(f"AUTOMATIC LEARNING: Added {new_k} new keywords and {new_i} new image hashes.")
    # --- پایان مکانیزم یادگیری ---

    # 1. بررسی هَش تصاویر: آیا تصویر فعلی، هَش ممنوعه دارد؟ (قوی‌ترین فیلتر جدید)
    with image_hash_lock:
        for src in image_sources:
            current_hash = get_image_hash(src)
            if current_hash and current_hash in FORBIDDEN_IMAGE_HASHES:
                # ثبت لاگ
                if ip_address:
                    log_user_activity(ip_address, 'FILTER_HARD', {
                        'action': 'FILTER_HARD',
                        'reason': 'HIGH_PRIORITY: Known Forbidden Image Hash Detected',
                        'image_url': src[:100],
                        'content_preview': article_text[:200]
                    })
                return {
                    "action": "FILTER_HARD",
                    "reason": "HIGH_PRIORITY: Known Forbidden Image Hash Detected"
                }

    # 2. بررسی مستقیم منبع ممنوعه (برای تصویر یا لینک) - این یک فیلتر پشتیبان سریع است.
    if any(any(host in src for host in FORBIDDEN_HOSTS) for src in image_sources):
        # ثبت لاگ
        if ip_address:
            log_user_activity(ip_address, 'FILTER_HARD', {
                'action': 'FILTER_HARD',
                'reason': 'HIGH_PRIORITY: Image Source from Forbidden Host Detected (URL Match)',
                'forbidden_hosts': FORBIDDEN_HOSTS,
                'content_preview': article_text[:200]
            })
        return {
            "action": "FILTER_HARD",
            "reason": "HIGH_PRIORITY: Image Source from Forbidden Host Detected (URL Match)"
        }

    # 3. منطق لینک و متن
    has_forbidden_link = any(any(host in link for host in FORBIDDEN_HOSTS) for link in links_to_check)

    if has_forbidden_link:
        if len(article_text) > 100 and check_keyword_robust(article_text):
            # ثبت لاگ
            if ip_address:
                log_user_activity(ip_address, 'FILTER_HARD', {
                    'action': 'FILTER_HARD',
                    'reason': 'Nested Logic: Forbidden Link + Sensitive Topic Match (Robust)',
                    'forbidden_links': [link[:100] for link in links_to_check if
                                        any(host in link for host in FORBIDDEN_HOSTS)],
                    'content_preview': article_text[:200]
                })
            return {
                "action": "FILTER_HARD",
                "reason": "Nested Logic: Forbidden Link + Sensitive Topic Match (Robust)"
            }
        # اگر لینک ممنوعه بود اما موضوع حساس نبود، باز هم سخت مسدود کن (احتیاط بیشتر)
        # ثبت لاگ
        if ip_address:
            log_user_activity(ip_address, 'FILTER_HARD', {
                'action': 'FILTER_HARD',
                'reason': 'HIGH_PRIORITY: Forbidden Link Detected',
                'forbidden_links': [link[:100] for link in links_to_check if
                                    any(host in link for host in FORBIDDEN_HOSTS)]
            })
        return {
            "action": "FILTER_HARD",
            "reason": "HIGH_PRIORITY: Forbidden Link Detected"
        }

    # 4. فیلترینگ سبک‌تر (بررسی فقط متن)
    if check_keyword_robust(article_text):
        # ثبت لاگ
        if ip_address:
            log_user_activity(ip_address, 'FILTER_LIGHT', {
                'action': 'FILTER_LIGHT',
                'reason': 'Generic Sensitive Topic Found (Robust)',
                'content_preview': article_text[:200]
            })
        return {"action": "FILTER_LIGHT", "reason": "Generic Sensitive Topic Found (Robust)"}

    # ثبت لاگ برای محتوای مجاز
    if ip_address:
        log_user_activity(ip_address, 'ALLOW', {
            'action': 'ALLOW',
            'reason': 'Content is clear.',
            'content_preview': article_text[:100]
        })
    return {"action": "ALLOW", "reason": "Content is clear."}


# مسیر اصلی برای بررسی وضعیت سرور
@app.route('/', methods=['GET'])
def home():
    # نمایش تعداد کلمات و تصاویر فیلتر برای تأیید صحت یادگیری
    total_images = 0
    with image_hash_lock:
        total_images = len(FORBIDDEN_IMAGE_HASHES)

    # تعداد لاگ‌های ذخیره شده
    with USER_LOGS_LOCK:
        total_logs = sum(len(logs) for logs in USER_LOGS.values())
        unique_users = len(USER_LOGS)

    return f"""
    <html>
        <head><title>Iran Blocker API</title></head>
        <body>
            <h1>Python Content Filter API is running!</h1>
            <ul>
                <li>Total keywords: {len(SENSITIVE_KEYWORDS)}</li>
                <li>Total forbidden image hashes: {total_images}</li>
                <li>Total users logged: {unique_users}</li>
                <li>Total logs stored: {total_logs}</li>
            </ul>
            <p>API Endpoints:</p>
            <ul>
                <li><a href="/analyze_content_api">/analyze_content_api</a> (POST)</li>
                <li><a href="/get_user_logs">/get_user_logs</a> (GET)</li>
                <li><a href="/get_system_stats">/get_system_stats</a> (GET)</li>
            </ul>
        </body>
    </html>
    """, 200


@app.route('/analyze_content_api', methods=['POST'])
def analyze_content_api():
    """
    نقطه پایانی که افزونه کروم آن را فراخوانی می‌کند (نیاز به توکن ندارد).
    """
    ip_address = get_client_ip()
    data = request.get_json()

    if not data or 'content' not in data:
        # ثبت لاگ خطا
        log_user_activity(ip_address, 'ERROR', {
            'error': 'No content provided',
            'request_data': str(data)[:500]
        })
        return jsonify({"error": "No content provided."}), 400

    result = check_nested_api_logic(data['content'], ip_address)

    # ثبت نتیجه تحلیل
    log_user_activity(ip_address, 'ANALYSIS_RESULT', {
        'result': result,
        'content_length': len(data['content'].get('text', '')) if data.get('content') else 0,
        'links_count': len(data['content'].get('links', [])) if data.get('content') else 0,
        'images_count': len(data['content'].get('imageSources', [])) if data.get('content') else 0
    })

    return jsonify(result)


@app.route('/get_user_logs', methods=['GET'])
def get_user_logs():
    """
    دریافت لاگ‌های کاربر بر اساس IP
    """
    ip_address = get_client_ip()
    limit = request.args.get('limit', default=50, type=int)
    activity_type = request.args.get('type', default=None, type=str)

    with USER_LOGS_LOCK:
        user_logs = USER_LOGS.get(ip_address, [])

        # فیلتر بر اساس نوع فعالیت
        if activity_type:
            user_logs = [log for log in user_logs if log['activity_type'] == activity_type]

        # مرتب سازی بر اساس زمان (جدیدترین اول)
        user_logs.sort(key=lambda x: x['timestamp'], reverse=True)

        # محدود کردن تعداد
        user_logs = user_logs[:limit]

    return jsonify({
        'user_ip': ip_address,
        'total_logs': len(USER_LOGS.get(ip_address, [])),
        'filtered_logs': len(user_logs),
        'logs': user_logs
    })


@app.route('/clear_user_logs', methods=['POST'])
def clear_user_logs():
    """
    پاک‌سازی لاگ‌های کاربر
    """
    ip_address = get_client_ip()

    with USER_LOGS_LOCK:
        if ip_address in USER_LOGS:
            deleted_count = len(USER_LOGS[ip_address])
            del USER_LOGS[ip_address]
            return jsonify({
                'success': True,
                'message': f'Deleted {deleted_count} logs for user {ip_address}',
                'deleted_count': deleted_count
            })
        else:
            return jsonify({
                'success': False,
                'message': f'No logs found for user {ip_address}'
            }), 404


@app.route('/get_system_stats', methods=['GET'])
def get_system_stats():
    """
    دریافت آمار سیستم
    """
    with USER_LOGS_LOCK:
        total_users = len(USER_LOGS)
        total_logs = sum(len(logs) for logs in USER_LOGS.values())

        # آمار فعالیت‌ها
        activity_stats = {}
        for logs in USER_LOGS.values():
            for log in logs:
                activity_type = log['activity_type']
                activity_stats[activity_type] = activity_stats.get(activity_type, 0) + 1

    with image_hash_lock:
        total_image_hashes = len(FORBIDDEN_IMAGE_HASHES)

    with keyword_lock:
        total_keywords = len(SENSITIVE_KEYWORDS)

    return jsonify({
        'system_stats': {
            'total_users': total_users,
            'total_logs': total_logs,
            'total_image_hashes': total_image_hashes,
            'total_keywords': total_keywords,
            'forbidden_hosts': FORBIDDEN_HOSTS,
            'log_retention_days': LOG_RETENTION_DAYS,
            'max_logs_per_user': MAX_LOGS_PER_USER
        },
        'activity_stats': activity_stats,
        'timestamp': time.time(),
        'datetime': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    })


# اجرای برنامه
if __name__ == '__main__':
    # پاک‌سازی لاگ‌های قدیمی در شروع
    cleanup_old_logs()

    # این خط فقط برای اجرای محلی است.
    # در محیط ابری (مثل Render) اجرای Gunicorn از $PORT استفاده می‌کند.
    # تنظیم host='0.0.0.0' برای اجرای محلی روی تمام اینترفیس‌ها
    app.run(debug=True, host='0.0.0.0', port=os.environ.get('PORT', 5050))
