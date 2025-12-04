from flask import Flask, request, jsonify
from flask_cors import CORS
import json
import re
from threading import Lock
import requests
import hashlib
import os
import sys

app = Flask(__name__)
# فعال‌سازی CORS برای اجازه دادن به درخواست از افزونه کروم
CORS(app)

FORBIDDEN_HOST = "melliun.org"
keyword_lock = Lock()
image_hash_lock = Lock()

# 🚨 شبیه سازی دیتابیس: این متغیرها پس از هر بار خاموش شدن سرور (Cold Start) ریست می شوند.
CONTENT_HISTORY = {}
CONTENT_HISTORY_LOCK = Lock()

# 🚨 فهرست جدید: فهرست هَش‌های تصاویر ممنوعه (SHA256) که به طور خودکار یاد گرفته شده‌اند.
# در محیط واقعی، اینها باید در یک دیتابیس دائمی ذخیره شوند.
FORBIDDEN_IMAGE_HASHES = set()

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
            # فقط URLهایی را یاد بگیر که از FORBIDDEN_HOST می آیند
            if FORBIDDEN_HOST in src:
                img_hash = get_image_hash(src)
                if img_hash and img_hash not in FORBIDDEN_IMAGE_HASHES:
                    FORBIDDEN_IMAGE_HASHES.add(img_hash)
                    newly_added_hashes += 1

    return newly_added_keywords, newly_added_hashes


def check_nested_api_logic(content_data):
    """
    اجرای منطق API تودرتوی چندلایه با منطق فیلترینگ تقویت شده و یادگیری خودکار.
    """
    article_text = content_data.get('text', '')
    links_to_check = content_data.get('links', [])
    image_sources = content_data.get('imageSources', [])

    # 0. بررسی اولیه برای اجرای یادگیری
    has_forbidden_source = any(FORBIDDEN_HOST in src for src in image_sources) or any(
        FORBIDDEN_HOST in link for link in links_to_check)

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
                return {
                    "action": "FILTER_HARD",
                    "reason": "HIGH_PRIORITY: Known Forbidden Image Hash Detected"
                }

    # 2. بررسی مستقیم منبع ممنوعه (برای تصویر یا لینک) - این یک فیلتر پشتیبان سریع است.
    if any(FORBIDDEN_HOST in src for src in image_sources):
        return {
            "action": "FILTER_HARD",
            "reason": "HIGH_PRIORITY: Image Source from Forbidden Host Detected (URL Match)"
        }

    # 3. منطق لینک و متن
    has_forbidden_link = any(FORBIDDEN_HOST in link for link in links_to_check)

    if has_forbidden_link:
        if len(article_text) > 100 and check_keyword_robust(article_text):
            return {
                "action": "FILTER_HARD",
                "reason": "Nested Logic: Forbidden Link + Sensitive Topic Match (Robust)"
            }
        # اگر لینک ممنوعه بود اما موضوع حساس نبود، باز هم سخت مسدود کن (احتیاط بیشتر)
        return {
            "action": "FILTER_HARD",
            "reason": "HIGH_PRIORITY: Forbidden Link Detected"
        }

    # 4. فیلترینگ سبک‌تر (بررسی فقط متن)
    if check_keyword_robust(article_text):
        return {"action": "FILTER_LIGHT", "reason": "Generic Sensitive Topic Found (Robust)"}

    return {"action": "ALLOW", "reason": "Content is clear."}


# مسیر اصلی برای بررسی وضعیت سرور
@app.route('/', methods=['GET'])
def home():
    # نمایش تعداد کلمات و تصاویر فیلتر برای تأیید صحت یادگیری
    total_images = 0
    with image_hash_lock:
        total_images = len(FORBIDDEN_IMAGE_HASHES)

    return f"Python Content Filter API is running! Total keywords: {len(SENSITIVE_KEYWORDS)}. Total forbidden image hashes: {total_images}", 200


@app.route('/analyze_content_api', methods=['POST'])
def analyze_content_api():
    """
    نقطه پایانی که افزونه کروم آن را فراخوانی می‌کند (نیاز به توکن ندارد).
    """
    data = request.get_json()
    if not data or 'content' not in data:
        return jsonify({"error": "No content provided."}), 400

    result = check_nested_api_logic(data['content'])
    return jsonify(result)


# اجرای برنامه
if __name__ == '__main__':
    # این خط فقط برای اجرای محلی است.
    # در محیط ابری (مثل Render) اجرای Gunicorn از $PORT استفاده می‌کند.
    # تنظیم host='0.0.0.0' برای اجرای محلی روی تمام اینترفیس‌ها
    app.run(debug=True, host='0.0.0.0', port=os.environ.get('PORT', 5050))
