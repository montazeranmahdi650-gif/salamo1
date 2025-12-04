from flask import Flask, request, jsonify
from flask_cors import CORS
import json
import time

app = Flask(__name__)
# فعال‌سازی CORS برای اجازه دادن به درخواست از افزونه کروم
CORS(app)

FORBIDDEN_HOST = "melliun.org"


def check_nested_api_logic(content_data):
    """
    اجرای منطق API تودرتوی چندلایه، شامل بررسی لینک و منابع تصویر.
    """
    article_text = content_data.get('text', '')
    links_to_check = content_data.get('links', [])
    image_sources = content_data.get('imageSources', [])

    # 0. HIGH-PRIORITY: بررسی منابع تصویر
    has_forbidden_image = any(FORBIDDEN_HOST in src for src in image_sources)
    if has_forbidden_image:
        return {
            "action": "FILTER_HARD",
            "reason": "HIGH_PRIORITY: Image Source from Forbidden Host Detected"
        }

    # 1. API 1 (اصلی): بررسی وجود لینک به سایت ممنوعه
    has_forbidden_link = any(FORBIDDEN_HOST in link for link in links_to_check)

    # --- منطق تو در تویی ---
    if has_forbidden_link:

        # 2. API 2 (تو در تو): تحلیل محتوای اطراف لینک ممنوعه (تحلیل موضوعی)
        if len(article_text) > 100 and any(keyword in article_text for keyword in ['شورش', 'تحریم', 'بحران', 'سقوط']):
            return {
                "action": "FILTER_HARD",
                "reason": "Nested Logic: Forbidden Link + Sensitive Topic Match"
            }

    # فیلترینگ سبک‌تر
    if 'ضد نظام' in article_text:
        return {"action": "FILTER_LIGHT", "reason": "Generic Sensitive Topic Found"}

    return {"action": "ALLOW", "reason": "Content is clear."}


# مسیر جدید: مسیر اصلی (/) برای بررسی وضعیت سرور (این خط اضافه شده است!)
@app.route('/', methods=['GET'])
def home():
    return "Python Content Filter API is running!", 200


@app.route('/analyze_content_api', methods=['POST'])
def analyze_content_api():
    """ نقطه پایانی که افزونه کروم آن را فراخوانی می‌کند. """
    data = request.get_json()
    if not data or 'content' not in data:
        return jsonify({"error": "No content provided."}), 400

    # اجرای منطق API تودرتو
    result = check_nested_api_logic(data['content'])

    return jsonify(result)

# بخش اجرای محلی حذف شده است.
