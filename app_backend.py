# app_backend.py - سرویس تحلیلگر پایتون (Flask)
# پیش‌نیاز: pip install flask flask-cors

from flask import Flask, request, jsonify
from flask_cors import CORS
import json
import time

app = Flask(__name__)
# فعال‌سازی CORS برای اجازه دادن به درخواست از افزونه کروم
CORS(app)

# --- شبیه‌سازی API تودرتو ---
FORBIDDEN_HOST = "melliun.org"


def check_nested_api_logic(content_data):
    """
    اجرای منطق API تودرتوی چندلایه، شامل بررسی لینک و منابع تصویر.
    """
    article_text = content_data.get('text', '')
    links_to_check = content_data.get('links', [])
    image_sources = content_data.get('imageSources', [])  # دریافت منابع تصاویر

    # 0. HIGH-PRIORITY: بررسی منابع تصویر (برای مسدودسازی محتوای بصری از سایت ممنوعه)
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


@app.route('/analyze_content_api', methods=['POST'])
def analyze_content_api():
    """ نقطه پایانی که افزونه کروم آن را فراخوانی می‌کند. """
    data = request.get_json()
    if not data or 'content' not in data:
        return jsonify({"error": "No content provided."}), 400

    # اجرای منطق API تودرتو
    result = check_nested_api_logic(data['content'])

    return jsonify(result)


if __name__ == '__main__':
    # استفاده از پورت 5050
    print("Python Backend API running on http://127.0.0.1:5050")
    app.run(port=5050)