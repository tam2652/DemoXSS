import colorama
import requests
import re
from collections import deque
import threading
import logging
from colorama import Fore, Style

from utils import extract_internal_links, get_base_url, is_same_domain
from xss_checks import perform_xss_checks_input, perform_xss_checks_textarea, inject_payloads_to_url, payloads
from auth import login

# Khởi tạo colorama để sử dụng màu sắc trong console
colorama.init()

# Cấu hình logging để ghi lại thông tin vào tệp 'xss_scan_results.log'
logging.basicConfig(filename='xss_scan_results.log', level=logging.INFO, format='%(asctime)s - %(message)s')

# Tập hợp để theo dõi các URL đã được thăm
visited_urls = set()
# Khóa để đảm bảo an toàn khi truy cập 'visited_urls' trong môi trường đa luồng
visited_urls_lock = threading.Lock()

def perform_xss_checks(url, login_url=None, username=None, password=None, max_depth=3):
    """
    Hàm kiểm tra XSS trên các trang web, bắt đầu từ một URL nhất định và đệ quy tới các liên kết nội bộ
    """
    session = requests.Session()

    if login_url and username and password:
        if not login(session, login_url, username, password):
            return

    # Hàng đợi hai đầu để duyệt qua các trang
    queue = deque([(url, 0)])
    visited_urls.add(url)

    while queue:
        # lấy url hiện tại và độ sâu của hàm đợi
        current_url, depth = queue.popleft()
        if depth > max_depth: # nếu độ sâu vượt giới hạn tối đa, bỏ qua url
            continue

        try:
            response = session.get(current_url, headers={'User-Agent': 'Mozilla/5.0'}) #gửi yêu cầu HTTP GET đến URL hiện tại
            if response.status_code == 200: #yêu cầu thành công
                page_content = response.text #lấy nội dung của trang web
                # Tìm tất cả các thẻ input và textarea
                input_fields = re.findall(r'<input.*?type=["\']text["\'].*?>', page_content, flags=re.IGNORECASE)
                textarea_fields = re.findall(r'<textarea.*?>.*?</textarea>', page_content, flags=re.IGNORECASE)
                # Kiểm tra XSS trên các thẻ input và textarea
                perform_xss_checks_input(current_url, input_fields, payloads)
                perform_xss_checks_textarea(current_url, textarea_fields,payloads)
                # Kiểm tra XSS bằng cách chèn payload vào tham số URL
                inject_payloads_to_url(current_url, payloads)
                # Trích xuất các liên kết nội bộ
                internal_links = extract_internal_links(current_url, session)
                for link in internal_links:
                    with visited_urls_lock:
                        if link not in visited_urls:
                            visited_urls.add(link)
                            queue.append((link, depth + 1))
        except requests.RequestException as e: #nếu xảy ra lỗi khi gửi yêu cầu HTTP, in ra cảnh báo
            print(f"{Fore.YELLOW}Cảnh báo: Không thể truy xuất {current_url}: {e}{Style.RESET_ALL}")

# Nhận URL và thông tin đăng nhập từ người dùng và bắt đầu kiểm tra XSS
url = "http://testphp.vulnweb.com/"
login_url = "http://testphp.vulnweb.com/userinfo.php"
username = "test"
password = "test"

perform_xss_checks(url, login_url, username, password)