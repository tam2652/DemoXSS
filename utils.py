import re
import requests
from urllib.parse import urlparse, urljoin

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
        print(f"Cảnh báo: Không thể truy xuất {url}: {e}")
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
