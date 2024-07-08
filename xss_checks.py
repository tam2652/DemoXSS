import re
from urllib.parse import urlparse, parse_qs, urlencode

import requests
import logging
from colorama import Fore, Style

payloads = [
    '<script>alert("XSS")</script>',
    '"><script>alert("XSS\')"></script>',
    '"><img src=x onerror=alert("XSS")>',
    'javascript:alert("XSS")',
]

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
