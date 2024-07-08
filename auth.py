import requests
from colorama import Fore, Style

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
