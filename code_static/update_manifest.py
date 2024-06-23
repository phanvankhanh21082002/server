#!/usr/bin/env python3

import re
import requests
from bs4 import BeautifulSoup, NavigableString

ANDROID_PERMISSION_DOCS_URL = 'https://developer.android.com/reference/android/Manifest.permission'

def fetch_android_permissions(url):
    # Gửi yêu cầu HTTP GET
    response = requests.get(url)
    response.raise_for_status()  # Nếu yêu cầu thất bại, một ngoại lệ sẽ được ném ra
    content = BeautifulSoup(response.content, 'html.parser')

    online_permissions = {}

    # Lấy tất cả các thẻ div chứa thông tin về permission
    permission_divs = content.find_all('div', {'data-version-added': re.compile(r'\d*')})
    for pd in permission_divs:
        header = pd.find('h3')
        if header is None or header.text in ['Constants', 'Manifest.permission']:
            continue
        
        permission_name = header.text.strip()
        description_paragraph = pd.find('p')
        if description_paragraph is None:
            continue
        
        # Rút trích mức độ bảo vệ
        protection_level_match = re.search(r'Protection level: (\w+)', str(pd))
        protection_level = protection_level_match.group(1) if protection_level_match else 'normal'

        # Rút trích mô tả
        description = ' '.join([str(x).strip() for x in description_paragraph.contents if isinstance(x, (str, NavigableString))])

        online_permissions[permission_name] = [protection_level, '', description]

    return online_permissions

def main():
    permissions = fetch_android_permissions(ANDROID_PERMISSION_DOCS_URL)
    for perm, details in permissions.items():
        print(f"{perm}: {details}")

if __name__ == "__main__":
    main()
