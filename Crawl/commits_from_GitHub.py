import os
import subprocess
import json
import time

# Thư mục chứa các repo đã clone
REPO_ROOT = "C:/Users/ACER/Downloads/do an/clone"  # Thay đổi theo đường dẫn repo của bạn

# Danh sách từ khóa lấy từ keywords_dict gốc (đã flatten và chuyển về lowercase)
keywords_dict = {
    'oob': ['Out-of-bounds write', 'out of bounds write', 'out of bounds',  'memory corruption', 'CWE-787',
            'intended buffer', 'out-of-bounds', 'allows heap corruption', 'allows memory corruption', 
            'browser allows heap corruption', 'user can obtain read/write access to read-only pages', 
            'out-of-bounds write (CWE-787)', 'Out-of-bounds write in kernel-mode driver', 
            'incorrect bounds check', 'Memory corruption in web browser scripting engine', 
            'leading to out-of-bounds write', 'allowing out-of-bounds write', 
            'leading to memory corruption', 'leads to buffer underflow',  
            'stack-based buffer overflow', 'Heap-based buffer overflow' 
           ],
    'xss': ['Cross-site Scripting', 'cross site', 'cross-site','CWE-79', 'Improper Neutralization of Input During Web Page Generation',
            'XSS', 'HTML injection', 'contains untrusted data', 'executable by a web browser', 'untrusted data', 
            'web browser executes the malicious script', 'Reflected XSS', 'Stored XSS', 'DOM-Based XSS',
            'prevent XSS', 'prevent cross site', 'fix XSS', 'fix cross site', 'correct XSS', 'correct cross site',
            'allow reflected XSS', 'allowing reflected XSS', 'allowed reflected XSS',
            'reflected Cross-Site Scripting attacks','XSS (CWE-79)', 'allows XSS', 'insert malicious HTML sequences', 'XSS flaw',
            'did not sufficiently neutralize', 'allowing for reflected Cross-Site Scripting attacks', 
            'Universal XSS', 'Admin GUI allows XSS through cookie', 'allows XSS through crafted HTTP header',
            'allows XSS through crafted HTTP Referer header', 'protection mechanism failure allows XSS', 
            'allowing XSS (CWE-79) using other tags', 'enabling XSS (CWE-79)', 'Reflected XSS using the PATH_INFO in a URL',
            'Stored XSS in a security product', 'Stored XSS using a wiki page', 'Stored XSS in a guestbook application',                   
           ],
    'sql': ['Improper Neutralization of Special Elements used in an SQL Command', 'CWE-89', 
            'SQL Injection','SQL Command', 'improper SQL syntax', 'prevent sql injection'
           ], 
    'iiv': ['CWE-20', 'Improper Input Validation', 'does not validate input',
            'incorrectly validates the input', 'does not validate input properly',
            'input validation', 'bypass a validation step', 
            'insufficient input validation', 'improved input validation'
           ],
    'rce': ['Improper Control of Generation of Code', 'Code Injection', 'RCE',  'CWE-94',
            'remote code execution', 'modify the syntax', 'modify the behavior',
            'alter the intended control flow of the software', 'arbitrary code execution', 
            'injection weakness', 'string vulnerabilities',
            'prevent rce','prevent remote code execution', 'fix rce',
            'fix remote code execution', 'correct rce','correct remote code execution'
           ],
    'pat': ['CWE-22', 'Improper Limitation of a Pathname to a Restricted Directory','Path Traversal',
            'directory traversal', 'outside the restricted directory', 
            'escape outside of the restricted location', 'relative path traversal', 
            'absolute path traversal', 'accessing unexpected files', 
            'injection of a null byte', 'truncate a generated filename', 'null injection',
            'prevent directory traversal', 'fix directory traversal', 'correct directory traversal',
            'absolute pathname', 'drive letter'],
}

# Flatten tất cả keywords thành list lowercase để dễ so sánh
all_keywords = []
for group, keys in keywords_dict.items():
    for kw in keys:
        all_keywords.append(kw.lower())

# Chỉ lấy commit từ sau ngày này (theo API query gốc)
SINCE_DATE = "2012-01-01"

def scan_repo_commits(repo_path):
    commits = {}
    try:
        log = subprocess.check_output(
            ["git", "log", f"--since={SINCE_DATE}", "--pretty=format:%H|%an|%ad|%s"],
            cwd=repo_path,
            text=True,
            stderr=subprocess.DEVNULL
        )
    except Exception as e:
        print(f"⚠️ Lỗi khi đọc lịch sử commit repo {repo_path}: {e}")
        return commits
    
    for line in log.splitlines():
        parts = line.split("|", 3)
        if len(parts) < 4:
            continue
        sha, author, date, message = parts
        message_lower = message.lower()
        matched = [kw for kw in all_keywords if kw in message_lower]
        if matched:
            commits[sha] = {
                "sha": sha,
                "author": author,
                "date": date,
                "message": message.strip(),
                "keyword": list(set(matched))
            }
    return commits

def main():
    all_commits = {}
    repo_names = [d for d in os.listdir(REPO_ROOT) if os.path.isdir(os.path.join(REPO_ROOT, d))]
    total = len(repo_names)
    print(f"Found {total} repos. Starting scan...")

    for i, repo_name in enumerate(repo_names, 1):
        repo_path = os.path.join(REPO_ROOT, repo_name)
        print(f"[{i}/{total}] Scanning repo: {repo_name}")
        commits = scan_repo_commits(repo_path)
        if commits:
            all_commits[repo_name] = commits

    # Lưu kết quả ra file JSON
    with open("all_commits.json", "w", encoding="utf-8") as f:
        json.dump(all_commits, f, indent=2, ensure_ascii=False)

    print(f"Scan hoàn tất. Tìm thấy tổng cộng {sum(len(v) for v in all_commits.values())} commit phù hợp.")
    print("Kết quả lưu trong file all_commits_local.json")

if __name__ == "__main__":
    start = time.time()
    main()
    end = time.time()
    print(f"Thời gian chạy: {(end - start)/60:.2f} phút")
