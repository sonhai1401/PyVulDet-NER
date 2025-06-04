import re
from unidiff import PatchSet
from io import StringIO
import os
import json
import multiprocessing
from datetime import datetime

def getChanges(rest):
    # Loại bỏ dòng \ No newline at end of file
    lines = rest.splitlines()
    cleaned_lines = [line for line in lines if line.strip() != r'\ No newline at end of file']
    cleaned_diff = "\n".join(cleaned_lines)

    try:
        patch = PatchSet(StringIO(cleaned_diff))
        changes = []
        for patched_file in patch:
            filename = patched_file.path
            if not (filename.endswith('.py') or filename.endswith('.ipynb')):
                continue
            for hunk in patched_file:
                change = ''
                for line in hunk:
                    if line.is_added:
                        change += '+' + line.value
                    elif line.is_removed:
                        change += '-' + line.value
                    else:
                        change += ' ' + line.value
                if change:
                    changes.append([filename, change])
        return changes
    except Exception as e:
        print(f"unidiff failed with {e}, falling back to manual parse...")
        return manual_parse_diff(rest)

def manual_parse_diff(rest):
    changes = []
    # Tách các phần diff từng file dựa vào dòng bắt đầu diff --git
    titlelines = re.findall(r'^diff --git a/(.*) b/.*$', rest, flags=re.MULTILINE)
    diff_file_blocks = re.split(r'^diff --git a/.* b/.*$', rest, flags=re.MULTILINE)[1:]

    for titleline, block in zip(titlelines, diff_file_blocks):
        # Lọc file ko phải .py hoặc .ipynb
        if not (titleline.endswith('.py') or titleline.endswith('.ipynb')):
            continue
        
        # Tách từng hunk theo dấu @@ ... @@
        hunks = re.split(r'@@ .* @@', block)
        for hunk in hunks[1:]:  # bỏ phần đầu không chứa code
            lines = hunk.splitlines()
            change = ""
            for line in lines:
                line = line.rstrip('\n\r')
                if line.startswith('+'):
                    change += '+' + line[1:] + '\n'
                elif line.startswith('-'):
                    change += '-' + line[1:] + '\n'
                else:
                    change += ' ' + line + '\n'
            if change.strip():
                changes.append([titleline, change.strip('\n')])
    return changes

def getFilename(titleline):
    # Với unidiff titleline đã là filename
    return titleline

def getBadpart(change):
    badexamples = []
    goodexamples = []
    lines = change.split("\n")
    for line in lines:
        line = line.strip()
        if len(line) > 0:
            if line[0] == "-":
                badexamples.append(line[1:])
            if line[0] == "+":
                goodexamples.append(line[1:])
    if len(badexamples) == 0:
        return None
    else:
        return [badexamples, goodexamples]

def getDiffOrig(change):
    difforig = ''
    lines = change.split("\n")
    for line in lines:
        line = line.strip()
        if len(line) > 0:
            if line[0] == "-":
                difforig += '\n' + line[1:]
            elif line[0] == "+":
                continue
            else:
                difforig += '\n' + line
    return difforig

def makechangeobj(changething):
    change = changething[1]
    titleline = changething[0]
    thischange = {}

    bad_good = getBadpart(change)
    if bad_good is None:
        return None

    badparts, goodparts = bad_good
    linesadded = change.count("\n+")
    linesremoved = change.count("\n-")
    thischange["diff"] = change
    thischange["add"] = linesadded
    thischange["remove"] = linesremoved
    thischange["filename"] = getFilename(titleline)
    thischange["diffOrig"] = getDiffOrig(change)
    thischange["badparts"] = badparts
    thischange["goodparts"] = goodparts if goodparts is not None else []
    return thischange

def contains_keyword(keywords, keywords_to_check):
    if isinstance(keywords, list):
        keywords_str = " ".join(keywords).lower()
    else:
        keywords_str = str(keywords).lower()
    return any(k in keywords_str for k in keywords_to_check)

def process_mode(args):
    data_orig, mode, version, data_dir, keywords_dict = args

    filename = f"{mode}_{version}.json"
    save_path = os.path.join(data_dir, filename)
    if os.path.exists(save_path):
        return f"{filename} already exists, skipping."

    keywords_to_check = set(x.lower() for x in keywords_dict[mode])
    changelist = set()
    data_new_list = []

    total_commits = sum(len(data_orig[r]) for r in data_orig)
    processed_commits = 0

    for repo_idx, r in enumerate(data_orig):
        for c in data_orig[r]:
            processed_commits += 1
            if processed_commits % 100 == 0:
                print(f"[{mode}] Processed {processed_commits}/{total_commits} commits")

            keywords = data_orig[r][c].get("keyword", "")
            if not contains_keyword(keywords, keywords_to_check):
                continue

            if c in changelist:
                continue
            changelist.add(c)

            changes = getChanges(data_orig[r][c].get("diff", ""))
            for change in changes:
                thischange = makechangeobj(change)
                if thischange is not None:
                    data_new = {
                        "keyword": data_orig[r][c]["keyword"],
                        "cwetype": mode,
                        "repo": r,
                        "commit": c,
                        "goodparts": thischange['goodparts'],
                        "badparts": thischange['badparts'],
                        "orig_diff": thischange['diff'],
                        "orig_txt": thischange["diffOrig"]
                    }
                    data_new_list.append(data_new)

    with open(save_path, 'w', encoding='utf-8') as outfile:
        json.dump(data_new_list, outfile, indent=2, ensure_ascii=False)

    return f"{filename} done, extracted {len(data_new_list)} changes"

if __name__ == '__main__':
    data_dir = 'Data'
    os.makedirs(data_dir, exist_ok=True)

    chunked_file_list = list(os.listdir('ChunkedData'))
    file_list = [os.path.join('ChunkedData', f) for f in chunked_file_list]
    file_list.append('commits_with_diffs.json')

    keywords_dict = {'oob':['Out-of-bounds write','out of bounds write', 'out of bounds',  'memory corruption', 'CWE-787',
                            'intended buffer', 'out-of-bounds', 'allows heap corruption', 'allows memory corruption', 
                            'browser allows heap corruption', 'user can obtain read/write access to read-only pages', 
                            'out-of-bounds write (CWE-787)', 'Out-of-bounds write in kernel-mode driver', 
                            'incorrect bounds check', 'Memory corruption in web browser scripting engine', 
                            'leading to out-of-bounds write', 'allowing out-of-bounds write', 
                            'leading to memory corruption', 'leads to buffer underflow',  
                            'stack-based buffer overflow', 'Heap-based buffer overflow' 
                           ],
                     
                     'xss':['Cross-site Scripting', 'cross site', 'cross-site','CWE-79', 'Improper Neutralization of Input During Web Page Generation',
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
                     
                     'sql':['Improper Neutralization of Special Elements used in an SQL Command', 'CWE-89', 
                            'SQL Injection','SQL Command', 'improper SQL syntax', 'prevent sql injection'
                           ], 
                     
                     'iiv':['CWE-20', 'Improper Input Validation', 'does not validate input',
                            'incorrectly validates the input', 'does not validate input properly',
                            'input validation', 'bypass a validation step', 
                            'insufficient input validation', 'improved input validation'
                           ],
                     
                     'rce':['Improper Control of Generation of Code', 'Code Injection', 'RCE',  'CWE-94',
                            'remote code execution', 'modify the syntax', 'modify the behavior',
                            'alter the intended control flow of the software', 'arbitrary code execution', 
                            'injection weakness', 'string vulnerabilities',
                            'prevent rce','prevent remote code execution', 'fix rce',
                            'fix remote code execution', 'correct rce','correct remote code execution'
                           ],
                     
                     'pat':['CWE-22', 'Improper Limitation of a Pathname to a Restricted Directory','Path Traversal',
                            'directory traversal', 'outside the restricted directory', 
                            'escape outside of the restricted location', 'relative path traversal', 
                            'absolute path traversal', 'accessing unexpected files', 
                            'injection of a null byte', 'truncate a generated filename', 'null injection',
                            'prevent directory traversal', 'fix directory traversal', 'correct directory traversal',
                            'absolute pathname', 'drive letter'],
                    } 

    mode_list = ["sql", "oob", "iiv", "rce", "pat", "xss"]

    print(f"Start processing at {datetime.now().strftime('%H:%M:%S')}")

    for file_idx, file in enumerate(file_list):
        print(f"\nLoading file {file_idx+1}/{len(file_list)}: {file}")
        with open(file, 'r', encoding='utf-8') as infile:
            data_orig = json.load(infile)
        print(f"  Number of repos in file: {len(data_orig)}")

        version = os.path.basename(file).split('_')[-1].split('.')[0]

        params = [(data_orig, mode, version, data_dir, keywords_dict) for mode in mode_list]

        with multiprocessing.Pool(processes=4) as pool:
            results = pool.map(process_mode, params)

        for res in results:
            print(res)

    print(f"\nFinished all processing at {datetime.now().strftime('%H:%M:%S')}")
