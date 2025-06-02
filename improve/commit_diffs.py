import os
import sys
import json
import subprocess

REPO_ROOT = "D:/clone1/clone"  #folder repo

def check_if_have(repository, sha):
    return (
        repository in prev_results
        and sha in prev_results[repository]
        and 'diff' in prev_results[repository][sha]
    )

def getdiffs(repo_path):
    repo_data = {}
    local_repo_dir = os.path.join(REPO_ROOT, repo_path)

    for c in repositories[repo_path]:
        already_have_it = check_if_have(repo_path, c)

        if already_have_it:
            if repo_path not in repo_data:
                repo_data[repo_path] = {}
            repo_data[repo_path][c] = {
                "sha": prev_results[repo_path][c]["sha"],
                "keyword": prev_results[repo_path][c]["keyword"],
                "diff": prev_results[repo_path][c]["diff"]
            }
        else:
            try:
                result = subprocess.run(
                    ['git', 'show', c],
                    cwd=local_repo_dir,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    encoding='utf-8', 
                    errors='replace',    
                    check=True
                )
                diffcontent = result.stdout
            except subprocess.CalledProcessError as e:
                print(f"Lỗi khi lấy diff từ commit {c} trong repo {repo_path}: {e.stderr}")
                continue

            if diffcontent and ".py" in diffcontent:
                if repo_path not in repo_data:
                    repo_data[repo_path] = {}
                repo_data[repo_path][c] = {
                    "sha": repositories[repo_path][c].get("sha", c),
                    "keyword": repositories[repo_path][c].get("keyword", ""),
                    "diff": diffcontent
                }

    return repo_data

if len(sys.argv) < 2:
    print("Usage: python script.py <json_file>")
    sys.exit(1)

json_file = sys.argv[1]

with open(json_file, 'r', encoding='utf-8') as infile:
    repositories = json.load(infile)

print('# of repositories:', len(repositories))

# Load previous results
prev_results = {}
if os.path.isfile('commits_with_diffs.json'):
    with open('commits_with_diffs.json', 'r', encoding='utf-8') as infile:
        prev_results = json.load(infile)

alld = {}

for idx, repo_name in enumerate(repositories):
    data = getdiffs(repo_name)

    if repo_name not in alld:
        alld[repo_name] = {}
    if repo_name in data:
        alld[repo_name].update(data[repo_name])

    if idx % 10 == 0:
        print(f"Processed {idx} repos...")

    if len(alld[repo_name]) % 100 == 0:
        print(f"{idx} - Saving partial data ({len(alld[repo_name])} commits for {repo_name})")
        os.makedirs("ChunkedData", exist_ok=True)
        with open(f"ChunkedData/part_of_diffs_data_{idx}.json", 'w', encoding='utf-8') as outfile:
            json.dump(alld, outfile, indent=2)

    elif idx == len(repositories) - 1:
        print(f"{idx} - Final save for {repo_name}")
        os.makedirs("ChunkedData", exist_ok=True)
        with open(f"ChunkedData/part_of_diffs_data_{idx}.json", 'w', encoding='utf-8') as outfile:
            json.dump(alld, outfile, indent=2)

# Save final result
print('len(alld):', len(alld))
with open('commits_with_diffs.json', 'w', encoding='utf-8') as outfile:
    json.dump(alld, outfile, indent=2)
