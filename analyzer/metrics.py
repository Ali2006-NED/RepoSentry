import os

def evaluate_code_metrics(repo_path):
    loc_count = 0
    file_count = 0
    for root, _, files in os.walk(repo_path):
        for file in files:
            if file.endswith(".py"):
                file_count += 1
                with open(os.path.join(root, file), "r", encoding="utf-8", errors="ignore") as f:
                    loc_count += len(f.readlines())

    return {
        "total_files": file_count,
        "total_lines_of_code": loc_count
    }