import os
import re

# Define extensions for common programming languages
LANG_EXTENSIONS = {
    '.py', '.js', '.java', '.cpp', '.c', '.cs', '.ts', '.rb', '.go'
}

def evaluate_code_metrics(repo_path):
    loc_count = 0
    comment_count = 0
    file_count = 0
    total_size = 0
    function_count = 0

    function_patterns = {
        '.py': r'^\s*def\s+\w+\(',
        '.js': r'function\s+\w+\(',
        '.java': r'(public|private|protected)?\s+\w+\s+\w+\(',
        '.cpp': r'^\s*\w+\s+\w+\(.*\)\s*{',
        '.c': r'^\s*\w+\s+\w+\(.*\)\s*{',
        '.cs': r'(public|private|protected)?\s+\w+\s+\w+\(',
        '.ts': r'function\s+\w+\(',
        '.go': r'func\s+\w+\(',
        '.rb': r'def\s+\w+'
    }

    for root, _, files in os.walk(repo_path):
        for file in files:
            ext = os.path.splitext(file)[1]
            if ext in LANG_EXTENSIONS:
                file_path = os.path.join(root, file)
                file_count += 1
                total_size += os.path.getsize(file_path)

                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    lines = f.readlines()
                    loc_count += len(lines)

                    # Count comment lines and functions
                    for line in lines:
                        if ext == '.py' and line.strip().startswith("#"):
                            comment_count += 1
                        elif ext in {'.js', '.ts', '.java', '.c', '.cpp', '.cs'} and '//' in line.strip():
                            comment_count += 1
                        elif ext == '.go' and line.strip().startswith("//"):
                            comment_count += 1
                        elif ext == '.rb' and line.strip().startswith("#"):
                            comment_count += 1

                        if ext in function_patterns:
                            if re.search(function_patterns[ext], line):
                                function_count += 1

    average_file_size = total_size / file_count if file_count else 0
    avg_lines_per_func = loc_count / function_count if function_count else 0

    return {
        "total_files": file_count,
        "total_lines_of_code": loc_count,
        "total_comment_lines": comment_count,
        "average_file_size_bytes": round(average_file_size, 2),
        "average_lines_per_function": round(avg_lines_per_func, 2)
    }

EXTENSION_LANG_MAP = {
    ".py": "Python",
    ".js": "JavaScript",
    ".ts": "TypeScript",
    ".java": "Java",
    ".cpp": "C++",
    ".c": "C",
    ".cs": "C#",
    ".rb": "Ruby",
    ".go": "Go",
    ".php": "PHP"
    # Add more as needed
}

def infer_language_from_path(path):
    ext = os.path.splitext(path)[1]
    return EXTENSION_LANG_MAP.get(ext, "Unknown")

def calculate_vuln_metrics(vulnerabilities, repo_path):
    # Base code metrics
    repo_metrics = evaluate_code_metrics(repo_path)
    total_loc = repo_metrics["total_lines_of_code"]
    lang_stats = repo_metrics.get("language_stats", {})

    # Metric 1: Vulnerability Density (per 1000 LoC)
    total_loc = total_loc if total_loc > 0 else 1
    vuln_density = len(vulnerabilities) / (total_loc / 1000)

    # Metric 2: Severity Weighted Risk Score
    severity_weights = {"INFO": 1, "WARNING": 5, "ERROR": 10}
    risk_score = sum(severity_weights.get(v.get("severity", "INFO").upper(), 1) for v in vulnerabilities)

    # Metric 3: Hotspot Detection
    file_issues = {}
    for vuln in vulnerabilities:
        path = vuln.get("path", "unknown")
        file_issues[path] = file_issues.get(path, 0) + 1
    top_hotspots = sorted(file_issues.items(), key=lambda x: x[1], reverse=True)

    # Metric 4: Vulnerability Type Distribution
    type_distribution = {}
    for vuln in vulnerabilities:
        rule_id = vuln.get("check_id", "unknown")
        type_distribution[rule_id] = type_distribution.get(rule_id, 0) + 1

    # Metric 5: Security Debt Score
    unresolved = len([v for v in vulnerabilities if not v.get("resolved", False)])
    total = len(vulnerabilities)
    security_debt = unresolved / total if total > 0 else 0.0

    # Metric 6: Language-Specific Risk Profile
    language_risks = {}
    for vuln in vulnerabilities:
        lang = vuln.get("language")
        if not lang:
            lang = infer_language_from_path(vuln.get("path", ""))

        if lang not in language_risks:
            language_risks[lang] = {"vulns": 0, "density": 0}
        language_risks[lang]["vulns"] += 1

    # Compute density for each language using lang_stats
    for lang, stats in language_risks.items():
        loc = lang_stats.get(lang, 0)
        stats["density"] = stats["vulns"] / (loc / 1000) if loc > 0 else 0

    return {
        "vulnerability_density": round(vuln_density, 2),
        "severity_risk_score": risk_score,
        "hotspot_files": top_hotspots[:5],
        "vulnerability_type_distribution": type_distribution,
        "security_debt_score": round(security_debt, 2),
        "language_risk_profile": language_risks,
        "total_files": repo_metrics["total_files"],
        "total_lines_of_code": repo_metrics["total_lines_of_code"]
    }