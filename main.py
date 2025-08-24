# main.py
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from typing import List, Dict, Any
import os

# Your analyzers
from analyzer.repo_cloner import clone_repository
from analyzer.static_analyzer import run_semgrep_scan
from analyzer.commits import analyze_commits
from analyzer.metrics import calculate_vuln_metrics
from analyzer.ai_engine import suggest_fixes  # we'll call this with a better prompt

app = FastAPI(title="CyberGuard")

# Templates & static
templates = Jinja2Templates(directory="Frontend/asset")
app.mount("/static", StaticFiles(directory="Frontend/static"), name="static")


# ===== Helpers to normalize data for the frontend =====
EXT_LANG = {
    ".py": "Python", ".js": "JavaScript", ".ts": "TypeScript", ".jsx": "JavaScript",
    ".tsx": "TypeScript", ".java": "Java", ".rb": "Ruby", ".go": "Go", ".rs": "Rust",
    ".php": "PHP", ".c": "C", ".h": "C", ".cpp": "C++", ".hpp": "C++", ".cs": "C#",
    ".swift": "Swift", ".kt": "Kotlin", ".m": "Objective-C", ".scss": "SCSS",
    ".css": "CSS", ".sh": "Shell", ".sql": "SQL", ".yaml": "YAML", ".yml": "YAML"
}

def guess_language_from_path(path: str) -> str:
    _, ext = os.path.splitext(path or "")
    return EXT_LANG.get(ext.lower(), "Other")

def read_snippet(path: str, start_line: int, end_line: int, context: int = 1) -> str:
    try:
        if not os.path.exists(path):
            return ""
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
        s = max(1, start_line - context)
        e = min(len(lines), (end_line or start_line) + context)
        return "".join(lines[s-1:e])
    except Exception:
        return ""

def normalize_semgrep(raw_results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Convert semgrep list -> normalized dict the frontend consumes.
    Expected semgrep entry keys we saw earlier:
      check_id, path, start_line, end_line, message, severity
    """
    issues = []
    severity_counts = {"ERROR": 0, "WARNING": 0, "INFO": 0}
    hotspots: Dict[str, int] = {}
    lang_vulns: Dict[str, int] = {}

    for it in raw_results or []:
        file_path = it.get("path", "unknown")
        start = int(it.get("start_line", 0) or 0)
        end = int(it.get("end_line", start) or start)
        sev = (it.get("severity") or "INFO").upper()
        rule = it.get("check_id") or "unknown"
        msg = it.get("message") or ""

        # Try to include a short code snippet (non-fatal if missing)
        snippet = read_snippet(file_path, start, end, context=1)

        lang = guess_language_from_path(file_path)

        file_name = os.path.basename(file_path)

        issues.append({
            "file": file_name,
            "line": start,
            "end_line": end,
            "severity": sev,
            "rule": rule,
            "message": msg,
            "language": lang,
            "snippet": snippet.strip()
        })

        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        hotspots[file_path] = hotspots.get(file_path, 0) + 1
        lang_vulns[lang] = lang_vulns.get(lang, 0) + 1

    sorted_hotspots = sorted(hotspots.items(), key=lambda x: x[1], reverse=True)
    return {
        "issues": issues,
        "severity_distribution": severity_counts,
        "hotspots": [{"file": f, "count": c} for f, c in sorted_hotspots[:8]],
        "language_vulns": lang_vulns
    }

def normalize_commits(commit_stats: Dict[str, Any]) -> Dict[str, Any]:
    # Expected from your earlier code: total_commits, contributors, large_commits
    contributors = commit_stats.get("contributors", []) if commit_stats else []
    large = commit_stats.get("large_commits", []) if commit_stats else []
    return {
        "total_commits": commit_stats.get("total_commits", 0),
        "contributors_count": len(contributors),
        "top_contributors": contributors[:8],
        "large_commits_count": len(large),
        "large_commits": large,  # pass a few for detail panel
    }


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.post("/analyze")
async def analyze_repo(payload: Dict[str, Any]):
    """
    Request:
      {
        "repo_url": "https://github.com/owner/repo.git",
        "include_ai": true/false
      }
    Response: structured for the dashboard UI.
    """
    try:
        repo_url = (payload or {}).get("repo_url")
        include_ai = bool((payload or {}).get("include_ai", False))
        if not repo_url:
            raise HTTPException(status_code=400, detail="repo_url is required")

        local_path = clone_repository(repo_url)

        # Static analysis
        semgrep_raw = run_semgrep_scan(local_path)
        static_norm = normalize_semgrep(semgrep_raw)

        # Metrics (your advanced metrics based on semgrep + repo)
        metrics = calculate_vuln_metrics(semgrep_raw, local_path)
        # Also compute a simple risk score alias for the card (if not present)
        risk_score = metrics.get("severity_risk_score") or metrics.get("risk_score") or 0

        # Commit analysis
        commits_raw = analyze_commits(local_path)
        commits_norm = normalize_commits(commits_raw)

        # AI suggestions (optional: cap to top N risky issues)
        ai_suggestions = []
        if include_ai and static_norm["issues"]:
            top_issues = sorted(
                static_norm["issues"],
                key=lambda x: {"ERROR": 3, "WARNING": 2, "INFO": 1}.get(x["severity"], 1),
                reverse=True
            )[:8]  # limit cost
            # Build a compact payload for ai_engine
            ai_input = [{
                "file": i["file"],
                "line": i["line"],
                "rule": i["rule"],
                "severity": i["severity"],
                "message": i["message"],
                "language": i["language"],
                "code": i["snippet"]
            } for i in top_issues]
            # suggest_fixes should accept list[dict] and return list[str] or list[dict]
            ai_suggestions = suggest_fixes(ai_input)

        return {
            "static_analysis": static_norm,
            "code_metrics": {**metrics, "risk_score": risk_score},
            "commit_overview": commits_norm,
            "ai_suggestions": ai_suggestions
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
