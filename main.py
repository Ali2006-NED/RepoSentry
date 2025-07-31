from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from analyzer.repo_cloner import clone_repository
from analyzer.metrics import evaluate_code_metrics
from analyzer.commits import analyze_commits
from analyzer.ai_engine import suggest_fixes
from analyzer.static_analyzer import run_semgrep_scan

app = FastAPI()

class RepoInput(BaseModel):
    repo_url:str
    include_ai:bool = False

@app.post('/analyze')
async def analyze_repo(inpt:RepoInput):
    try:
        local_path = clone_repository(inpt.repo_url)
        static_results = run_semgrep_scan(local_path)
        commit_stats = analyze_commits(local_path)
        code_metrics = evaluate_code_metrics(local_path)

        ai_suggestions = []
        if inpt.include_ai:
            ai_suggestions = suggest_fixes(static_results)

        return {
            "static_analysis": static_results,
            "commit_analysis": commit_stats,
            "code_metrics": code_metrics,
            "ai_suggestions": ai_suggestions
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
