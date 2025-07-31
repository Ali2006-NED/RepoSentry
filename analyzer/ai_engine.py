from mistralai import Mistral
import os
from dotenv import load_dotenv

from analyzer.repo_cloner import clone_repository
from analyzer.metrics import evaluate_code_metrics
from analyzer.commits import analyze_commits
from analyzer.static_analyzer import run_semgrep_scan


load_dotenv()

API_KEY = os.getenv("MISTRAL_API_KEY")

client = Mistral(api_key=API_KEY)

def suggest_fixes(semgrep_results):
    suggestions = []
    for issue in semgrep_results:
        code_snippet = issue.get("code", "")
        prompt = f"Detect any vulnerability in this code and suggest a fix:\n{code_snippet}"

        try:
            response = client.chat.complete(
                model="mistral-large-latest",
                messages=[{"role": "user", "content": prompt}]
            )
            suggestions.append({
                "issue": issue,
                "ai_fix": response.choices[0].message.content
            })
        except Exception as e:
            suggestions.append({
                "issue": issue,
                "ai_fix": f"Error generating suggestion: {str(e)}"
            })

    return suggestions

if __name__ == '__main__':
    repo_url = 'https://github.com/Ali2006-NED/Inventory-Management-System.git'
    local_path = clone_repository(repo_url)
    static_results = run_semgrep_scan(local_path)
    commit_stats = analyze_commits(local_path)
    code_metrics = evaluate_code_metrics(local_path)
    ai_fixes = suggest_fixes(static_results)

    print(commit_stats)
    print(code_metrics)
    print(ai_fixes)


