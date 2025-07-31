import subprocess
import json

def run_semgrep_scan(local_path):
    try:
        result = subprocess.run(
            ['semgrep', '--config', 'auto', '--json', local_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding='utf-8',
            errors='replace'
        )

        if result.returncode != 0 and not result.stdout:
            return [{"error": result.stderr}]

        data = json.loads(result.stdout)
        findings = []

        for finding in data.get('results', []):
            findings.append({
                'check_id': finding.get('check_id'),
                'path': finding.get('path'),
                'start_line': finding['start']['line'],
                'end_line': finding['end']['line'],
                'message': finding.get('extra', {}).get('message'),
                'severity': finding.get('extra', {}).get('severity')
            })

        return findings

    except Exception as e:
        return [{"error": str(e)}]
