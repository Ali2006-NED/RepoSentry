from pydriller import Repository

def analyze_commits(repo_path):
    stats = {"total_commits":0,
             "contributors":set(),
             "large_commits":[]}

    for commit in Repository(repo_path).traverse_commits():
        stats['total_commits'] += 1
        stats.get("contributors").add(commit.author.name)

        if commit.lines > 500:
            stats['large_commits'].append({"hash":commit.hash,
                                           'message':commit.msg,
                                           'lines_changed':commit.lines
                                           })
    stats['contributors'] = list(stats['contributors'])
    return stats