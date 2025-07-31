import shutil

import git
import tempfile

def clone_repository(repo_url):
    temp = tempfile.mkdtemp('temp')
    try:
        git.Repo.clone_from(repo_url,temp)
    except Exception as e:
        shutil.rmtree(temp)
        raise e
    return temp