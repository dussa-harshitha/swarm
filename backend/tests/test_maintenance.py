import pathlib, subprocess, time
from app.verify.maintenance import maintenance_stats

def test_maintenance_on_fresh_git_repo(tmp_path):
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    (tmp_path / "a.txt").write_text("x")
    env = {"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t",
           "GIT_COMMITTER_EMAIL": "t@t", "PATH": "/usr/bin:/usr/local/bin"}
    for i in range(6):
        (tmp_path / "a.txt").write_text(str(i))
        subprocess.run(["git", "-C", str(tmp_path), "add", "."], check=True, env=env)
        subprocess.run(["git", "-C", str(tmp_path), "commit", "-qm", f"c{i}"], check=True, env=env)
    r = maintenance_stats(tmp_path)
    assert r.status == "verified", r.summary

def test_maintenance_no_git(tmp_path):
    r = maintenance_stats(tmp_path)
    assert r.status == "unverifiable"
