import subprocess


def run_task():
    return subprocess.run(["echo", "ok"], shell=False, timeout=5)
