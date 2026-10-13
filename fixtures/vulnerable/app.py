import subprocess


def run_task(user_input):
    return subprocess.run(user_input, shell=True)
