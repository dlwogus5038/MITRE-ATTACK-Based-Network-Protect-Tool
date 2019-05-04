import subprocess

print(subprocess.getstatusoutput("echo %systemroot%")[1])