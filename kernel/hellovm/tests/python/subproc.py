import subprocess, sys
out = subprocess.run([sys.executable, "-c", "print('child', 6 * 7)"], capture_output=True, text=True)
print("subprocess:", out.returncode, out.stdout.strip())
p = subprocess.Popen(["/bin/sh", "-c", "read x; echo got $x; exit 3"], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
stdout, _ = p.communicate(b"hello\n")
print("communicate:", p.returncode, stdout.decode().strip())
print("check_output:", subprocess.check_output("echo a; echo b | tr b c", shell=True).decode().split())
