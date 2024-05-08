# RCE with user provided command with paramiko ssh client
Processing an unvalidated user input can allow an attacker to inject arbitrary command in your local and remote servers when creating a ssh connection.


## Recommendation
This vulnerability can be prevented by not allowing untrusted user input to be passed as ProxyCommand or exec_command.


## Example
In the example below, the ProxyCommand and exec_command are controlled by the user and hence leads to a vulnerability.


```python
#!/usr/bin/env python

from flask import request, Flask
import paramiko
from paramiko import SSHClient

app = Flask(__name__)
paramiko_ssh_client = SSHClient()
paramiko_ssh_client.load_system_host_keys()
paramiko_ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
paramiko_ssh_client.connect(hostname="127.0.0.1", port="22", username="ssh_user_name", pkey="k", timeout=11, banner_timeout=200)


@app.route('/external_exec_command_1')
def bad1():
    user_cmd = request.args.get('command')
    stdin, stdout, stderr = paramiko_ssh_client.exec_command(user_cmd)
    return stdout

@app.route('/external_exec_command_2')
def bad2():
    user_cmd = request.args.get('command')
    stdin, stdout, stderr = paramiko_ssh_client.exec_command(command=user_cmd)
    return stdout


@app.route('/proxycommand')
def bad2():
    user_cmd = request.args.get('command')
    stdin, stdout, stderr = paramiko_ssh_client.connect('hostname', username='user',password='yourpassword',sock=paramiko.ProxyCommand(user_cmd))
    return stdout

if __name__ == '__main__':
    app.debug = False
    app.run()


```
