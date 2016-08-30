import threading
import paramiko
import subprocess

def ssh_command(ip, username, password, command):
	client = paramiko.SSHClient()
	#client.load_host_keys('/home/felicitychou/.ssh/known_hosts')
	client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
	client.connect(hostname=ip, username=username, password=password)

	ssh_session = client.get_transport().open_session()
	if ssh_session.active:
		ssh_session.exec_command(command)
		print ssh_session.recv(1024)
	return

ssh_command('192.168.100.130','felicitychou','password','id')