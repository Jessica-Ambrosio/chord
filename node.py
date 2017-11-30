from flask import Flask, request, render_template
import sys, math
import hashlib
import requests
from socket import *
import time

node = Flask(__name__)
node.secret_key = "Distribyed4Lyfe"


@node.route("/")
def home():
	return render_template("index.html")

# Depending on how long the functions become, we could separate this
# into two files. One containing user functions, and the other one
# with Chord functions only. 

# Do you want to make a Node object? D:! 

# USER VARIABLES
nodeID = 0
# We could have a list of downloaded files on display. 

# CHORD VARIABLES
idBits = 3   		# Number of bits for ID
successor = None
predecessor = None
nodeSocket = socket.socket(AF_INET, socket.SOCK_STREAM)
nodePort = 5000
neighbors = []

# USER FUNCTIONS

@node.route("/")
def main():
	# Initialize the port opening the page.
	try: 
		nodeSocket.bind(socket.gethostbyname(hostname), nodePort)
	except socket.error:
		return "Error creating socket."
		sys.exit()
	render_template("index.html")

# TO DO: MAKE /exist POST function to check if a node alreayd exists. 

@node.route("/join")
def join():
	#Generate ID for the node.
	global nodeID 
	nodeID = genID()
	#Announce self. 
	data = "CONNECT"
	dest = ('<broadcast>', nodePort)
	nodeSocket.settimeout(5.0)  	   # Has a timeout of 5 seconds.
	nodeSocket.sendto(data, dest)
	try:
		counter = 0
		idTaken = False
		(data, address) = nodeSocket.recvfrom(512)  # data -> string
		# Keep at most 5 nodes available in case the others fail.
		while ((not is_empty((data,address))) and (counter < 5)):
			r = requests.post(str(address) + "/exist", data={'id':nodeID})
			if (not is_empty(r)): 
				neighbors.append((data,address))
				if r == "YES": # The node already exists.
					idTaken = True
			counter += 1
			(data, address) = nodeSocket.recvfrom(512)
		if (idTaken):
			changeID() 	# This function will create a new ID, and  
						# will send requests to the saved list of neighbors
						# to check if the ID has been taken. 
		else:
			makeFingers() # Make the finger table! :D 
	except socket.timeout:
		print "YOU ARE THE FIRST NODE IN THE CHORD SYSTEM."
	
# Make function to check if there exists a node with a given 
# 
@node.route("/leave")
def leave():
	return "<h1>You have successfully exited chord.</h1>"

@node.route("/search") # This will be a GET request. 
def search():
	return "FILE"

@node.route("/upload") # I'll figure this out tonight.
def upload():
	return "FILE UPLOADED"

# END OF USER FUNCTIONS


# CHORD FUNCTIONS

@node.route("/findSucc")
def findSucc():
	return "successor";

@node.route("/findPred")
def findPred():
	return "predecessor"

# Finds closest preceding finger. 
@node.route("/finger")
def finger():
	return "finger"

@node.route("/stabilize")
def stabilize():
	return "peace"

@node.route("/notify")
def notify():
	return "notify"

@node.route("/fixFinger")
def fixFinger():
	return "finger"

def genID():
	hostname = socket.gethostname()
	IP = socket.gethostbyname(hostname)
	ID = hashlib.sha1(IP) % math.pow(2, idBits)
	return string(ID)

def between(a, b, c):
	if b > a:
		if (a < c) and (c < b):
			return True
		else:
			return False
	else:
		if (c > a) or (c < b):
			return True
		else:
			return False

# END OF CHORD FUNCTIONS


if __name__ == "__main__":
	node.debug = True
	node.run(host="0.0.0.0")




