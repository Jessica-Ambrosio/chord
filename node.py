from flask import Flask, request, render_template
import sys, math
import hashlib
import socket

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



# USER FUNCTIONS

@node.route("/join", methods["POST", "GET"])
def join():
	# Generate ID for the node.
	global nodeID 
	nodeID = genID()
	# Announce self. 
	# Broadcast message to the network. 
		# Need Broadcast address of network.
	# Set timer and wait for responses.
		# If we get responses
			# Store receivers. 
			# Verify with receiver that our ID has not been taken. 

	

@node.route("/leave", methods["POST"])
def leave():
	return "<h1>You have successfully exited chord.</h1>"

@node.route("/search", methods["POST"]) # This will be a GET request. 
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
	# Get IP address
	hostname = socket.gethostname()
	IP = socket.gethostbyname(hostname)
	# Hash it and mod it 
	ID = hashlib.sha1(IP) % math.pow(2, idBits)
	return ID

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




