from flask import Flask, request, render_template
# from flask_socketio import *
import sys, math
import hashlib
import requests
import socket
import time
import nmap

node = Flask(__name__)
node.secret_key = "Distribyed4Lyfe"
# socketio = SocketIO(node)


@node.route("/")
def home():
	return render_template("index.html")

# Depending on how long the functions become, we could separate this
# into two files. One containing user functions, and the other one
# with Chord functions only.

# USER VARIABLES
nodeID = 0
# We could have a list of downloaded files on display.

# CHORD VARIABLES
idBits = 3   		# Number of bits for ID
successor = None
predecessor = None
neighbors = []

# USER FUNCTIONS

@node.route("/")
def main():
	render_template("index.html")

# TO DO: MAKE /exist POST function to check if a node already exists.

@node.route("/join", methods=["POST", "GET"])
def join():
	# Generate ID for the node.
	global nodeID
	nodeID = genID()
	# Scan the network to look for other active Chord nodes.
	nm = nmap.PortScanner()
 	address = socket.gethostname() + "/24"   	# We are assuming the protocol used is IPv4
	nm.scan(hosts=address, arguments="-p5000")	# All the chord instances will run on port 5000
	counter = 0
	for host in nm.all_hosts():
		# Do not add more than 5 nodes. We do not need to talk to all the nodes active.
		if (counter > 4):
			break
		if nm[host]['tcp'][5000]['state'] == "open":
			neighbors.append(host)
			counter += 1
	if len(neighbors) > 0:
		idTaken = False
		print "This is our list of neighbors"
		print neighbors
		for neighbor in neighbors:
			try:
				r = ""
				r = requests.post("http://" + neighbor + ":5000/exist", data={'id':nodeID}, timeout=5)
				if (not (r == "")):
					print "the request is not empty"
					print r  	   # For debugging purposes.
					if r == "YES": # The node already exists.
						idTaken = True
						break;
			except requests.exceptions.RequestException as e:
				print e
		if (idTaken):
			# changeID()
			return "Generate a new ID"
		else:
			# makeFingers() # Make the finger table! :D
			return "Welcome to CHORD"
	else:
		return "<h1>You are the only chord node in the network</h1>"


# Returns "YES" if the ID has already been taken
# and "NO" otherwise.
@node.route("/exist", methods=["POST"])
def exist():
	recID = request.form['id']
	# Do something to check if the node ID is taken or not.
	return "NO"

@node.route("/leave")
def leave():
	# Let the nodes on your table know that you are leaving
	# through a POST request.
	return "<h1>You have successfully exited chord.</h1>"


@node.route("/search")
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

# Fix this thing to ensure that it generates different IDs.
# For now, it's returning 0.0
def genID():
	hostname = socket.gethostname()
	IP = socket.gethostbyname(hostname)
	hashIP = hashlib.sha1(IP)
	ID = int(hashIP.hexdigest(), 16) % math.pow(2, idBits)
	print 'The id is' ,
	print str(ID)
	return str(ID)


# This function will create a new ID, and
# will send requests to the saved list of neighbors
# to check if the ID has been taken. This will be repeated
# until we determine a valid ID.
def changeID():
	print "I will do something"


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
	node.run(host='0.0.0.0', port=5000)
	# socketio.run(node) # Defaults to listening on localhost:5000
