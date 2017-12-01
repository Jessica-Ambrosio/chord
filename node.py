
from flask import Flask, request, render_template, jsonify
import sys, math
import hashlib
import requests
import socket
import time
import nmap
import random
import requests
import csv

app = Flask(__name__)
app.secret_key = "Distribyed4Lyfe"

# [IP]: string
# [ID]: integer
class Node:
	def __init__(self, IP, ID):
		self.IP = IP
		self.ID = ID

@app.route("/")
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
NEIGHBORS = []

# Do you want to make a Node object? D:!

# USER VARIABLES
NODE = Node(None, None)
# We could have a list of downloaded files on display.

# CHORD VARIABLES
IDBITS = 3   		# Number of bits for ID
SUCCESSOR = Node(None, None)
PREDECESSOR = Node(None, None)
# key: i (for ith finger), value: (start, Node node)
FINGERS = dict()
# successor_list = []

# USER FUNCTIONS

# find the successor node of an ID on the Chord ring
def find_successor(ID):
	# print '(find_successor): finding successor of ' + str(ID)
	node = find_predecessor(ID)
	# print '(find_successor): predecessor of ' + str(ID) + ' is ' + str(node.ID)

	succ = None
	if node.IP == NODE.IP:
		succ = SUCCESSOR
	else:
		r = requests.get('http://' + node.IP + ':5000/successor')
		# LOOP X TIMES??
		if r.status_code != 200:
			raise Exception('/succesor to ' + node.IP + ' failed')

		data = r.json()
		succ = Node(data["ip"], int(data["id"]))
	return succ

def find_predecessor(ID):
	global NODE, SUCCESSOR
	node = NODE
	found = False
	while not found:
		# find [node]'s successor
		succ = None
		if node == NODE:
			succ = SUCCESSOR
		else:
			r = requests.get('http://' + node.IP + ':5000/successor')
			if r.status_code != 200:
				raise Exception('/succesor to ' + node.IP + ' failed')
			data = r.json()
			succ = Node(data["ip"], int(data["id"]))
		# check if [node] is [ID]'s predecessor
		# print '(find_predecessor): successor of node ' + str(node.ID) + ' is ' + str(succ.ID)
		if between(node.ID + 1, succ.ID, ID):
			# print str(ID) + ' is between ' + str(node.ID + 1) + ' and ' + str(succ.ID)
			found = True
		else:
			if node == NODE:
				node = find_closest_preceding_finger(ID)
			else:
				r = requests.post('http://' + node.IP + ':5000/closest_preceding_finger', json={'id': ID})
				if r.status_code != 200:
					raise Exception('/closest_preceding_finger to ' + node.IP + ' failed')
				data = r.json()
				node = Node(data["ip"], int(data["id"]))
	return node

def find_closest_preceding_finger(ID):
	global NODE, FINGERS, IDBITS
	# loops from IDBITS to 1
	for i in range(IDBITS, 0, -1):
		ith_finger = FINGERS[i][1]
		if between(NODE.ID + 1, ID - 1, ith_finger.ID):
			return ith_finger
	return NODE

@node.route("/")
def main():
	render_template("index.html")

# TO DO: MAKE /exist POST function to check if a node already exists.NEIGHBORS

@node.route("/join", methods=["POST", "GET"])
def join():
	# Generate ID for the node.
	global NODE
	NODE.ID = genID(False)
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
			NEIGHBORS.append(host)
			counter += 1
	if len(NEIGHBORS) > 0:
		idTaken = False
		print "This is our list of NEIGHBORS"
		print NEIGHBORS
		for neighbor in NEIGHBORS:
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

@node.route("/leave", methods=["POST"])
def leave():
	# Let the nodes on your table know that you are leaving
	# through a POST request.
	return "<h1>You have successfully exited chord.</h1>"

@app.route("/search", methods=["POST"]) # This will be a GET request.
def search():
	return "FILE"

@app.route("/upload") # I'll figure this out tonight.
def upload():
	return "FILE UPLOADED"

# END OF USER FUNCTIONS


# CHORD FUNCTIONS

@app.route("/successor", methods=["GET"])
def find_succesor_api():
	global SUCCESSOR
	resp = jsonify({
		"ip": SUCCESSOR.IP,
		"id": SUCCESSOR.ID
	})
	resp.status_code = 200
	return resp

@app.route("/predecessor")
def findPred():
	return predecessor

# Finds closest preceding finger.
@app.route("/closest_preceding_finger", methods=["POST"])
def find_closest_preceding_finger_api():
	data = request.get_json()
	closest_preceding_finger = find_closest_preceding_finger(data["id"])
	resp = jsonify({
		"ip": closest_preceding_finger.IP,
		"id": closest_preceding_finger.ID,
	})
	resp.status_code = 200
	return resp

@app.route("/stabilize")
def stabilize():
	return "peace"

@app.route("/notify")
def notify():
	return "notify"

@app.route("/fix_finger")
def fixFinger():
	return "finger"

# Fix this thing to ensure that it generates different IDs.
# For now, it's returning 0.0
def genID(addRandom):
    hostname = socket.gethostname()
    IP = socket.gethostbyname(hostname)
    hashIP = hashlib.sha1(IP)
    hexString = str(int(hashIP.hexdigest(), 16))
    decimal = 0
    for index,char in enumerate(hexString):
        decimal += int (char) * 16 ** index
    if (addRandom):
        decimal += random.randint(1, (2**idBits))
    ID = decimal % (2 ** 3)
    return str(ID)

# checks if ID c is (inclusive) between a & b in the Chord ring
def between(a, b, c):
	if b > a:
		return a <= c and c <= b
	elif a > b:
		return c >= a or c <= b
	else:
		return a == c

# END OF CHORD FUNCTIONS

if __name__ == "__main__":
	if len(sys.argv) > 1:
		if sys.argv[1] == 'hardcode':
			with open('state' + sys.argv[2] + '.csv', 'rb') as f:
				reader = csv.reader(f)
				arg_list = list(reader)
				for idx, arg in enumerate(arg_list):
					# NOTE: IP comes before ID in Node initialization
					if len(arg) == 3:
						start, ID, IP = arg
						FINGERS[idx + 1] = (int(start), Node(IP.strip(), int(ID)))
					elif len(arg) == 2:
						ID, IP = arg
						NODE = Node(IP.strip(), int(ID))
				SUCCESSOR = (FINGERS[1])[1]
	# print FINGERS
	# print SUCCESSOR.ID
	# print NODE.ID

	if NODE.ID == 3:
		for i in range(0, 8):
			node = find_successor(i)
			print 'Successor of ' + str(i) + ' is ' + str(node.ID)

	app.debug = True
	app.run(host="0.0.0.0", port=5000)
