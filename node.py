from flask import Flask, request, render_template, jsonify
from werkzeug.utils import secure_filename
import sys, math, os
import hashlib
import requests
import socket
import time
import nmap
import random
import requests
import csv
import threading

# convert 'raise Exception' to 'print' because don't want Node to crash due to network problems

UPLOAD_FOLDER = "static/uploads"
ALLOWED_EXTENSIONS = set(['txt', 'pdf', 'png', 'jpg', 'jpeg'])

app = Flask(__name__)
app.secret_key = "Distribyed4Lyfe"
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# [IP]: string
# [ID]: integer
class Node:
	def __init__(self, IP, ID):
		self.IP = IP
		self.ID = ID
		self.FILES = {}

@app.route("/", methods=["GET"])
def home():
	return render_template("index.html")

# Depending on how long the functions become, we could separate this
# into two files. One containing user functions, and the other one
# with Chord functions only.

# USER VARIABLES
START_TIME = time.time()
NEIGHBORS = []
NODE = Node(None, None)

# CHORD VARIABLES
IDBITS = 3   		# Number of bits for ID
SUCCESSOR = Node(None, None)
PREDECESSOR = Node(None, None)
# key: i (for ith finger), value: (start, Node node)
FINGERS = dict()
MAX_RETRIES = 5
# successor_list = []

# CORE
# Find the successor node of an ID on the Chord ring
def find_successor(ID):
	# print '(Node' + str(NODE.ID) + ':find_successor): finding successor of ' + str(ID)
	node = find_predecessor(ID)
	if null_node(node):
		return Node(None, None)

	succ = None
	if node.IP == NODE.IP:
		succ = SUCCESSOR
	else:
		data, result = make_http_request(node.IP, 'successor', 'GET', None)
		if not result:
			return Node(None, None)

		succ = Node(data["ip"], int(data["id"]))
	# print '(Node' + str(NODE.ID) + ':find_successor): successor of ' + str(ID) + ' is ' + str(succ.ID)
	return succ

def find_predecessor(ID):
	global NODE, SUCCESSOR
	# print '(Node' + str(NODE.ID) + ':find_predecessor): finding predecessor of ' + str(ID)

	node = NODE
	found = False
	while not found:
		# find [node]'s successor
		succ = None
		if node == NODE:
			succ = SUCCESSOR
		else:
			data, result = make_http_request(node.IP, 'successor', 'GET', None)
			if not result:
				return Node(None, None)

			succ = Node(data["ip"], int(data["id"]))

		# check if [node] is [ID]'s predecessor
		# print '(find_predecessor): successor of node ' + str(node.ID) + ' is ' + str(succ.ID)
		if between(next_ID(node.ID), succ.ID, ID):
			# print str(ID) + ' is between ' + str(node.ID + 1) + ' and ' + str(succ.ID)
			found = True
		else:
			if node == NODE:
				node = find_closest_preceding_finger(ID)
			else:
				data, result = make_http_request(node.IP, 'closest_preceding_finger', 'POST', {'id': ID})
				if not result:
					return Node(None, None)

				node = Node(data["ip"], int(data["id"]))

	# print '(Node' + str(NODE.ID) + ':find_predecessor): predecessor of ' + str(ID) + ' is ' + str(node.ID)
	return node

def find_closest_preceding_finger(ID):
	# loops from IDBITS to 1
	for i in range(IDBITS, 0, -1):
		ith_finger = FINGERS[i][1]
		# e.g x = 4, y = 5 or 4, then there does not exist a z that could
		# be exclusive between 4 & 5
		invalid = next_ID(NODE.ID) == ID
		if not invalid and between(next_ID(NODE.ID), prev_ID(ID), ith_finger.ID):
			return ith_finger
	return NODE

# STABILIZATION
def fix_fingers():
	global FINGERS
	# print_finger_table('Before fixing fingers')
	idx = random.randint(1, IDBITS)
	new_succ = find_successor(FINGERS[idx][0])
	if not null_node(new_succ):
		start = FINGERS[idx][0]
		FINGERS[idx] = (start, new_succ)
	# print_finger_table('Before fixing fingers')

def run_fix_fingers():
	while True:
		# print_finger_table('Before fix_fingers')
		fix_fingers()
		print_finger_table('After [fix_fingers]')
		print_succ_pred()
		time.sleep(10)

def stabilize():
	global SUCCESSOR
	# find the successor node's predecessor
	data, pred_result = make_http_request(SUCCESSOR.IP, 'predecessor', 'GET', None)
	if not pred_result:
		found_new_succ = False
		# try and find new successor by going through ring in clockwise order
		# and finding the first ID whose predecessor can be found

		for ID in circular_range(SUCCESSOR.ID):
			new_succ = find_predecessor(ID)
			if not null_node(new_succ):
				found_new_succ = True
				print 'New successor is ' + str(new_succ.ID)
				SUCCESSOR = new_succ
				break

		# could not find node's new successor
		if not found_new_succ:
			# for now, raise exception
			print '==================================='
			print 'WARNING: Could not update successor'
			print '==================================='
			return



		data, pred_result = make_http_request(SUCCESSOR.IP, 'predecessor', 'GET', None)
		# node's new successor also cannot be contacted
		if not pred_result:
			print 'Failed to contact new successor ' + SUCCESSOR.IP
			return

	# node is our successor's predecessor
	succ_pred = Node(data["ip"], int(data["id"]))

	# if our successor's predecessor is between us
	invalid = next_ID(NODE.ID) == SUCCESSOR.ID
	if not invalid and between(next_ID(NODE.ID), prev_ID(SUCCESSOR.ID), succ_pred.ID):
		print 'New successor is ' + str(succ_pred.ID)
		SUCCESSOR = succ_pred

	# notify successor of our existence
	data, notify_result = make_http_request(SUCCESSOR.IP, 'notify', 'POST', {'id': NODE.ID, 'ip': NODE.IP})
	if not notify_result:
		print 'Failed to notify ' + str(SUCCESSOR.ID)

	# print 'Successor is ' + str(SUCCESSOR.ID)

def run_stabilize():
	while True:
		# print_finger_table('Before stabilize')
		print '============[stabilize]=============='
		stabilize()
		print '====================================='
		# print_finger_table('After stabilize')
		time.sleep(10)

def notify(node):
	global PREDECESSOR

	# no predecessor
	if PREDECESSOR.IP == None and PREDECESSOR.ID == None:
		print 'New predecessor is ' + str(node.ID)
		PREDECESSOR = node

	invalid = next_ID(PREDECESSOR.ID) == NODE.ID
	if not invalid and between(next_ID(PREDECESSOR.ID), prev_ID(NODE.ID), node.ID):
		print 'New predecessor is ' + str(node.ID)
		PREDECESSOR = node
	# print 'PREDECESSOR is ' + str(PREDECESSOR.ID)



@app.route("/join", methods=["POST", "GET"])
def join():
	# Generate ID for the node.
	global NODE
	NODE.ID = genID(False)
	# Scan the network to look for other active Chord nodes.
	nm = nmap.PortScanner()
	# We are assuming the protocol used is IPv4
 	address = socket.gethostname() + "/24"
	nm.scan(hosts=address, arguments="-p5000")
	counter = 0
	for host in nm.all_hosts():
		# Do not add more than 5 nodes.
		if (counter > 4):
			break
		if nm[host]['tcp'][5000]['state'] == "open":
			NEIGHBORS.append(host)
			counter += 1
	if len(NEIGHBORS) > 0:
		idTaken = False
		# print "This is our list of NEIGHBORS"
		# print NEIGHBORS
		for neighbor in NEIGHBORS:
			try:
				r = ""
				r = requests.post("http://" + neighbor + ":5000/exist",
										 data={'id':NODE.ID}, timeout=5)
				if (not (r == "")):
					#print "the request is not empty"
					# print r.text 	   # For debugging purposes.
					if r.text == "YES": # The node already exists.
						idTaken = True
						break;
			except requests.exceptions.RequestException as e:
				print e
		if (idTaken):
			# changeID()
			#print "THE ID IS TAKEN"
			return "Generate a new ID"
		else:
			# makeFingers() # Make the finger table! :D
			#print "WELCOME TO CHORD"
			return "Welcome to CHORD"
	else:
		return "<h1>You are the only chord node in the network</h1>"

# Returns "YES" if the ID has already been taken
# and "NO" otherwise.
@app.route("/exist", methods=["POST"])
def exist():
	# Check if the request is correctly made.
	# and send an error otherwise.
	recID = request.form['id']
	print "THIS IS THE RECEIVED ID " + str(recID)
	return "YES"

@app.route("/leave", methods=["POST"])
def leave():
	# Let the nodes on your table know that you are leaving
	# through a POST request.
	return "<h1>You have successfully exited chord.</h1>"

# Function to verify that the file looked up/ downloaded
# has one of the allowed extensions.
def allowed_file(filename):
	return '.' in filename and filename.rsplit('.',1)[1].lower() in ALLOWED_EXTENSIONS

@app.route("/searchFile", methods=["POST"])
def search():
	fileName = request.form.get("fileName", None)
	# Hash the name of the file.
	# Check if we already have the file on the uploads folder
	# or in the downloads folder.
	# 	if we already have it, return its location
	# else
	# 	Determine which node should have the file.
	# 	Use the finger table to get to that node.
	# Once you get the file, hash it, and save it in the
	# file dictionary.
	return "FILE"

@app.route("/upload", methods=["POST"])
def upload():
	successFiles = []
	files = request.files.getlist("file[]")
	for file in files:
		if  file and allowed_file(file.filename):
			filename = secure_filename(file.filename)
			file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
			successFiles.append(file.filename)
	if (not successFiles):
		return render_template("uploaded.html", successFiles=None)
	processUFiles(successFiles)
	return render_template("uploaded.html", successFiles=successFiles)

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

@app.route("/predecessor", methods=["GET"])
def find_predecessor_api():
	if null_node(PREDECESSOR):
		resp = jsonify({})
		resp.status_code = 404
		return resp
	else:
		resp = jsonify({
			"ip": PREDECESSOR.IP,
			"id": PREDECESSOR.ID
		})
		resp.status_code = 200
		return resp

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

@app.route("/notify", methods=["POST"])
def notify_api():
	data = request.get_json()
	node = Node(data["ip"], data["id"])
	notify(node)

	resp = jsonify({})
	resp.status_code = 200
	return resp

@app.route("/fingers", methods=["GET"])
def print_fingers():
	for key in FINGERS.keys():
		print 'Finger ' + str(key) + ': Start: ' + str(FINGERS[key][0]) + ', Node: ' +str(FINGERS[key][1].ID)
	resp = jsonify({})
	resp.status_code = 200
	return resp

# This function will receive a file, and it
# will determine whether this node should keep it
# or send it to the appropriate node.
@app.route("/receiveFile")
def recFile(info):
	assert "nodeID" in request.form
	assert "fileName" in request.form
	assert request.form["fileName"] in request.files
 	# Check if this is correct.
	nodeID = request.form["nodeID"]
	fileName = request.form["fileName"]
	if nodeID == NODE.ID:
		# Keep the file.
		with codecs.open(os.path.join(app.config['UPLOAD_FOLDER'], fileName)) as f:
			f.write(request.files['fileName'])
	else:
		# Try to figure out if the correct node exists.
		sendNode = 0
		for i in range(0,3):
			interval = ((fingers.get(i))[0], (fingers.get(i))[0] + 2**i)
			if between(interval[0], interval[1], nodeID):
				sendNode = (fingers.get(i))[1]
				break;
		# Three options:
		# This is the only node in the interval. The
		# correct node does not exist. (nodeID = chord(fileName))
		if sendNode != NODE.ID:
			address = "http://" + sendNode.IP + ":5000/receiveFile"
			try:
				req = requests.post(address, data={'nodeID':nodeID, 'fileName':fileName},
									 files={fileName: request.files['fileName']})
				if r.status_code != 200:
					raise Exception("Finger" + finger + "did not receive the file correctly.")
			except requests.exceptions.RequestException as e:
				print e

# addRandom -> boolean
# Use addRandom = True whenever you need to generate
# a new ID if the one generated first was already taken.
>>>>>>> Fire stabilize, fix_fingers periodically; Fixing bugs (stabilize is still broken)
def genID(addRandom):
    hostname = socket.gethostname()
    IP = socket.gethostbyname(hostname)
    hashIP = hashlib.sha1(IP)
    hexString = str(int(hashIP.hexdigest(), 16))
    decimal = 0
    for index,char in enumerate(hexString):
        decimal += int (char) * 16 ** index
    if (addRandom):
        decimal += random.randint(1, (2**IDBITS))
    ID = decimal % (2 ** 3)
    return ID

# This function maps a file to a node.
def chord(filename):
	hashFile = hashlib.sha1(filename)
	hexString = str(int(hashFile.hexdigest(), 16))
	decimal = 0
	for index,char in enumerate(hexString):
		decimal += int (char) * 16 ** index
	node = decimal % (2 ** 3)
	return node


# Sends uploaded files to their respective nodes.
def processUFiles(files):
	for file in files:
		# Save the files in NODE's list of files.
		# To provide redundancy, keep a copy of the file and its key.
		# This will make lookup a bit faster, and if the node leaves,
		# someone will still have the file.
		NODE.FILES[hashlib.sha1(file.filename)] = "uploads"
		# Find where the file should be sent to.
		node = chord(file.filename)
		print "CHORD HAS ASSIGNED THE FILE TO NODE: ",
		print node
		sendNode = node
		if node != NODE.ID:
			for i in range(0,3):
				interval = ((fingers.get(i))[0], (fingers.get(i))[0] + 2**i)
				if between(interval[0], interval[1], node):
					sendNode = (fingers.get(i))[1]
					break;
			address = "http://" + sendNode.IP + ":5000/receiveFile" #
			# Send the file to node.
			print "THE FILE WILL BE SENT TO NODE: ",
			print sendNode
			with open(os.path.join(app.config['UPLOAD_FOLDER'], file.filename)) as f:
				try:
					r = requests.post(address, data={'nodeID':node, 'fileName':file.filename},
										files={file.filename: f}, timeout=5)
					if r.status_code != 200:
						raise Exception("Finger" + finger + "did not receive the file correctly.")
				except requests.exceptions.RequestException as e:
					print finger + "could not be reached."


def make_http_request(target, endpoint, method, payload):
	tries = 0
	while tries < MAX_RETRIES:
		try:
			if method.upper() == 'GET':
				r = requests.get('http://' + target + ':5000/' + endpoint)
			elif method.upper() == 'POST':
				r = requests.post('http://' + target + ':5000/' + endpoint, json=payload)
			if r.status_code == 200:
				return (r.json(), True)
		except:
			pass
			# print 'Failed to establish connection with ' + str(target)

		tries += 1
	return (None, False)

# checks if ID c is (inclusive) between a & b in the Chord ring
def between(a, b, c):
	if b > a:
		return a <= c and c <= b
	elif a > b:
		return c >= a or c <= b
	else:
		return a == c

# return next ID on the Chord ring
def next_ID(ID):
	return ID + 1 if ID != math.pow(2, IDBITS) - 1 else 0

# return previous ID on the Chord ring
def prev_ID(ID):
	return ID - 1 if ID != 0 else math.pow(2, IDBITS) - 1

def circular_range(start):
	l = []
	ring_size = int(math.pow(2, IDBITS))
	for i in range(1, ring_size):
		l.append((start + i) % ring_size)
	return l

def null_node(node):
	return node.ID == None and node.IP == None

def print_finger_table(msg):
	print msg
	for key in FINGERS.keys():
		print 'Finger ' + str(key) + ': Start: ' + str(FINGERS[key][0]) + ', Node: ' +str(FINGERS[key][1].ID)

def print_succ_pred(msg):
	if msg:
		print msg
	print 'Successor: ' + str(SUCCESSOR.ID) + ', Predecessor: ' + str(PREDECESSOR.ID)

# END OF CHORD FUNCTIONS
# def job1():
# 	tries = 0
# 	while tries < 4:
# 		print 'Are we there yet?'
# 		time.sleep(5)
# 		tries += 1
#
# def job2():
# 	tries = 0
# 	while tries < 2:
# 		print 'No.'
# 		time.sleep(10)
# 		tries += 1
# 		print FINGERS

if __name__ == "__main__":
	if len(sys.argv) > 1:
		if sys.argv[1] == 'demo':
			assigned_node = False
			with open('state' + sys.argv[2] + '.csv', 'rb') as f:
				reader = csv.reader(f)
				arg_list = list(reader)
				for idx, arg in enumerate(arg_list):
					# NOTE: IP comes before ID in Node initialization
					if len(arg) == 3:
						start, ID, IP = arg
						FINGERS[idx + 1] = (int(start), Node(IP.strip(), int(ID)))
					elif len(arg) == 2:
						if not assigned_node:
							ID, IP = arg
							NODE = Node(IP.strip(), int(ID))
							assigned_node = True
						else:
							ID, IP = arg
							PREDECESSOR = Node(IP.strip(), int(ID))

				SUCCESSOR = (FINGERS[1])[1]

		if NODE.ID == 3 and sys.argv[3] == 'search':
			for i in range(0, 8):
				node = find_successor(i)
				print 'File w/ key' + str(i) + ' is in ' + str(node.ID)

		if sys.argv[3] == 'join':
			print_finger_table('Finger table on joining')

			# schedule [stabilize] and [fix_fingers] to run periodically
			t1 = threading.Thread(target=run_stabilize)
			t1.daemon = True
			t1.start()

			t2 = threading.Thread(target=run_fix_fingers)
			t2.daemon = True
			t2.start()

	# app.debug = True
	app.run(host="0.0.0.0", port=5000)
