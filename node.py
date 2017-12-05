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

# The uploads folder will contain all the files
# that the user has decided to share with other nodes.
# These files are searchable.
UPLOAD_FOLDER = "static/uploads"
# The downloads folder will contain all the files
# that the user has downloaded or received form other nodes.
DOWNLOAD_FOLDER = "static/downloads"
ALLOWED_EXTENSIONS = set(['txt', 'pdf', 'png', 'jpg', 'jpeg'])

app = Flask(__name__)
app.secret_key = "Distributed4Lyfe"
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# [IP]: string
# [ID]: integer
class Node:
	def __init__(self, IP, ID):
		self.IP = IP
		if ID == None:
			self.ID = None
		else:
			self.ID = int(ID)
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
INITIALIZED = False
# successor_list = []

# CORE
# Find the successor node of an ID on the Chord ring
def find_successor(ID):
	# print '(Node' + str(NODE.ID) + ':find_successor): finding successor of ' + str(ID)
	print 'calling [find_predecessor] from [find_successor]'
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
		print '(find_predecessor): check if ' + str(ID) + ' is between ' +  str(next_ID(node.ID)) + ' and ' + str(succ.ID)
		if between(next_ID(node.ID), succ.ID, ID):
			# print str(ID) + ' is between ' + str(node.ID + 1) + ' and ' + str(succ.ID)
			found = True
		else:
			# if next_ID(node.ID) == 2 and succ.ID == 2 and ID == 5:
			# 	raise Exception('ABORT!')

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
	for i in xrange(IDBITS, 0, -1):
		ith_finger = FINGERS[i][1]
		# e.g x = 4, y = 5 or 4, then there does not exist a z that could
		# be exclusive between 4 & 5
		invalid = next_ID(NODE.ID) == ID
		print '[find_closest_preceding_finger] Is finger ' + str(i) + ': ' + str(ith_finger.ID) + ' between ' + str(next_ID(NODE.ID)) + ' and ' + str(prev_ID(ID))
		if not invalid and between(next_ID(NODE.ID), prev_ID(ID), ith_finger.ID):
			return ith_finger
	return NODE

# STABILIZATION
def fix_fingers():
	global FINGERS
	idx = random.randint(1, IDBITS)
	print 'Check if finger ' + str(idx) + ' needs to be fixed'
	new_succ = find_successor(FINGERS[idx][0])
	if not null_node(new_succ):
		start = FINGERS[idx][0]
		print 'Finger ' + str(idx) + ' is now Node ' + str(new_succ.ID)
		FINGERS[idx] = (start, new_succ)

def run_fix_fingers():
	while True:
		time.sleep(10)
		if not INITIALIZED:
			continue
		# print_finger_table('Before fix_fingers')
		print '============[fix_fingers]=============='
		fix_fingers()
		print '======================================='
		print_finger_table('After [fix_fingers]')
		print_succ_pred()

def node_exists(node):
	data, result = make_http_request(node.IP, 'ping', 'GET', None)
	print '[node_exists/ping] node ' + str(node.ID) + ' exists: ' + str(result)
	return result

def stabilize():
	global SUCCESSOR, PREDECESSOR

	# node is 1st node in network
	if SUCCESSOR.ID == NODE.ID:
		print '[stabilize] SUCCESSOR.ID == NODE.ID'
		data = {"id": PREDECESSOR.ID, "ip": PREDECESSOR.IP}
		pred_result = True
	# find the successor node's predecessor
	else:
		print '[stabilize] SUCCESSOR.ID != NODE.ID'
		data, pred_result = make_http_request(SUCCESSOR.IP, 'predecessor', 'GET', None)

	# successor has left; find new successor
	if not pred_result:
		print '[stabilize] successor has left, trying to find new successor'
		found_new_succ = False
		# try and find new successor by going through ring in clockwise order
		# and finding the first ID whose predecessor can be found

		for ID in circular_range(SUCCESSOR.ID):
			old_succ = SUCCESSOR
			print 'calling [find_predecessor] from stabilize'
			new_succ = find_predecessor(ID)
			if not null_node(new_succ):
				found_new_succ = True
				if node_exists(new_succ):
					print 'New successor is ' + str(new_succ.ID)
					SUCCESSOR = new_succ
					FINGERS[1] = (FINGERS[1][0], SUCCESSOR)

				# "fixing the gap" (i.e successor & predecessor of the leaving node fixing their predecessor & successor)
				# has to be atomic BUT NO NEED TO BE ATOMIC IF SUCCESSOR IS YOURSELF
				if SUCCESSOR.ID != NODE.ID:
					data, notify_result = make_http_request(SUCCESSOR.IP, 'notify', 'POST', {'id': NODE.ID, 'ip': NODE.IP})
					if not notify_result:
						print 'Failed to notify ' + str(SUCCESSOR.ID)
						SUCCESSOR = old_succ
						FINGERS[1] = (FINGERS[1][0], SUCCESSOR)

				return

		# could not find node's new successor
		if not found_new_succ:
			# for now, raise exception
			print '==================================='
			print 'WARNING: Could not update successor'
			print '==================================='
			return
	# check if successor has a new predecessor in between us & the successor
	else:
		# node is our successor's predecessor
		succ_pred = Node(data["ip"], data["id"])

		# ===========================================
		# If [succ_pred] is NULL, immediately notify [succ]
		if not null_node(succ_pred):
			# if our successor's predecessor is between us
			invalid = next_ID(NODE.ID) == SUCCESSOR.ID
			if not invalid and between(next_ID(NODE.ID), prev_ID(SUCCESSOR.ID), succ_pred.ID):
				if node_exists(succ_pred):
					print 'New successor is ' + str(succ_pred.ID)
					SUCCESSOR = succ_pred
					FINGERS[1] = (FINGERS[1][0], SUCCESSOR)
		# ===========================================

		# invalid = next_ID(NODE.ID) == SUCCESSOR.ID
		# if not invalid and between(next_ID(NODE.ID), prev_ID(SUCCESSOR.ID), succ_pred.ID):
		# 	print 'New successor is ' + str(succ_pred.ID)
		# 	SUCCESSOR = succ_pred

		# notify successor of our existence
		if SUCCESSOR.ID == NODE.ID:
			PREDECESSOR = NODE
		else:
			data, notify_result = make_http_request(SUCCESSOR.IP, 'notify', 'POST', {'id': NODE.ID, 'ip': NODE.IP})
			if not notify_result:
				print 'Failed to notify ' + str(SUCCESSOR.ID)

	# print 'Successor is ' + str(SUCCESSOR.ID)

def run_stabilize():
	while True:
		time.sleep(10)
		if not INITIALIZED:
			continue
		# print_finger_table('Before stabilize')
		print '============[stabilize]=============='
		stabilize()
		print '====================================='
		# print_finger_table('After stabilize')

def notify(node):
	global PREDECESSOR

	# no predecessor
	if PREDECESSOR.IP == None and PREDECESSOR.ID == None:
		print 'New predecessor is ' + str(node.ID)
		PREDECESSOR = node

	data, result = make_http_request(PREDECESSOR.IP, 'ping','GET', None)
	print '[node_exists/ping] node ' + str(node.ID) + ' exists: ' + str(result)

	if not result:
		print 'New predecessor is ' + str(node.ID)
		PREDECESSOR = node

	invalid = next_ID(PREDECESSOR.ID) == NODE.ID
	if not invalid and between(next_ID(PREDECESSOR.ID), prev_ID(NODE.ID), node.ID):
		print 'New predecessor is ' + str(node.ID)
		PREDECESSOR = node
	# print 'PREDECESSOR is ' + str(PREDECESSOR.ID)

# def no_neighbors():
# 	if len(NEIGHBORS) == 0:
# 		return True
#
# 	for neighbor in NEIGHBORS:
# 		data, result = make_http_request(neighbor, 'init_status', 'GET', None)
# 		if result and data["initialized"]:
# 			return False
#
# 	return True

@app.route("/init_status", methods=["GET"])
def handle_init_status():
	resp = jsonify({
		"initialized": INITIALIZED
	})
	resp.status_code = 200
	return resp

@app.route("/join", methods=["POST", "GET"])
def join():
	print '[join] Kicked off process to join'
	# Generate ID for the node.
	global NODE, INITIALIZED, SUCCESSOR, NEIGHBORS
	NEIGHBORS = []
	NODE.IP = socket.gethostbyname(socket.gethostname())

	# Scan the network to look for other active Chord nodes.
	nm = nmap.PortScanner()
	# We are assuming the protocol used is IPv4
 	address = socket.gethostname() + "/24"
	nm.scan(hosts=address, arguments="-p5000")
	counter = 0
	for host in nm.all_hosts():
		if host == NODE.IP:
			continue
		# Do not add more than 5 nodes.
		if (counter > 4):
			break
		if nm[host]['tcp'][5000]['state'] == "open":
			# only add hosts if they are INITIALIZED CHORD NODES, not just online
			data, result = make_http_request(host, 'init_status', 'GET', None)
			if result and data["initialized"]:
				NEIGHBORS.append(host)
				counter += 1

	print '[join] ' + str(len(NEIGHBORS)) + ' are online'
	if len(NEIGHBORS) == 0:
		NODE.ID = genID(False)
		SUCCESSOR = NODE
		makeFingers() # Make the finger table! :D
		INITIALIZED = True
		return "<h1>You are the only chord node in the network</h1>"

	idTaken = True
	tries = 0
	NODE.ID = genID(False)

	while idTaken and tries < 10:
		for neighbor in NEIGHBORS:
			data, result = make_http_request(neighbor, 'successor', 'POST', {'id': NODE.ID})
			# if neighbor tells us successor of ID = Node.ID is not ID then there is no node
			# w/ ID = Node.ID and we can take the ID for ourselves
			if result:
				if data["id"] != NODE.ID:
					idTaken = False
				break

		if idTaken:
			# try a new ID
			NODE.ID = genID(True)
			tries += 1

	# if we pick [IDBITS] such that math.pow(2, [IDBITS]) > #(Zoo machines), then if [idTaken]
	# is still true at this point, neighbors all failed in setting up our ID
	if idTaken:
		return "<h1>Failed to join! Please try to join again in a bit.</h1>"

	SUCCESSOR = Node(data["ip"], data["id"])
	makeFingers() # Make the finger table! :D
	INITIALIZED = True
	return "Welcome to CHORD"

def makeFingers():
	for i in range(1, IDBITS + 1):
		start = (NODE.ID + math.pow(2, i-1)) % math.pow(2, IDBITS)
		FINGERS[i] = (start, SUCCESSOR)

@app.route("/ping", methods=["GET"])
def ping():
	resp = jsonify({})
	resp.status_code = 200
	return resp

@app.route("/leave", methods=["POST"])
def leave():
	# MOVE FILES

	# Let the nodes on your table know that you are leaving
	# through a POST request.
	# ======================== DO WE EVEN NEED THIS? MORE ROBUST TO RELY ON STABILIZE ==============================
	# make_http_request(PREDECESSOR.ID, 'leave_notice', 'POST', {'node_leaving': 'SUCCESSOR', 'ip': SUCCESSOR.IP, 'id': SUCCESSOR.ID})
	# make_http_request(SUCCESSOR.ID, 'leave_notice', 'POST', {'node_leaving': 'PREDECESSOR', 'ip': PREDECESSOR.IP, 'id': PREDECESSOR.ID})
	return "<h1>You have successfully exited chord.</h1>"

# @app.route("/leave_notice", methods=["POST"])
# def handle_leave_notice():
# 	data = request.get_json()
# 	IP, ID, node_leaving = data["ip"], data["id"], data["node_leaving"]
# 	if node_leaving.upper() == 'SUCCESSOR':
# 		SUCCESSOR = Node(IP, ID)
# 	elif node_leaving.upper() == 'PREDECESSOR':
# 		PREDECESSOR = Node(IP, ID)

# Function to verify that the file looked up/ downloaded
# has one of the allowed extensions.
def allowed_file(filename):
	return '.' in filename and filename.rsplit('.',1)[1].lower() in ALLOWED_EXTENSIONS

@app.route("/searchFile", methods=["POST"])
def search():
	if "fileName" not in request.form:
		resp = jsonify({})
		resp.status_code = 404
		return resp
	fileName = request.form.get("fileName", None)
	if not fileName:
		return "No file name typed."
	hashFile = hashlib.sha1(fileName)
	if hashFile in NODE.FILES:
		return "You already have this file and it's in downloads or uploads. LOL"
	else:
		node = chord(fileName)
		successor = find_successor(node)
		try:
			req = requests.post(address, data={'fileName':fileName,}, timeout=15)
			if req.status_code == 200:
				file = request.files[fileName]
				file.save(os.path.join(app.config['DOWNLOAD_FOLDER'], fileName))
				NODE.FILES[hashlib.sha1(fileName)] = "downloads"
				return "FILE DOWNLOADED AND SHIT"
			elif req.status_code == 400:
				return "The request did not arrive correctly."
			elif req.status_code == 404:
				return "The file does not exist in the system"
			# Use the status code to determine the output in jinja.
		except requests.exceptions.RequestException as e:
			print e
			run_stabilize()
			return "COULD NOT DOWNLOAD THE FILE" # We need to do something if this fails


@app.route("/upload", methods=["POST"])
def upload():
	uploadFiles = []
	failure = False
	files = request.files.getlist("file[]")
	for file in files:
		if  file and allowed_file(file.filename):
			filename = secure_filename(file.filename)
			file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
			uploadFiles.append(file.filename)
	if (not uploadFiles):
		return render_template("uploaded.html", successFiles=None, failure=failure)
	successFiles = processUFiles(uploadFiles)
	if len(successFiles) == 0:
		failure = True
	return render_template("uploaded.html", successFiles=successFiles, failure=failure)

# END OF USER FUNCTIONS


# CHORD FUNCTIONS

@app.route("/successor", methods=["GET", "POST"])
def find_succesor_api():
	global SUCCESSOR
	if request.method == 'GET':
		resp = jsonify({
			"ip": SUCCESSOR.IP,
			"id": SUCCESSOR.ID
		})
		resp.status_code = 200
		return resp
	elif request.method == 'POST':
		data = request.get_json()
		node = find_successor(data["id"])
		if null_node(node):
			resp = jsonify({})
			resp.status_code = 404
			return resp

		resp = jsonify({
			"ip": node.IP,
			"id": node.ID
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
@app.route("/receiveFile", methods=["POST"])
def recFile():
	assert "nodeID" in request.form
	assert "fileName" in request.form
 	# Check if this is correct.
	nodeID = int(request.form["nodeID"]) # File destination
	fileName = request.form["fileName"]
	sender = int(request.form["sender"])
	keepFile = True
	if nodeID != NODE.ID:
		print "WE ARE NOT THE DESTINATION OF THE FILE"
		# Check if we are the successor of the goal node.
		# if we are not, then there is a node ahead of us that
		# is closer to the node we are aiming for.
		if not between(sender, NODE.ID, nodeID):
			print "WE ARE NOT THE SUCCESSOR OF THE GOAL NODE"
			# Send it to successor within the range of the
			# correct file owner node.
			sendNode = None
			for i in xrange(0,IDBITS):
				interval = (FINGERS[i][0], (FINGERS[i][0] + 2**i) % 2**IDBITS)
				if between(interval[0], interval[1], nodeID):
					sendNode = FINGERS[i][1]
					break;
			if sendNode.ID != NODE.ID:   # we could be the successor in the interval of the right node owner
				keepFile = False
				address = "http://" + sendNode.IP + ":5000/receiveFile"
				try:
					file = request.files[fileName]
					req = requests.post(address, data={'nodeID':nodeID, 'fileName':fileName,
								'sender':str(NODE.ID)}, files={fileName: file}, timeout=15)
					if req.status_code != 200:
						print req.text
						return "FAILURE"
					print req.text
					return "SUCESS"
				except requests.exceptions.RequestException as e:
					print e
					# Call stabilize to update the finger tables.
					run_stabilize()
					return "FAILURE" # We need to do something if this fails.
		# else:
		# 	print "WE ARE THE SUCCESSOR OF THE GOAL NODE"
	if keepFile:
		file = request.files[fileName]
		file.save(os.path.join(app.config['DOWNLOAD_FOLDER'], fileName))
		NODE.FILES[hashlib.sha1(fileName)] = "downloads"
		return "SUCCESS"

@app.route("/fileRequest", methods=["POST"])
def fileRequest():
	# Check that the request is valid.
	if "fileName" not in request.form:
		resp = jsonify({})
		resp.status_code = 400 # Bad request
		return resp
	# Check if we actually have the file.
	if os.path.isfile(os.path.join(app.config['UPLOAD_FOLDER'], fileName)):
		with open(os.path.join(app.config['UPLOAD_FOLDER'], fileName), 'r') as f:
			return send_from_directory(app.config['UPLOAD_FOLDER'], fileName)
	else:
		resp = jsonify({})
		resp.status_code = 404 # File not found.
		return resp

# addRandom -> boolean
# Use addRandom = True whenever you need to generate
# a new ID if the one generated first was already taken.
def genID(addRandom):
	# return int(sys.argv[1])

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
def processUFiles(fileNames):
	succFiles = []
	for fileName in fileNames:
		# Save the files in NODE's list of files.
		# To provide redundancy, keep a copy of the file and its key.
		# This will make lookup a bit faster, and if the node leaves,
		# someone will still have the file.
		NODE.FILES[hashlib.sha1(fileName)] = "uploads"
		# Find where the file should be sent to.
		node = chord(fileName)
		print "CHORD HAS ASSIGNED THE FILE TO NODE: ",
		print node
		sendNode = None
		if node != NODE.ID:
			for i in xrange(0,IDBITS):
				interval = (FINGERS[i][0], (FINGERS[i][0] + 2**i) % 2**IDBITS)
				if between(interval[0], interval[1], node):
					sendNode = FINGERS[i][1]
					break;
			# Send the file to node.
			print "THE FILE WILL BE SENT TO NODE: ",
			print sendNode
			address = "http://" + sendNode.IP + ":5000/receiveFile"
			# Send the file to node.
			# print "THE FILE WILL BE SENT TO NODE: ",
			# print sendNode.ID
			with open(os.path.join(app.config['UPLOAD_FOLDER'], fileName), 'r') as f:
				try:
					r = requests.post(address, data={'nodeID':node, 'fileName':fileName,
					'sender':str(NODE.ID)}, files={fileName: f}, timeout=15)
					if r.status_code != 200:
						print r.text
						print "Node " + str(sendNode.ID) + " did not receive" + fileName + "correctly."
					else:
						if (r.text == "SUCCESS"):
							succFiles.append(fileName)
						else:
							print "The node " + str(node) + "could not be found."
							print "Stabilization inititated." # The other nodes must have initialized
															  # stabilization at this point.
				except requests.exceptions.RequestException as e:
					print str(sendNode.ID) + " could not be reached."
					# Use stabilize
					run_stabilize()
	return succFiles


# STABILIZE TAKES SUPER LONG BECAUSE 10 tries * 5 timeout
def make_http_request(target, endpoint, method, payload):
	tries = 0
	while tries < MAX_RETRIES:
		try:
			if method.upper() == 'GET':
				r = requests.get('http://' + target + ':5000/' + endpoint, timeout=1)
			elif method.upper() == 'POST':
				r = requests.post('http://' + target + ':5000/' + endpoint, json=payload, timeout=1)
			if r.status_code == 200:
				return (r.json(), True)
		except:
			pass
			# print 'Failed to establish connection with ' + str(target)

		tries += 1
	return (None, False)

# checks if ID c is (inclusive) between a & b in the Chord ring
def between(a, b, c):
	# print "WE ARE BETWEEN"
	# print "THIS IS a ",
	# print a,
	# print " "
	# print type(a)
	# print " THIS IS b ",
	# print b,
	# print " "
	# print type(b)
	# print " THIS is c ",
	# print c
	# print " "
	# print type(c)
	a, b, c = int(a), int(b), int(c)
	if b > a:
		# print "b > a"
		# print (a <= c and c <= b)
		return a <= c and c <= b
	elif a > b:
		# print "a > b"
		# print (c >= a or c <= b)
		return c >= a or c <= b
	else:
		# print "last case"
		# print (a == c)
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
	# WE CHANGED THIS FROM ring_size TO ring_size + 1
	for i in xrange(1, ring_size + 1):
		l.append((start + i) % ring_size)
	return l

def null_node(node):
	return node.ID == None and node.IP == None

def print_finger_table(msg):
	print msg
	for key in FINGERS.keys():
		print 'Finger ' + str(key) + ': Start: ' + str(FINGERS[key][0]) + ', Node: ' +str(FINGERS[key][1].ID)

def print_succ_pred(msg=''):
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

	# if len(sys.argv) > 1:
	# 	if sys.argv[1] == 'demo':
	# 		assigned_node = False
	# 		with open('state' + sys.argv[2] + '.csv', 'rb') as f:
	# 			reader = csv.reader(f)
	# 			arg_list = list(reader)
	# 			for idx, arg in enumerate(arg_list):
	# 				# NOTE: IP comes before ID in Node initialization
	# 				if len(arg) == 3:
	# 					start, ID, IP = arg
	# 					FINGERS[idx + 1] = (int(start), Node(IP.strip(), int(ID)))
	# 				elif len(arg) == 2:
	# 					if not assigned_node:
	# 						ID, IP = arg
	# 						NODE = Node(IP.strip(), int(ID))
	# 						assigned_node = True
	# 					else:
	# 						ID, IP = arg
	# 						PREDECESSOR = Node(IP.strip(), int(ID))
	#
	# 			SUCCESSOR = (FINGERS[1])[1]
	# 	elif sys.argv[1] == 'test':
	# 		NODE = Node(sys.argv[3],int(sys.argv[2]))
	#
	# 	if NODE.ID == 3 and sys.argv[3] == 'search':
	# 		for i in xrange(0, 8):
	# 			node = find_successor(i)
	# 			print 'File w/ key' + str(i) + ' is in ' + str(node.ID)
	#
	# 	if sys.argv[3] == 'join':
	# 		print_finger_table('Finger table on joining')

	# schedule [stabilize] and [fix_fingers] to run periodically
	t1 = threading.Thread(target=run_stabilize)
	t1.daemon = True
	t1.start()

	t2 = threading.Thread(target=run_fix_fingers)
	t2.daemon = True
	t2.start()
	# app.debug = True
	app.run(host="0.0.0.0", port=5000)
