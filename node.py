from flask import Flask, request, render_template, jsonify, send_from_directory
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
app.config['DOWNLOAD_FOLDER'] = DOWNLOAD_FOLDER

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
SHUTDOWN = False
THREADS = []

# CORE

# returns the node whose ID succeeds input [ID], i.e the node that,
# from a clockwise perspective of the Chord ring, is ahead of the
# input [ID] by the least distance
def find_successor(ID):
	# print '(Node' + str(NODE.ID) + ':find_successor): finding successor of ' + str(ID)
	# print 'calling [find_predecessor] from [find_successor]'
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

# returns the node whose ID precedes input [ID], i.e the node that, from
# a clockwise perspective of the Chord ring, is behind of the
# input [ID] by the least distance
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
		# print '(find_predecessor): check if ' + str(ID) + ' is between ' +  str(next_ID(node.ID)) + ' and ' + str(succ.ID)
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

# returns the finger node whose ID preceds input [ID] (using the
# definition of precedes from above)
def find_closest_preceding_finger(ID):
	# loops from IDBITS to 1
	for i in xrange(IDBITS, 0, -1):
		ith_finger = FINGERS[i][1]
		invalid = next_ID(NODE.ID) == ID
		# print '[find_closest_preceding_finger] Is finger ' + str(i) + ': ' + str(ith_finger.ID) + ' between ' + str(next_ID(NODE.ID)) + ' and ' + str(prev_ID(ID))
		if not invalid and between(next_ID(NODE.ID), prev_ID(ID), ith_finger.ID):
			return ith_finger
	return NODE

# STABILIZATION

# randomly index into the finger table and check if the finger node for
# that index is out of date (by calling find_successor), and updates it
# if necessary
def fix_fingers():
	global FINGERS
	idx = random.randint(1, IDBITS)
	# print 'Check if finger ' + str(idx) + ' needs to be fixed'
	new_succ = find_successor(FINGERS[idx][0])
	if not null_node(new_succ):
		start = FINGERS[idx][0]
		# print 'Finger ' + str(idx) + ' is now Node ' + str(new_succ.ID)
		FINGERS[idx] = (start, new_succ)

def run_fix_fingers():
	while True and not SHUTDOWN:
		time.sleep(10)
		if not INITIALIZED:
			continue
		# print_finger_table('Before fix_fingers')
		print '============[fix_fingers]=============='
		fix_fingers()
		print_finger_table('After [fix_fingers]')
		print_succ_pred()
		print '======================================='

# check if a node exists by pinging it
def node_exists(node):
	data, result = make_http_request(node.IP, 'ping', 'GET', None)
	# print '[node_exists/ping] node ' + str(node.ID) + ' exists: ' + str(result)
	return result

# runs periodically on thread separate from main thread; checks if a new
# node has come between our node and its successor, or if our successor
# has left, and responds in both situation by correcting our successor
# (which is also the first finger) and notifying our new successor of
# our existence
def stabilize():
	global SUCCESSOR, PREDECESSOR

	# node is 1st node in network
	if SUCCESSOR.ID == NODE.ID:
		# print '[stabilize] SUCCESSOR.ID == NODE.ID'
		data = {"id": PREDECESSOR.ID, "ip": PREDECESSOR.IP}
		pred_result = True
	# find the successor node's predecessor
	else:
		# print '[stabilize] SUCCESSOR.ID != NODE.ID'
		data, pred_result = make_http_request(SUCCESSOR.IP, 'predecessor', 'GET', None)

	# successor has left; find new successor
	if not pred_result:
		print '==============[stabilize]================='
		print 'successor has left, trying to find new successor'
		print '======================================='
		found_new_succ = False
		# try and find new successor by going through ring in clockwise order
		# and finding the first ID whose predecessor can be found
		for ID in circular_range(SUCCESSOR.ID):
			old_succ = SUCCESSOR
			# print 'calling [find_predecessor] from stabilize'
			new_succ = find_predecessor(ID)
			if not null_node(new_succ):
				found_new_succ = True
				if node_exists(new_succ):
					print '==============[stabilize]================='
					print 'New successor is ' + str(new_succ.ID)
					print '======================================='
					SUCCESSOR = new_succ
					# the first finger node is equivalent to our successor
					FINGERS[1] = (FINGERS[1][0], SUCCESSOR)

				# "fixing the gap" (i.e successor & predecessor of the leaving node fixing their predecessor & successor)
				# has to be atomic unless our successor is ourselves
				if SUCCESSOR.ID != NODE.ID:
					data, notify_result = make_http_request(SUCCESSOR.IP, 'notify', 'POST', {'id': NODE.ID, 'ip': NODE.IP})
					if not notify_result:
						print '==============[stabilize]================='
						print 'Failed to notify ' + str(SUCCESSOR.ID) + '; reverting to old successor & trying again later'
						print '======================================='
						SUCCESSOR = old_succ
						# the first finger node is equivalent to our successor
						FINGERS[1] = (FINGERS[1][0], SUCCESSOR)

				return

		# could not find node's new successor
		if not found_new_succ:
			print '==============[stabilize]================='
			print 'Could not update successor'
			print '==================================='
			return

	# check if successor has a new predecessor in between us & the successor
	else:
		# node is our successor's predecessor
		succ_pred = Node(data["ip"], data["id"])

		# If [succ_pred] is NULL, immediately notify [succ]
		if not null_node(succ_pred):
			# if our successor's predecessor is between us
	 		invalid = next_ID(NODE.ID) == SUCCESSOR.ID
			if not invalid and between(next_ID(NODE.ID), prev_ID(SUCCESSOR.ID), succ_pred.ID):
				if node_exists(succ_pred):
					print '==============[stabilize]================='
					print 'New successor is ' + str(succ_pred.ID)
					print '==================================='
					SUCCESSOR = succ_pred
					# the first finger node is equivalent to our successor
					FINGERS[1] = (FINGERS[1][0], SUCCESSOR)

		# notify successor of our existence
		if SUCCESSOR.ID == NODE.ID:
			PREDECESSOR = NODE
		else:
			data, notify_result = make_http_request(SUCCESSOR.IP, 'notify', 'POST', {'id': NODE.ID, 'ip': NODE.IP})
			if not notify_result:
				print '==============[stabilize]================='
				print 'Failed to notify ' + str(SUCCESSOR.ID)
				print '==================================='
	# print 'Successor is ' + str(SUCCESSOR.ID)

def run_stabilize():
	while True and not SHUTDOWN:
		time.sleep(10)
		if not INITIALIZED:
			continue
		# print_finger_table('Before stabilize')
		stabilize()
		# print_finger_table('After stabilize')

# runs periodically on thread separate from main thread; checks if
# input [node] is between our node and its predecessor, i.e if we have
# a new predecessor, and responds by correcting our predecessor if necessary
def notify(node):
	global PREDECESSOR

	# no predecessor
	if PREDECESSOR.IP == None and PREDECESSOR.ID == None:
		print '==============[notify]================='
		print 'New predecessor is ' + str(node.ID)
		print '======================================='
		PREDECESSOR = node

	# make sure predecessor has not left the Chord network to prevent
	# making inaccurate comparisons below
	data, result = make_http_request(PREDECESSOR.IP, 'ping','GET', None)
	# print '[node_exists/ping] node ' + str(node.ID) + ' exists: ' + str(result)

	if not result:
		print '==============[notify]================='
		print 'New predecessor is ' + str(node.ID)
		print '======================================='
		PREDECESSOR = node

	invalid = next_ID(PREDECESSOR.ID) == NODE.ID
	if not invalid and between(next_ID(PREDECESSOR.ID), prev_ID(NODE.ID), node.ID):
		print '==============[notify]================='
		print 'New predecessor is ' + str(node.ID)
		print '======================================='
		PREDECESSOR = node
	# print 'PREDECESSOR is ' + str(PREDECESSOR.ID)

# check if the node at IP has joined the Chord network (to prevent
# relying on online BUT uninitialized during the [join] process)
@app.route("/init_status", methods=["GET"])
def handle_init_status():
	resp = jsonify({
		"initialized": INITIALIZED
	})
	resp.status_code = 200
	return resp

# attempts to join the Zoo's Chord network by generating a unique ID
# and performs a TCP SYN scan through nmap to find another node in the
# network we ask to initialize our successor and finger table.
@app.route("/join", methods=["POST", "GET"])
def join():
	print '==============[join]================='
	print "Attempting to join the Zoo's Chord network"
	print '====================================='
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

	print '==============[join]================='
	print str(len(NEIGHBORS)) + ' Chord nodes are online'
	print '====================================='
	if len(NEIGHBORS) == 0:
		NODE.ID = genID()
		SUCCESSOR = NODE
		makeFingers() # Make the finger table! :D
		INITIALIZED = True
		return "<h1>You are the only chord node in the network</h1>"

	idTaken = True
	tries = 0
	NODE.ID = genID()

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
			NODE.ID = genID()
			tries += 1

	# if we pick [IDBITS] such that math.pow(2, [IDBITS]) > #(Zoo machines), then if [idTaken]
	# is still true at this point, neighbors all failed in setting up our ID
	if idTaken:
		return "<h1>Failed to join! Please try to join again in a bit.</h1>"

	SUCCESSOR = Node(data["ip"], data["id"])
	makeFingers() # Make the finger table! :D
	INITIALIZED = True
	print '==============[join]================='
	print 'Node has joined Chord'
	print '====================================='
	return "Welcome to CHORD"

# initialize all finger nodes to the successor on joining
def makeFingers():
	for i in range(1, IDBITS + 1):
		start = (NODE.ID + math.pow(2, i-1)) % math.pow(2, IDBITS)
		FINGERS[i] = (start, SUCCESSOR)

# check if a node is still in the Chord network
@app.route("/ping", methods=["GET"])
def ping():
	resp = jsonify({})
	resp.status_code = 200
	return resp

# exit loops calling [stabilize] and [fix_fingers]; terminate Flask app
@app.route("/leave", methods=["POST"])
def leave():
	global SHUTDOWN, THREADS
	SHUTDOWN = True
	for t in THREADS:
		t.shutdown = True
		t.join()
	func = request.environ.get('werkzeug.server.shutdown')
	func()
	return "<h1>You have successfully exited chord.</h1>"

# Function to verify that the file looked up/ downloaded
# has one of the allowed extensions.
def allowed_file(filename):
	return '.' in filename and filename.rsplit('.',1)[1].lower() in ALLOWED_EXTENSIONS

# wrapper function that allows user to search if a file is in the
# Chord network by checking if the node Chord maps the file's ID to
# contains the file; initiates download to local folder if file is available
@app.route("/searchFile", methods=["POST"])
def search():
	if "fileName" not in request.form:
		resp = jsonify({})
		resp.status_code = 404
		return resp
	fileName = request.form.get("fileName", None)
	if not fileName:
		return "No file name typed."
	if fileName in NODE.FILES:
		return "You already have this file and it's in downloads or uploads. LOL"
	else:
		# print "we don't have the file"
		node = chord(fileName)
		successor = find_successor(node)
		address = "http://" + successor.IP + ":5000/fileRequest"
		try:
			req = requests.post(address, data={'fileName':fileName,'originID':NODE.ID, 'originIP':NODE.IP}, timeout=40)
			# print "THIS IS THE REQUEST RESPONSE " + str(req.text)
			if req.status_code == 200:
				# print dir(req)
				# file = req.files[fileName]
				# file.save(os.path.join(app.config['DOWNLOAD_FOLDER'], fileName))
				# NODE.FILES[hashlib.sha1(fileName)] = "downloads"
				return "File exists and will be downloaded soon."
			elif req.status_code == 400:
				return "The request did not arrive correctly."
			elif req.status_code == 404:
				return "The file does not exist in the system"
			else:
				return "PLease check the downloads folder '/static/downloads' to see if the download succeeded."
			# Use the status code to determine the output in jinja.
		except requests.exceptions.RequestException as e:
			print e
			run_stabilize()
			return "COULD NOT DOWNLOAD THE FILE" # We need to do something if this fails

# allows users to upload files to our node and the Chord network; sends
# the file to the node Chord maps the file's ID to and then saves copy
# of file to our node for redundancy
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
	print '==============[receieveFIle]================='
	print "the ultimate destination of the file is " + str(nodeID)
	print '====================================='
	fileName = request.form["fileName"]
	sender = int(request.form["sender"])
	keepFile = True
	if nodeID != NODE.ID:
		print '==============[receieveFIle]================='
		print "We are not the destination of the file"
		print '====================================='
		# Check if we are the successor of the goal node.
		# if we are not, then there is a node ahead of us that
		# is closer to the node we are aiming for.
		if not between(sender, NODE.ID, nodeID):
			print '==============[receieveFIle]========='
			print "We are not the successor of the goal node"
			print '====================================='
			# Send it to successor within the range of the
			# correct file owner node.
			sendNode = None
			for i in xrange(1, IDBITS+1):
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
					return "SUCCESS"
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
		NODE.FILES[fileName] = "downloads"
		return "SUCCESS"

@app.route("/fileRequest", methods=["POST"])
def fileRequest():
	resp = jsonify({})
	# Check that the request is valid.
	if "fileName" not in request.form:
		# print "SENT A 400 RESPONE FOR FILEREQUEST"
		resp.status_code = 400 # Bad request
		return resp
	fileName = request.form["fileName"]
	# Check if we actually have the file.
	if os.path.isfile(os.path.join(app.config['UPLOAD_FOLDER'], fileName)):
		originIP = request.form['originIP']
		originID = request.form['originID']
		response = sendFile(fileName, originID, originIP)
		if response == "SUCCESS":
			# print "/fileRequest: sending a 200 response"
			resp.status_code = 200
		else:
			# print "/fileRequest sending a 598 response"
			resp.status_code = 598    # Network read timeout error.
		return resp
	else:
		resp = jsonify({})
		resp.status_code = 404 # File not found.
		# print "SENT A 404 RESPONSE"
		return resp

def sendFile(fileName, originID, originIP):
	address = "http://" + originIP + ":5000/receiveFile"
	with open(os.path.join(app.config['UPLOAD_FOLDER'], fileName), 'r') as file:
		try:
			req = requests.post(address, data={'nodeID':originID, 'fileName':fileName,
					'sender':str(NODE.ID)}, files={fileName: file}, timeout=15)

			if req.text == "SUCCESS":
				print '==============[sendFIle]========='
				print "node " + str(originID) + " successfully received the file."
				print '================================='
				return "SUCCESS"
			else:
				print '==============[sendFIle]========='
				print "node " + str(originID) + " could not received the file."
				print '================================='
				return "FAILURE"
		except requests.exceptions.RequestException as e:
			print '==============[sendFIle]========='
			print e
			print "we could not connect to node " + str(originID)
			print '================================='
			return "FAILURE"

def genID():
	# return int(sys.argv[1])
	hostname = socket.gethostname()
	IP = socket.gethostbyname(hostname)
	hashIP = hashlib.sha1(IP)
	hexString = str(int(hashIP.hexdigest(), 16))
	decimal = 0
	for index,char in enumerate(hexString):
		decimal += int (char) * 16 ** index
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
		NODE.FILES[fileName] = "uploads"
		# Find where the file should be sent to.
		node = chord(fileName)
		print '===============[processUFiles]==============='
		print "Chord has assigned the file to Node ",
		print node
		print '============================================='
		#sendNode = None
		sendNode = find_successor(node)
		if sendNode.ID != NODE.ID:
			# for i in xrange(1, IDBITS+1):
			# 	interval = (FINGERS[i][0], (FINGERS[i][0] + 2**i) % 2**IDBITS)
			# 	if between(interval[0], interval[1], node):
			# 		sendNode = FINGERS[i][1]
			# 		break;
			# Send the file to node.
			print '===============[processUFiles]==============='
			print "The file will be sent to Node ",
			print sendNode.ID
			print '============================================='
			address = "http://" + sendNode.IP + ":5000/receiveFile"
			# Send the file to node.
			# print "THE FILE WILL BE SENT TO NODE: ",
			# print sendNode.ID
			with open(os.path.join(app.config['UPLOAD_FOLDER'], fileName), 'r') as f:
				try:
					r = requests.post(address, data={'nodeID':node, 'fileName':fileName,
					'sender':str(NODE.ID)}, files={fileName: f}, timeout=15)
					if r.status_code != 200:
						print '===============[processUFiles]==============='
						print r.text
						print "Node " + str(sendNode.ID) + " did not receive" + fileName + "correctly."
						print '============================================='
					else:
						if r.text == "SUCCESS":
							succFiles.append(fileName)
						else:
							print '===============[processUFiles]==============='
							print "The node " + str(node) + "could not be found."
							print "Stabilization inititated." # The other nodes must have initialized
															  # stabilization at this point.
							print '============================================='
				except requests.exceptions.RequestException as e:
					print '===============[processUFiles]==============='
					print str(sendNode.ID) + " could not be reached."
					print '============================================='
					# Use stabilize
					stabilize()
		else:
			succFiles.append(fileName)
	return succFiles

# wrapper function for retrying http requests and failing gracefully
# on timeout
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
# using module arithmetic
def between(a, b, c):
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

# generates a sequence of nodes to traverse in clockwise order
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


if __name__ == "__main__":
	# schedule [stabilize] and [fix_fingers] to run periodically
	t1 = threading.Thread(target=run_stabilize)
	t1.daemon = True
	t1.start()
	THREADS.append(t1)

	t2 = threading.Thread(target=run_fix_fingers)
	t2.daemon = True
	t2.start()
	THREADS.append(t1)

	# app.debug = True
	app.run(host="0.0.0.0", port=5000)
