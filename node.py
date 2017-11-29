from flask import Flask, request, render_template
import sys


node = Flask(__name__)
node.secret_key = "Distribyed4Lyfe"


@node.route("/")
def home():
	return render_template("index.html")

# Depending on how long the functions become, we could separate this
# into two files. One containing user functions, and the other one
# with Chord functions only. 

# USER FUNCTIONS

@node.route("/join")
def join():
	return "join"
	

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
	print "I will return an ID"

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




