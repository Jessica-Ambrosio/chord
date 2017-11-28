from flask import Flask, request
app = Flask(__name__)

@app.route("/")
def home():
	return "<h1>This will contain the GUI to interact with Chord</h1>"

if __name__ == "__main__":
	app.debug = True
	app.run(host="0.0.0.0")




