from flask import Flask, render_template, request, redirect, url_for, session, abort, jsonify, make_response, send_from_directory
from werkzeug.utils import secure_filename
from datetime import timedelta
from flask_cors import CORS
from functools import wraps
from http import HTTPStatus
from datetime import datetime
import pymysql
import jwt
import re
import os



#####
# Start MySQL Server
#####

# mysql.server start
# mysql.server stop


app = Flask(__name__)

#####
# APP CONFIG
#####

cors = CORS(app, resources={r"/*": {"origins": "*"}})

app.secret_key = '4rZ8BTvr7qTdFF'
app.permanent_session_lifetime = timedelta(minutes=10)

app.config['SECRET_KEY'] = '4rZ8BTvr7qTdFF'
app.config['UPLOAD_FOLDER'] =  './Resources'
app.config['MAX_CONTENT_LENGTH'] = 4 * 1000 * 1000

ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg', 'gif'}

#####
# DB CONNECTION
#####

conn = pymysql.connect(
          host='localhost',
          user='root', 
          password = "rootpass",
          db='cpsc_449_db',
        cursorclass=pymysql.cursors.DictCursor
          )
cur = conn.cursor()


#####
# UTILS
#####

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

#####
# JWT DECORATOR
#####

def token_required(f):
    @wraps(f)
    def decorator(*args, **kwargs):
         token = None
         if 'x-access-tokens' in request.headers:
              token = request.headers['x-access-tokens']
 
         if not token:
              return make_response(
                   jsonify({'message': 'A valid token is missing'}),
                   HTTPStatus.UNAUTHORIZED,
               {'WWW-Authenticate' : 'Basic realm ="No token found !!"'}
              )
         try:
              data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])

              cur.execute('SELECT * FROM accounts WHERE id = %s', (data['public_id']))
              conn.commit()
              current_user = cur.fetchone()
         except:
              return make_response(
                   jsonify({'message': 'Token is invalid or Token Expired'}),
                   HTTPStatus.UNAUTHORIZED,
               {'WWW-Authenticate' : 'Basic realm ="No valid token found!!"'}
              )
 
         return f(current_user, *args, **kwargs)
    return decorator

#####
# API ROUTE CONFIGS
#####

@app.route("/api/login", methods =['POST'])
def api_login():
    
    auth = request.form
  
    if not auth or not auth.get('username') or not auth.get('password'):
        # returns 401 if any email or / and password is missing
        return make_response(
            jsonify({'message': 'Could not understand the request'}),
            HTTPStatus.UNAUTHORIZED,
            {'WWW-Authenticate' : 'Basic realm ="Login required !!"'}
        )
    
    cur.execute('SELECT * FROM accounts WHERE username = % s AND password = % s', (auth.get('username'), auth.get('password')))
    conn.commit()
    account = cur.fetchone()

    if not account:
        # returns 401 if user does not exist
        return make_response(
            jsonify({'message': 'Could not verify'}),
            HTTPStatus.UNAUTHORIZED,
            {'WWW-Authenticate' : 'Basic realm ="User does not exist !!"'}
        )
    
    if account['password'] == auth.get('password'):
    
        # generates the JWT Token
        token = jwt.encode({
            'public_id': account['id'],
            'exp' : datetime.utcnow() + app.permanent_session_lifetime
        }, app.config['SECRET_KEY'])
  
        return make_response(jsonify({'token' : token.decode('UTF-8')}), HTTPStatus.CREATED)
    
@app.route("/api/register", methods =['POST'])
def api_register():

    if 'username' in request.form and 'password' in request.form and 'email' in request.form and 'address' in request.form and 'city' in request.form and 'country' in request.form and 'postalcode' in request.form and 'organization' in request.form:
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        organization = request.form['organization']
        address = request.form['address']
        city = request.form['city']
        state = request.form['state']
        country = request.form['country']
        postalcode = request.form['postalcode']

        cur.execute('SELECT * FROM accounts WHERE username = % s', (username))
        account = cur.fetchone()
        conn.commit()

        if account:
            msg = 'Account already exists !'
            return make_response(jsonify({'message': 'Account already exists !'}), HTTPStatus.CONFLICT)
        elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
            return make_response(jsonify({'message': 'Invalid email address !'}), HTTPStatus.UNPROCESSABLE_ENTITY)
        elif not re.match(r'[A-Za-z0-9]+', username):
            return make_response(jsonify({'message': 'Username must contain only characters and numbers !'}), HTTPStatus.UNPROCESSABLE_ENTITY)
        else:
            cur.execute('INSERT INTO accounts VALUES (NULL, % s, % s, % s, % s, % s, % s, % s, % s, % s)', (username, password, email, organization, address, city, state, country, postalcode))
            conn.commit()
            return make_response(jsonify({'message': 'Successfully registered.'}), HTTPStatus.CREATED)
    return make_response(jsonify({'message': 'Could not understand the request'}), HTTPStatus.BAD_REQUEST)

@app.route("/api/upload", methods =['POST'])
@token_required
def api_upload(current_user):

    # check if the post request has the file part
    if 'file' not in request.files:
        return make_response(jsonify({'message': 'Could not find file to upload'}), HTTPStatus.BAD_REQUEST)

    file = request.files['file']

    # If the user does not select a file, the browser submits an
    # empty file without a filename.
    if file.filename == '':
        return make_response(jsonify({'message': 'Could not find file to upload'}), HTTPStatus.BAD_REQUEST)

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        return make_response(jsonify({'message': 'File was uploaded'}), HTTPStatus.OK)

    return make_response(jsonify({'message': 'File type is not supported'}), HTTPStatus.UNSUPPORTED_MEDIA_TYPE)

@app.route("/api/download/<filename>", methods =['GET'])
@token_required
def api_download(current_user, filename):
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)

@app.route("/api/list", methods =['GET'])
def api_list_files():
    return os.listdir(app.config["UPLOAD_FOLDER"]), HTTPStatus.OK

@app.route("/simulate/<errorno>", methods =['GET'])
def request_test(errorno):
    abort(int(errorno))

#####
# ERROR HANDLING
#####

@app.errorhandler(400)
def unauthorized_handler1(e):
     return make_response(jsonify({'message': 'BAD REQUEST'}), HTTPStatus.BAD_REQUEST)

@app.errorhandler(401)
def unauthorized_handler2(e):
     return make_response(jsonify({'message': 'UNAUTHORIZED'}), HTTPStatus.UNAUTHORIZED)

@app.errorhandler(404)
def unauthorized_handler3(e):
     return make_response(jsonify({'message': 'NOT FOUND'}), HTTPStatus.NOT_FOUND)

@app.errorhandler(405)
def unauthorized_handler4(e):
     return make_response(jsonify({'message': 'METHOD NOT ALLOWED'}), HTTPStatus.METHOD_NOT_ALLOWED)

@app.errorhandler(413)
def unauthorized_handler4(e):
     return make_response(jsonify({'message': 'FILE SIZE EXCEEDED MAX LIMIT OF 4MB'}), HTTPStatus.REQUEST_ENTITY_TOO_LARGE)

@app.errorhandler(500)
def unauthorized_handler5(e):
     return make_response(jsonify({'message': 'INTERNAL SERVER ERROR'}), HTTPStatus.INTERNAL_SERVER_ERROR)

#####
# RUN ONLY IF MAIN
#####

if __name__ == "__main__":
    app.run(host ="localhost", port = int("5000"), debug=False)
