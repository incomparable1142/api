from flask import Flask, request,  jsonify, session, redirect
from flask_login import LoginManager, UserMixin, login_user, login_required,\
                        logout_user, current_user
import uuid
from uuid import getnode as get_mac
from flask.ext.bcrypt import Bcrypt
from bson.objectid import ObjectId
from functools import wraps
from datetime import datetime
import datetime
import traceback
import flask_login
import flask
import json
import jwt
import os
from db import Mdb
# from werkzeug.utils import secure_filename
# from wtforms.fields import SelectField
# from utils import log

app = Flask(__name__)
bcrypt = Bcrypt(app)
mdb = Mdb()


##############################################################################
#                                                                            #
#                                                                            #
#                                    SESSION                                 #
#                                                                            #
#                                                                            #
##############################################################################
@app.before_request
def before_request():
    flask.session.permanent = True
    app.permanent_session_lifetime = datetime.timedelta(minutes=15)
    flask.session.modified = True
    flask.g.user = flask_login.current_user
    # print'session in working'


app.config['secretkey'] = 'some-strong+secret#key'
app.secret_key = 'F12Zr47j\3yX R~X@H!jmM]Lwf/,?KT'

# setup login manager
login_manager = LoginManager()
login_manager.init_app(app)


##############################################################################
#                                                                            #
#         _id of mongodb record was not getting JSON encoded, so             #
#                          using this custom one                             #
#                                                                            #
#                                                                            #
##############################################################################
class JSONEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, ObjectId):
            return str(o)
        return json.JSONEncoder.default(self, o)


#############################################
#                                           #
#                SESSION COUNTER            #
#                                           #
#############################################
def sumSessionCounter():
    try:
        session['counter'] += 1
    except KeyError:
        session['counter'] = 1


##############################################
#                                            #
#               LOGIN MANAGER                #
#                                            #
##############################################
@login_manager.unauthorized_handler
def unauthorized_callback():
    return redirect('/')


##############################################
#                                            #
#               GET MAC ADDRESS              #
#                                            #
##############################################
def get_mac():
    mac_num = hex(uuid.getnode()).replace('0x', '').upper()
    mac = '-'.join(mac_num[i: i + 2] for i in range(0, 11, 2))
    return mac


#############################################
#                                           #
#              TOKEN REQUIRED               #
#                                           #
#############################################
app.config['secretkey'] = 'some-strong+secret#key'


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.args.get('token')

        # ensure that token is specified in the request
        if not token:
            return jsonify({'message': 'Missing token!'})

        # ensure that token is valid
        try:
            data = jwt.decode(token, app.config['secretkey'])
        except:
            return jsonify({'message': 'Invalid token!'})

        return f(*args, **kwargs)

    return decorated


##############################################
#                                            #
#               WHO AM I ROUTE               #
#                                            #
##############################################
@app.route('/whoami')
def whoami():
    ret = {}
    try:
        sumSessionCounter()
        ret['User'] = (" hii i am %s !!" % session['name'])
        email = session['email']
        ret['Session'] = email
        ret['User_Id'] = mdb.get_user_id_by_session(email)
    except Exception as exp:
        ret['error'] = 1
        ret['user'] = 'user is not login'
    return JSONEncoder().encode(ret)


#############################################
#                                           #
#                  ADD USER                 #
#                                           #
#############################################
@app.route("/add_user", methods=['POST'])
def add_user():
    ret = {}
    try:
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        contact = request.form['contact']
        question = request.form['question']
        answer = request.form['answer']

        # password bcrypt  #
        pw_hash = bcrypt.generate_password_hash(password)
        passw = bcrypt.check_password_hash(pw_hash, password)

        check = mdb.check_email(email)
        if check:
            ret['error'] = 1
            ret['user'] = 'This Email Already Used'
            return JSONEncoder().encode(ret)

        else:
            mdb.add_user(name, email, pw_hash, contact, question, answer)
            ret['error'] = 0
            ret['user'] = (" user add successfully !!")
            return JSONEncoder().encode(ret)

    except Exception as exp:
        print('add_user() :: Got exception: %s' % exp)
        print(traceback.format_exc())


#############################################
#                                           #
#                 LOGIN USER                #
#                                           #
#############################################
@app.route('/login', methods=['POST'])
def login():
    ret = {}
    try:
        sumSessionCounter()
        email = request.form['email']
        password = request.form['password']


        if mdb.user_exists(email):
            pw_hash = mdb.get_password(email)
            print 'password in server, get from db class', pw_hash
            passw = bcrypt.check_password_hash(pw_hash, password)


            if passw == True:
                name = mdb.get_name(email)
                session['name'] = name
                session['email'] = email

                # Login Successful!
                expiry = datetime.datetime.utcnow() + datetime.\
                    timedelta(minutes=15)

                token = jwt.encode({'user': email, 'exp': expiry},
                                   app.config['secretkey'], algorithm='HS256')
                ret['msg'] = 'Login successful'
                ret['err'] = 0
                ret['token'] = token.decode('UTF-8')

            else:
                ret['msg'] = 'Password is wrong!'
                ret['err'] = 1
                return JSONEncoder().encode(ret)

        else:
            # Login Failed!
            ret['msg'] = 'Email Id is incorrect'
            ret['err'] = 1
            return JSONEncoder().encode(ret)

        LOGIN_TYPE = 'User Login'
        email = session['email']
        user_email = email
        mac = get_mac()
        ip = request.remote_addr

        agent = request.headers.get('User-Agent')
        mdb.save_login_info(user_email, mac, ip, agent, LOGIN_TYPE)

    except Exception as exp:
        ret['msg'] = '%s' % exp
        ret['err'] = 0
        print(traceback.format_exc())
    # return jsonify(ret)
    return JSONEncoder().encode(ret)


#############################################
#                                           #
#              SESSION LOGOUT               #
#                                           #
#############################################
@app.route('/logout')
def clearsession():
    try:
        ret = {}
        LOGIN_TYPE = 'User Logout'
        sumSessionCounter()
        email = session['email']
        user_email = email
        mac = get_mac()
        ip = request.remote_addr
        agent = request.headers.get('User-Agent')
        mdb.save_login_info(user_email, mac, ip, agent, LOGIN_TYPE)
        session.clear()
        ret['msg'] = 'Logout Successfully!'
        ret['err'] = 0
        return JSONEncoder().encode(ret)
    except Exception as exp:
        return 'clearsession() :: Got Exception: %s' % exp


#############################################
#                                           #
#          GET LOGIN INFORMATION            #
#                                           #
#############################################
@app.route('/get_info')
def get_info():
    try:
        LOGIN_TYPE = 'User Login'
        sumSessionCounter()
        email = session['email']
        user_email = email
        ip = request.remote_addr
        agent = request.headers.get('User-Agent')

        mdb.save_login_info(user_email, ip, agent, LOGIN_TYPE)
        return 'User_email: %s, IP: %s, ' \
               'User-Agent: %s' % (user_email, ip, agent, LOGIN_TYPE)
    except Exception as exp:
        print('get_info() :: Got exception: %s' % exp)
        print(traceback.format_exc())
        return ('get_info() :: Got exception: %s is '
                'not found Please Login first' % exp)


#################################################
#                                               #
#                    ADD_TODO                   #
#                                               #
#################################################
@app.route("/add_todo", methods=['POST'])
def add_todo():
    try:
        ret = {"error": 0}
        title = request.form['title']
        description = request.form['description']
        date = request.form['date']
        done = request.form['done']
        mdb.add_todo(title, description, date, done)
        ret["msg"] = "todo added sucessfully"
    except Exception as exp:
        print "todo_done() :: Got exception: %s" % exp
        print(traceback.format_exc())
    return json.dumps(ret)


#################################################
#                                               #
#               get_all_todos                   #
#                                               #
#################################################
@app.route("/get_all_todo", methods=['GET'])
def get_all_todo():
    return mdb.get_all_todo()


#################################################
#                                               #
#                delete_todos                   #
#                                               #
#################################################
@app.route("/delete_todo", methods=['POST'])
def delete_todo():
    try:
        title = request.form['title']
        mdb.delete_todo(title)
    except Exception as exp:
        print "delete_done() :: Got exception: %s" % exp
        print(traceback.format_exc())
    return "%s" % mdb.delete_todo(title)


#################################################
#                                               #
#            get_all_pending_todo               #
#                                               #
#################################################
@app.route("/get_all_pending", methods=['GET'])
def get_all_pending():
    try:
        mdb.get_all_pending()
    except Exception as exp:
        print "get_done() :: Got exception: %s" % exp
        print(traceback.format_exc())
    return "%s" % mdb.get_all_pending()


#################################################
#                                               #
#             get_all_done_todo                 #
#                                               #
#################################################
@app.route("/get_all_done", methods=['GET'])
def get_all_done():
    try:
        mdb.get_all_done()
    except Exception as exp:
        print "get_done() :: Got exception: %s" % exp
        print(traceback.format_exc())
    return "%s" % mdb.get_all_done()


#################################################
#                                               #
#             Main Server                       #
#                                               #
#################################################
# if __name__ == '__main__':
#     app.run(debug=True)
#
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='127.0.0.1', port=port, debug=True, threaded=True)
