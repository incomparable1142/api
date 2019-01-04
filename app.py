from flask import Flask, request,  jsonify, session, redirect
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
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
from config import EXPIRE_TOKEN_LIMIT
app = Flask(__name__)
bcrypt = Bcrypt(app)
mdb = Mdb()

# https://www.tecmint.com/install-mongodb-on-ubuntu-18-04/
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


##############################################
#                                            #
#               GET MAC ADDRESS              #
#                                            #
##############################################
def get_mac():
    mac_num = hex(uuid.getnode()).replace('0x', '').upper()
    mac = '-'.join(mac_num[i: i + 2] for i in range(0, 11, 2))
    return mac


##############################################
#                                            #
#               WHO AM I ROUTE               #
#                                            #
##############################################
@app.route('/whoami')
def whoami():
    ret = {}
    try:
        ret['Message'] = (" Hello, i am %s !!" % session['name'])
        email = session['email']
        ret['Session'] = email
        ret['Status codes'] = 200
        # ret['User_Id'] = mdb.get_user_id_by_session(email)
    except Exception as exp:
        print(traceback.format_exc())
        print('get_info() :: Got exception: %s' % exp)
        ret['Error'] = 'User is not login'
        ret['Status codes'] = 400
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
            ret['Status codes'] = 400
            ret['Error'] = 'This Email Already Used !!'

        else:
            mdb.add_user(name, email, pw_hash, contact, question, answer)
            ret['Status codes'] = 200
            ret['Message'] = " User added successfully !!"

    except Exception as exp:
        print('add_user() :: Got exception: %s' % exp)
        print(traceback.format_exc())
        ret['Status codes'] = 404
        ret['Error'] = 'Some thing went wrong !!'
    return JSONEncoder().encode(ret)


#############################################
#                                           #
#                 LOGIN USER                #
#                                           #
#############################################
@app.route('/login', methods=['POST'])
def login():
    ret = {}
    try:
        email = request.form['email']
        password = request.form['password']

        if mdb.user_exists(email):
            pw_hash = mdb.get_password(email)
            print('password in server, get from db class', pw_hash)
            passw = bcrypt.check_password_hash(pw_hash, password)

            if passw == True:
                name = mdb.get_name(email)
                session['name'] = name
                session['email'] = email

                # Login Successful!
                expiry = datetime.datetime.utcnow() + datetime.timedelta(minutes=EXPIRE_TOKEN_LIMIT)

                token = jwt.encode({'user': email, 'exp': expiry},
                                   app.config['secretkey'], algorithm='HS256')

                LOGIN_TYPE = 'User Login'
                email = session['email']
                user_email = email
                mac = get_mac()
                ip = request.remote_addr
                agent = request.headers.get('User-Agent')
                mdb.save_login_info(user_email, mac, ip, agent, LOGIN_TYPE)

                ret['Message'] = 'Login successful'
                ret['Status codes'] = 200
                ret['Token'] = token.decode('UTF-8')

            else:
                ret['Error'] = 'Password is wrong!'
                ret['Status codes'] = 403
        else:
            # Login Failed!
            ret['Error'] = 'Email Id is incorrect'
            ret['Status codes'] = 400
        return JSONEncoder().encode(ret)

    except Exception as exp:
        print(traceback.format_exc())
        print('login() :: Got exception: %s' % exp)
        ret['Status codes'] = 404
        ret['Error'] = 'Some thing went wrong !!'
    # return jsonify(ret)
    return JSONEncoder().encode(ret)


#############################################
#                                           #
#              SESSION LOGOUT               #
#                                           #
#############################################
@app.route('/logout')
def clearsession():
    ret = {}
    try:
        LOGIN_TYPE = 'User Logout'
        email = session['email']
        mac = get_mac()
        ip = request.remote_addr
        agent = request.headers.get('User-Agent')
        mdb.save_login_info(email, mac, ip, agent, LOGIN_TYPE)
        session.clear()
        ret['Message'] = 'Logout Successfully!'
        ret['Status codes'] = 200
    except Exception as exp:
        print(traceback.format_exc())
        print('clearsession() :: Got exception: %s' % exp)
        ret['Error'] = 'User Already Logout!'
        ret['Status codes'] = 400
    return JSONEncoder().encode(ret)


#############################################
#                                           #
#          GET LOGIN INFORMATION            #
#                                           #
#############################################
@app.route('/get_info')
def get_info():
    ret = {}
    try:
        email = session['email']
        ret['LOGIN_TYPE'] = 'User Login'
        ret['Email'] = email
        ret['IP'] = request.remote_addr
        ret['Agent'] = request.headers.get('User-Agent')
        ret['MAC Address '] = get_mac()
        ret['Message'] = 'Success!'
        ret['Status codes'] = 200
    except Exception as exp:
        print('get_info() :: Got exception: %s' % exp)
        print(traceback.format_exc())
        ret['Error'] = 'User not found Please Login first'
        ret['Status codes'] = 400
    return JSONEncoder().encode(ret)


#################################################
#                                               #
#                  search user                  #
#                                               #
#################################################
@app.route("/search_user", methods=['POST'])
def search_user():
    ret = {}
    try:
        text = request.form['email']
        data = mdb.search_user(text)
        ret['User Id'] = data['_id']
        ret['Email'] = data['email']
        ret['Name'] = data['name']
        ret['Password'] = data['password']
        ret['Contact'] = data['contact']
        ret['Question'] = data['question']
        ret['Answer'] = data['answer']
        ret['Creation Date'] = data['creation_date']
        ret['Message'] = 'Search Successfully!'
        ret['Status codes'] = 200
    except Exception as exp:
        print("search_user() :: Got exception: %s" % exp)
        print(traceback.format_exc())
        ret['Error'] = 'Some thing went wrong !!'
        ret['Status codes'] = 400
    return JSONEncoder().encode(ret)


#################################################
#                                               #
#                     forgot                    #
#                                               #
#################################################
@app.route("/forgot", methods=['POST'])
def forgot():
    ret = {}
    try:
        ret['Status codes'] = 404
        email = request.form['email']
        question = request.form['question']
        answer = request.form['answer']
        password = request.form['newpassword']

        # password bcrypt  #
        pw_hash = bcrypt.generate_password_hash(password)
        passw = bcrypt.check_password_hash(pw_hash, password)

        if mdb.user_exists(email):
            ques = mdb.get_security_question(email)
            if question == ques:
                ans = mdb.get_security_answer(email)
                if answer == ans:
                    mdb.set_password(email, pw_hash)
                    ret['Message'] = 'Changed password successfully!'
                    ret['Status codes'] = 200
                else:
                    ret['Error'] = "Your answer is wrong please try again.."
            else:
                ret['Error'] = "This question doesn't exists in our database.."
        else:
            ret['Error'] = "This email doesn't exists in our database.."

    except Exception as exp:
        print("forgot() :: Got exception: %s" % exp)
        print(traceback.format_exc())
        ret['Error'] = 'Some thing went wrong !!'
        ret['Status codes'] = 400
    # return json.dumps(ret)
    return JSONEncoder().encode(ret)


#################################################
#                                               #
#               get_all_todos                   #
#                                               #
#################################################
@app.route("/get_all_user", methods=['GET'])
def get_all_user():
    return mdb.get_all_user()


#################################################
#                                               #
#                delete_todos                   #
#                                               #
#################################################
@app.route("/delete_user", methods=['POST'])
def delete_user():
    try:
        email = request.form['email']
        mdb.delete_user(email)
    except Exception as exp:
        print("delete_user() :: Got exception: %s" % exp)
        print(traceback.format_exc())
    return "%s" % mdb.delete_user(email)


#################################################
#                                               #
#                    ADD_TODO                   #
#                                               #
#################################################
@app.route("/add_todo", methods=['POST'])
def add_todo():
    ret = {}
    try:
        email = session['email']
        if email:
            title = request.form['title']
            description = request.form['description']
            date = request.form['date']
            status = request.form['status']
            mdb.add_todo(title, description, date, status, email)

            ret['Status codes'] = 200
            ret['Message'] = "Todo added sucessfully !!"
    except Exception as exp:
        print("add_todo() :: Got exception: %s" % exp)
        print(traceback.format_exc())
        ret['Error'] = 'Some went wrong. please Login first'
        ret['Status codes'] = 400
    return json.dumps(ret)


#################################################
#                                               #
#            get_all_pending_todo               #
#                                               #
#################################################
@app.route("/get_all_pending", methods=['GET'])
def get_all_pending():
    try:
        email = session['email']
        mdb.get_all_pending(email)
    except Exception as exp:
        print("get_done() :: Got exception: %s" % exp)
        print(traceback.format_exc())
    return "%s" % mdb.get_all_pending(session['email'])


#################################################
#                                               #
#             get_all_done_todo                 #
#                                               #
#################################################
@app.route("/get_all_complete", methods=['GET'])
def get_all_done():
    try:
        email = session['email']
        mdb.get_all_complete(email)
    except Exception as exp:
        print("get_done() :: Got exception: %s" % exp)
        print(traceback.format_exc())
    return "%s" % mdb.get_all_complete(email)


#################################################
#                                               #
#             Main Server                       #
#                                               #
#################################################
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='127.0.0.1', port=port, debug=True, threaded=True)

