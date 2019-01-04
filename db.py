from pymongo import MongoClient
from config import *
import traceback
import json
import datetime
from bson import ObjectId


class JSONEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, ObjectId):
            return str(o)
        return json.JSONEncoder.default(self, o)

class Mdb:
    def __init__(self):
        conn_str = "mongodb://%s:%s@%s:%d/%s" \
                   % (DB_USER, DB_PASS, DB_HOST, DB_PORT, AUTH_DB_NAME)
        client = MongoClient(conn_str)
        self.db = client[DB_NAME]

#############################################
#                                           #
#                GET LAST ID                #
#                                           #
#############################################
    def get_last_id(self):
        data = self.db.user.find({}).count() > 0
        if data == True:
            last_id = self.db.user.find({}).sort({"_id": -1}).limit(1)
        else:
            last_id = 0
        return last_id

#################################################
#                                               #
#                    ADD_USER                   #
#                                               #
#################################################
    def check_email(self, email):
        return self.db.user.find({'email': email}).count() > 0

    def add_user(self, name, email, pw_hash, contact, question, answer):
        try:
            ts = datetime.datetime.today().strftime("%a %b %d %X  %Y ")
            rec = {
                'name': name,
                'email': email,
                'password': pw_hash,
                'contact': contact,
                'question': question,
                'answer': answer,
                'creation_date': ts
            }
            self.db.user.insert(rec)
        except Exception as exp:
            print("add_user() :: Got exception: %s", exp)
            print(traceback.format_exc())

#############################################
#                                           #
#           CHECK USER IN DATABASE          #
#                                           #
#############################################
    def user_exists(self, email):
        return self.db.user.find({'email': email}).count() > 0

#############################################
#                                           #
#               GET NEW PASSWORD            #
#                                           #
#############################################
    def get_password(self, email):
        result = self.db.user.find({'email': email})
        name = ''
        password = ''
        if result:
            for data in result:
                name = data['name']
                password = data['password']
                print 'password in db class', password
        return password

#############################################
#                                           #
#        GET NAME ACCORDING TO EMAIL        #
#                                           #
#############################################
    def get_name(self, email):
        result = self.db.user.find({'email': email})
        name = ''
        email = ''
        if result:
            for data in result:
                name = data['name']
                email = data['email']
        return name

#############################################
#                                           #
#            USER SESSION IN DATABASE       #
#                                           #
#############################################
    def save_login_info(self, user_email, mac, ip, user_agent, LOGIN_TYPE):
        # LOGIN_TYPE = 'User Login'
        try:
            ts = datetime.datetime.today().strftime("%a %b %d %X  %Y ")
            rec = {
                'user_id': user_email,
                'mac': mac,
                'ip': ip,
                'user_agent': user_agent,
                'user_type': LOGIN_TYPE,
                'timestamp': ts
            }
            self.db.user_session.insert(rec)
        except Exception as exp:
            print "save_login_info() :: Got exception: %s", exp
            print(traceback.format_exc())

#############################################
#                                           #
#                 GET SESSION               #
#                                           #
#############################################
    def get_sessions(self):
        collection = self.db["user_session"]
        result = collection.find({})
        ret = []
        for data in result:
            ret.append(data)
        return ret

#############################################
#                                           #
#         GET USER ID BY SESSION            #
#                                           #
#############################################
    def get_user_id_by_session(self, email):
        result = self.db.user.find({'email': email})
        id = ''
        if result:
            for data in result:
                id = data['_id']
        return id

#############################################
#                                           #
#               OR Query                    #
#                                           #
#############################################
    def search_user(self, text):
        result = self.db.user.find({
            "$or":
                [
                    # {"title": text}
                    # {"title" : { "$regex" : ".*${text}.*"} }
                    {'email': {'$regex': text, '$options': 'i'}}
                 ]
        })
        # ret = []
        for user in result:
            return user
            # ret.append(user)
        # return ret

    # db.survey.find( { $or:[ {"title": "Help Survey"} ] } )

##############################################
#                                            #
#       GET SECURITY QUESTION BY EMAIL       #
#                                            #
##############################################
    def get_security_question(self, email):
        result = self.db.user.find({'email': email})
        question = ''
        if result:
            for data in result:
                question = data['question']
                print 'password in db class', question
        return question

    def get_security_answer(self, email):
        result = self.db.user.find({'email': email})
        answer = ''
        if result:
            for data in result:
                answer = data['answer']
                print 'password in db class', answer
        return answer

    def set_password(self, email, pw_hash):
        self.db.user.update(
            {'email': email},
            {'$set': {'password': pw_hash}},
            upsert=True, multi=True)

#################################################
#                                               #
#                    ADD_TODO                   #
#                                               #
#################################################
    def add_todo(self, title, description, date, status, email):
        try:
            ts = datetime.datetime.today().strftime("%a %b %d %X  %Y ")
            rec = {
                'title': title,
                'description': description,
                'date': date,
                'status': status,
                'email': email,
                'creation_date': ts
            }
            self.db.todo.insert(rec)
        except Exception as exp:
            print "add_todo() :: Got exception: %s", exp
            print(traceback.format_exc())


#################################################
#                                               #
#                get_all_todo                   #
#                                               #
#################################################
    def get_all_user(self):
        collection = self.db["user"]
        result = collection.find({})

        ret = []
        for data in result:
            ret.append(data)
        return JSONEncoder().encode({'users': ret})

#################################################
#                                               #
#                 Delete user                   #
#                                               #
#################################################
    def delete_user(self, email):
        ret = []
        collection = self.db["user"]
        collection.remove({"email": email})
        todo_collection = self.db["todo"]
        todo_collection.remove({"email":email})
        result = collection.find({})
        for data in result:
            ret.append(data)
        return JSONEncoder().encode({'users': ret})

#################################################
#                                               #
#            get_all_pending_todo               #
#                                               #
#################################################
    def get_all_pending(self, email):
        ret = []
        collection = self.db["todo"]
        result = collection.find({"status": "0", "email": email})
        # if not result:
        #     not_done = collection.find()
        #     for data in not_done:
        #         print "<<=====got the data====>> :: %s" % data
        #         ret.append(data)
        #     return JSONEncoder().encode({'todo': ret})

        for data in result:
            ret.append(data)
        return JSONEncoder().encode({'todo': ret})

#################################################
#                                               #
#             get_all_done_todo                 #
#                                               #
#################################################
    def get_all_complete(self, email):
        ret = []
        collection = self.db["todo"]
        result = collection.find({"status": "1", "email": email})
        # if not result:
        #     not_done = collection.find()
        #     for data in not_done:
        #         print "<<=====got the data====>> :: %s" % data
        #         ret.append(data)
        #     return JSONEncoder().encode({'todo': ret})

        for data in result:
            ret.append(data)
        return JSONEncoder().encode({'todo': ret})


if __name__ == "__main__":
    mdb = Mdb()

