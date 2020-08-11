import gevent
import gevent.monkey
from gevent.pywsgi import WSGIServer
gevent.monkey.patch_all()

from flask import Flask, render_template, jsonify, request, Response, redirect, url_for, session, escape


import argparse
import sys
import requests
import time
import winsound

import boto3
from boto3.dynamodb.conditions import Key, Attr
import json

from datetime import datetime

from IOTAssignmentUtilitiesdorachua.MySQLManager import MySQLManager
from IOTAssignmentUtilitiesdorachua.MySQLManager import QUERYTYPE_DELETE, QUERYTYPE_INSERT, QUERYTYPE_UPDATE

from AWSIoTPythonSDK.MQTTLib import AWSIoTMQTTClient

import jsonconverter as jsonc

app = Flask(__name__)

app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'


# telegram bot to send alerts to the analyst
def telegram_bot(bot_message):

    bot_token = '1157671100:AAFnOQeaeRu6Jy0RsHzGf0Q9RUqUV7H4kbI'
    bot_chatID = '280242805'
    send_text = 'https://api.telegram.org/bot' + bot_token + '/sendMessage?chat_id=' + bot_chatID + '&parse_mode=Markdown&text=' + bot_message

    response = requests.get(send_text)

    return response.json()


# speed limit 80, if more than 80 , send a alert message to the telegram bot
@app.route("/api/sendalert",methods=['GET', 'POST'])
def apidata_sendalert():
    try:
        bookingid ="0.0"
        speedkmhour = "0"
        day = "Monday 2020."
        speed = ""

        frequency = 2000
        duration = 1000

        if 'bookingid' in request.form:        
            bookingid = request.form['bookingid']
        if 'speedkmhour' in request.form:
            speedkmhour = request.form['speedkmhour']
        if 'date' in request.form:
            date = request.form['date']
        if 'time' in request.form:
            time = request.form['time']


        speedkmhourf = float(speedkmhour)

        message = "Hi driver of Booking ID: " + bookingid + "," + " you have been caught speeding at " + "{0:.2f}".format(speedkmhourf) + " KM/H on " + time + " on " + date + " Max speed limit is 80, please slow down."  
        
        telegram_bot(message)

        winsound.Beep(frequency, duration)
        return redirect("/dashboard", code=303) #redirect to a page
    except:
        print(sys.exc_info()[0])
        print(sys.exc_info()[1])

        
# to show the booking id to the analyst when he/she searches.
@app.route("/api/showbookingid",methods=['GET', 'POST'])
def apidata_showbookingid():
    try:

        table_name = 'grabtable'
        print(f'Querying table : {table_name}')
        #define connection
        dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
        table = dynamodb.Table(table_name)

        #DK what is this for
        startdate = '2020-07'


        bookingid = '0.0'
        if 'getbookingid' in request.form:        
            bookingid = request.form['getbookingid']     

        #Querying from the table
        response = table.query(
            #KeyConditionExpression=key('bookingid').eq('0.0')
            #Add the name of the index you want to use in your query
            #IndexName is something like a primary key
            IndexName="bookingid-datetime_value-index",
            KeyConditionExpression=Key('bookingid').eq(bookingid),
            ScanIndexForward=False,
            Limit=10
        )


        items = response['Items']

        n=10 #limit to last 10 items
        data = items[:n] #slicing 
        data_reversed = data[::-1]

        return jsonify(json.loads(jsonc.data_to_json(data_reversed)))
        
    except:
        print(sys.exc_info()[0])
        print(sys.exc_info()[1])


# retrieves the data from db and sends it to a line graph and table.

@app.route("/api/getdata",methods=['GET', 'POST'])
def apidata_getdata():
    try:
        table_name = 'grabtable'
        print(f"Querying table {table_name}")
        dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
        table = dynamodb.Table(table_name)

        #response = table.query(
            # Add the name of the index you want to use in your query.
        #    IndexName="bookingid-datetime_value-index",
        #    KeyConditionExpression=Key('bookingid').eq('0.0'),
        #    ScanIndexForward=False,
        #    Limit=10
        #)            
        #to pull
        response = table.query(
            IndexName="sort-datetime_value-index",
            KeyConditionExpression=Key('sort').eq('1'),
            ScanIndexForward=False,
            Limit=10
        )

        items = response['Items']

        n=10 # limit to last 10 items
        data = items[:n]
        data_reversed = data[::-1]
        #print(data_reversed)
        #print( (json.loads(jsonc.data_to_json(data_reversed)))
        return jsonify(json.loads(jsonc.data_to_json(data_reversed)))
    except:
        print(sys.exc_info()[0])
        print(sys.exc_info()[1])

# route to handle the login
@app.route("/api/login",methods=['GET', 'POST'])
def apidata_login():
    try:

        table_name = 'users'
        print(f'Querying table : {table_name}')
        dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
        table = dynamodb.Table(table_name)

        startdate = '2020-07'

        # Output message if error
        name = 'username'
        msg = ''
        # Check if "username" and "password" POST requests exist
        if 'username' in request.form and 'password' in request.form:
            username = request.form['username']
            password = request.form['password']

        if (userlogin):
            session['username'] = username
            return redirect(url_for('dashboard', username = username), code = 303)
        else:
            return render_template('login.html', msg = "Invalid Credentials")
        
    except:
        print(sys.exc_info()[0])
        print(sys.exc_info()[1]) 

# route to handle register
@app.route("/api/register",methods=['GET', 'POST'])
def apidata_register():
    try:

        table_name = 'users'
        print(f'Querying table : {table_name}')
        dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
        table = dynamodb.Table(table_name)

        # Output message if error
        name = 'username'
        msg = ''
        role = 'analyst'
        # Check 
        if 'username' in request.form and 'email' in request.form and 'number' in request.form and 'password' in request.form and 'cpassword' in request.form:
            username = request.form['username']
            email = request.form['email']
            number = request.form['number']
            password = request.form['password']
            cpassword = request.form['cpassword']

        my_rpi = AWSIoTMQTTClient("registerUser")
        
        host = "a19dfxc0pabiyn-ats.iot.us-east-1.amazonaws.com"
        rootCAPath = "certs/rootca.pem"
        certificatePath = "certs/users-certificate.pem.crt"
        privateKeyPath = "certs/users-private.pem.key"
        my_rpi.configureEndpoint(host, 8883)
        my_rpi.configureCredentials(rootCAPath, privateKeyPath, certificatePath)
        my_rpi.connect()
        usersinfo = {}
        usersinfo['username'] = username
        usersinfo['email'] = email
        usersinfo['number'] = number
        usersinfo['password'] = password
        usersinfo['role'] = role
        print(usersinfo)
        #r = { "username": username, "email": email, "number": number, "password": password, 'role': role }   

        success = my_rpi.publish("iot/users", json.dumps(usersinfo), 1)
        #my_rpi.publish("iot/users", json.dumps(r), 1)
        if success:
            print("success")
        else:
            print("fail")
        #if (userregister):
        session['username'] = username
        return redirect(url_for('dashboard', username = username), code = 303)
        #else:
            #return render_template('register.html', msg = "Incorrect fields, please try again")

        
    except:
        print(sys.exc_info()[0])
        print(sys.exc_info()[1]) 

# route to handle the profile
@app.route("/api/profile",methods=['GET', 'POST'])
def apidata_profile():
    try:
        # Output message if error
        name = username
        msg = ''
        role = 'analyst'
        # Check 
        if 'username' in request.form and 'email' in request.form and 'number' in request.form and 'password' in request.form and 'cpassword' in request.form:
            username = request.form['username']
            email = request.form['email']
            number = request.form['number']
            password = request.form['password']
            cpassword = request.form['cpassword']

        u='iotuser';pw='iotpassword';h='localhost';db='iotdatabase'
        mysqlm = MySQLManager(u,pw,h,db)
        mysqlm.connect()
            
        sql="UPDATE users SET %(username)s, %(email)s, %(number)s, %(password)s, %(role)s WHERE name = username"
        updatedetails = {"username": username, "email": email, "number": number, "password": password, "role": role}            
        userupdate = mysqlm.insertupdatedelete(QUERYTYPE_UPDATE,sql,updatedetails)
        mysqlm.disconnect()

        if (userupdate):
            session['username'] = username
            return redirect(url_for('dashboard', username = username), code = 303)
        else:
            return render_template('profile.html', msg = "Unable to update, please try again")
        
    except:
        print(sys.exc_info()[0])
        print(sys.exc_info()[1]) 
    
# this is to handle the dashboard data
@app.route("/api/getdashboarddata",methods=['GET', 'POST'])
def apidata_getdashboarddata():
    try:
        

        u='iotuser';pw='iotpassword';h='localhost';db='iotdatabase'
        mysqlm = MySQLManager(u,pw,h,db)
        mysqlm.connect()

        sql=f"SELECT COUNT(DISTINCT bookingid) as dashboarddata FROM iotapp"
        datasql = {}            
        driver_data = mysqlm.fetch_fromdb_as_list(sql,datasql)

        sql=f"SELECT IFNULL(AVG(speedkmhour),0) as dashboarddata FROM iotapp WHERE timestamp_value = CURRENT_TIMESTAMP"
        datasql = {}            
        average_speed_data = mysqlm.fetch_fromdb_as_list(sql,datasql)

        sql=f"SELECT IFNULL(MAX(speedkmhour),0) as dashboarddata FROM iotapp WHERE timestamp_value = CURRENT_TIMESTAMP"
        datasql = {}            
        max_speed = mysqlm.fetch_fromdb_as_list(sql,datasql)

        dashboarddata = {'driver_data': driver_data, 'average_speed_data': average_speed_data, 'max_speed': max_speed}

        mysqlm.disconnect()
            
        return dashboarddata

    except:
        print(sys.exc_info()[0])
        print(sys.exc_info()[1])     


@app.route("/multiple")
def multiple():
    return render_template('index_multiple.html')

@app.route("/")
def home():
    return render_template('index.html')

@app.route("/profile")
def profile():
    if 'username' in session:
        username = escape(session['username'])
    return render_template('profile.html', username = username)

@app.route("/showbookingid", methods = ['GET', 'POST'])
def showbookingid():
    if 'getbookingid' in request.form:
        booking_value = request.form['getbookingid']
    if 'username' in session:
        username = escape(session['username'])
    return render_template('showbookingid.html', username = username, hidden_bookingid = booking_value)

@app.route("/login")
def login():
    return render_template('login.html')

@app.route("/logout")
def logout():
    # clears the session by removing the username
    session.pop('username', None)
    return redirect(url_for('login'))

@app.route("/register")
def register():
    return render_template('register.html')

@app.route("/speedcheck")
def speedcheck():
    if 'username' in session:
        username = escape(session['username'])
    return render_template('speedcheck.html', username = username)

@app.route("/dashboard")
def dashboard():
    if 'username' in session:
        username = escape(session['username'])
    return render_template('dashboard.html', username = username)


if __name__ == '__main__':
   try:
        host = '0.0.0.0'
        port = 80
        parser = argparse.ArgumentParser()        
        parser.add_argument('port',type=int)
        
        args = parser.parse_args()
        if args.port:
            port = args.port
                
        http_server = WSGIServer((host, port), app)
        app.debug = True
        print('Web server is now waiting for requests')
        http_server.serve_forever()

   except:
        print("Exception occured while running web server!")
        print(sys.exc_info()[0])
        print(sys.exc_info()[1])
