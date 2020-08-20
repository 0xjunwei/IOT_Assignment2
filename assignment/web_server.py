import gevent
import gevent.monkey
from gevent.pywsgi import WSGIServer
gevent.monkey.patch_all()

from flask import Flask, render_template, jsonify, request, Response, redirect, url_for, session, escape
import argparse
import sys
import requests
import time
import boto3
from boto3.dynamodb.conditions import Key, Attr
import json
import os
import cv2
from datetime import datetime
import pickle
from IOTAssignmentUtilitiesdorachua.MySQLManager import MySQLManager
from IOTAssignmentUtilitiesdorachua.MySQLManager import QUERYTYPE_DELETE, QUERYTYPE_INSERT, QUERYTYPE_UPDATE
from AWSIoTPythonSDK.MQTTLib import AWSIoTMQTTClient
import jsonconverter as jsonc



#import winsound

import pandas as pd
import numpy as np
from sklearn.decomposition import PCA

app = Flask(__name__)

app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'

model = pickle.load(open('grab_model.pkl', 'rb'))

# telegram bot to send alerts to the analyst


def telegram_bot(bot_message):

    bot_token = '1157671100:AAFnOQeaeRu6Jy0RsHzGf0Q9RUqUV7H4kbI'
    bot_chatID = '280242805'
    send_text = 'https://api.telegram.org/bot' + bot_token + \
        '/sendMessage?chat_id=' + bot_chatID + '&parse_mode=Markdown&text=' + bot_message

    response = requests.get(send_text)

    return response.json()


# speed limit 80, if more than 80 , send a alert message to the telegram bot
@app.route("/api/sendalert", methods=['GET', 'POST'])
def apidata_sendalert():
    try:
        bookingid = "0.0"
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

        message = "Hi driver of Booking ID: " + bookingid + "," + " you have been caught speeding at " + \
            "{0:.2f}".format(speedkmhourf) + " KM/H on " + time + \
            " on " + date + " Max speed limit is 80, please slow down."

        telegram_bot(message)

        #winsound.Beep(frequency, duration)
        return redirect("/dashboard", code=303)  # redirect to a page
    except:
        print(sys.exc_info()[0])
        print(sys.exc_info()[1])


# to show the booking id to the analyst when he/she searches.
@app.route("/api/showbookingid", methods=['GET', 'POST'])
def apidata_showbookingid():
    try:

        table_name = 'grabtable'
        print(f"Querying table : {table_name}")
        # define connection
        dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
        table = dynamodb.Table(table_name)

        bookingid = '0.0'
        if 'getbookingid' in request.form:
            bookingid = request.form['getbookingid']

        # Querying from the table
        response = table.query(
            # KeyConditionExpression=key('bookingid').eq('0.0')
            # Add the name of the index you want to use in your query
            # IndexName is something like a primary key
            IndexName="bookingid-datetime_value-index",
            KeyConditionExpression=Key('bookingid').eq(bookingid),
            ScanIndexForward=False,
            Limit=10
        )

        items = response['Items']

        n = 10  # limit to last 10 items
        data = items[:n]  # slicing
        data_reversed = data[::-1]

        return jsonify(json.loads(jsonc.data_to_json(data_reversed)))

    except:
        print(sys.exc_info()[0])
        print(sys.exc_info()[1])


# retrieves the data from db and sends it to a line graph and table.

@app.route("/api/getdata", methods=['GET', 'POST'])
def apidata_getdata():
    try:
        table_name = 'grabtable'
        print(f"Querying table {table_name}")
        dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
        table = dynamodb.Table(table_name)

        # response = table.query(
        # Add the name of the index you want to use in your query.
        #    IndexName="bookingid-datetime_value-index",
        #    KeyConditionExpression=Key('bookingid').eq('0.0'),
        #    ScanIndexForward=False,
        #    Limit=10
        # )
        # to pull
        response = table.query(
            IndexName="sort-datetime_value-index",
            KeyConditionExpression=Key('sort').eq('1'),
            ScanIndexForward=False,
            Limit=10
        )

        items = response['Items']

        n = 10  # limit to last 10 items
        data = items[:n]
        data_reversed = data[::-1]
        # print(data_reversed)
        # print( (json.loads(jsonc.data_to_json(data_reversed)))
        return jsonify(json.loads(jsonc.data_to_json(data_reversed)))
    except:
        print(sys.exc_info()[0])
        print(sys.exc_info()[1])

@app.route("/api/getWarning", methods=['GET', 'POST'])
def apidata_getWarning():
    try:
        table_name = 'grabtable'
        print(f"Querying table {table_name}")
        dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
        table = dynamodb.Table(table_name)

        # response = table.query(
        # Add the name of the index you want to use in your query.
        #    IndexName="bookingid-datetime_value-index",
        #    KeyConditionExpression=Key('bookingid').eq('0.0'),
        #    ScanIndexForward=False,
        #    Limit=10
        # )
        # to pull
        
        response = table.query(
            IndexName="sort-datetime_value-index",
            KeyConditionExpression=Key('sort').eq('1'),
            ScanIndexForward=False,
        )

        items = response['Items']

  
        a_dict= {}
        a_list = []
        for i in response['Items']:
            if(i['speedkmhour'] > 80):
                d = {'bookingid' : i['bookingid'] , 'speedkmhour' : i['speedkmhour'], 'datetime_value' : i['datetime_value']}
                dictionary_copy = d.copy()
                a_list.append(dictionary_copy)


        print(a_list)

        # print(data_reversed)
        # print( (json.loads(jsonc.data_to_json(data_reversed)))
        return jsonify(json.loads(jsonc.data_to_json(a_list)))
    except:
        print(sys.exc_info()[0])
        print(sys.exc_info()[1])


# route to handle the login
@app.route("/api/login", methods=['GET', 'POST'])
def apidata_login():
    try:

        table_name = 'users'
        print(f'Querying table : {table_name}')
        dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
        table = dynamodb.Table(table_name)

        # Output message if error
        name = 'username'
        msg = ''
        # Check if "username" and "password" POST requests exist
        if 'username' in request.form and 'password' in request.form:
            username = request.form['username']
            password = request.form['password']

        try:

            response = table.get_item(
                Key={'username': username, 'password': password})

            items = response['Item']
            print(items)

            if (items):
                session['username'] = username
                return redirect(url_for('dashboard', username=username), code=303)
        except Exception as e:
            print(e)
            return render_template('login.html', msg="Username or password is incorrect, please try again.")

    except:
        print(sys.exc_info()[0])
        print(sys.exc_info()[1])

# route to handle register
@app.route("/api/register", methods=['GET', 'POST'])
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
        my_rpi.configureCredentials(
            rootCAPath, privateKeyPath, certificatePath)
        my_rpi.connect()
        usersinfo = {}
        usersinfo['username'] = username
        usersinfo['email'] = email
        usersinfo['number'] = number
        usersinfo['password'] = password
        usersinfo['role'] = role
        #r = { "username": username, "email": email, "number": number, "password": password, 'role': role }

        success = my_rpi.publish("iot/users", json.dumps(usersinfo), 1)
        #my_rpi.publish("iot/users", json.dumps(r), 1)
        if success:
            print("success")
        else:
            print("fail")
        # if (userregister):
        session['username'] = username
        return redirect(url_for('dashboard', username=username), code=303)
        # else:
        # return render_template('register.html', msg = "Incorrect fields, please try again")

    except:
        print(sys.exc_info()[0])
        print(sys.exc_info()[1])

# # route to handle the profile
# @app.route("/api/profile",methods=['GET', 'POST'])
# def apidata_profile():
#     try:
#         # Output message if error
#         name = username
#         msg = ''
#         role = 'analyst'
#         # Check
#         if 'username' in request.form and 'email' in request.form and 'number' in request.form and 'password' in request.form and 'cpassword' in request.form:
#             username = request.form['username']
#             email = request.form['email']
#             number = request.form['number']
#             password = request.form['password']
#             cpassword = request.form['cpassword']

#         u='iotuser';pw='iotpassword';h='localhost';db='iotdatabase'
#         mysqlm = MySQLManager(u,pw,h,db)
#         mysqlm.connect()

#         sql="UPDATE users SET %(username)s, %(email)s, %(number)s, %(password)s, %(role)s WHERE name = username"
#         updatedetails = {"username": username, "email": email, "number": number, "password": password, "role": role}
#         userupdate = mysqlm.insertupdatedelete(QUERYTYPE_UPDATE,sql,updatedetails)
#         mysqlm.disconnect()

#         if (userupdate):
#             session['username'] = username
#             return redirect(url_for('dashboard', username = username), code = 303)
#         else:
#             return render_template('profile.html', msg = "Unable to update, please try again")

#     except:
#         print(sys.exc_info()[0])
#         print(sys.exc_info()[1])

# this is to handle the dashboard data
@app.route("/api/getdashboarddata", methods=['GET', 'POST'])
def apidata_getdashboarddata():
    try:
        table_name = 'grabtable'
        print(f"Querying table {table_name}")
        dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
        table = dynamodb.Table(table_name)

        response = table.scan(AttributesToGet=['bookingid', 'speedkmhour'])

        lst = []
        for i in response['Items']:
            lst.append(i['bookingid'])
        unique_booking = set(lst)
        unique_booking_count = len(unique_booking)
        print(unique_booking_count)

        max_speed = []
        for i in response['Items']:
            max_speed.append(i['speedkmhour'])

        max_speed_value = max(max_speed)

        r = {}
        r['driver_data'] = unique_booking_count
        r['max_speed'] = max_speed_value

        return jsonify(json.loads(jsonc.data_to_json(r)))
        # return dashboarddata

    except:
        print(sys.exc_info()[0])
        print(sys.exc_info()[1])


@app.route("/api/getbookingdashboarddata", methods=['GET', 'POST'])
def apidata_getbookingdashboarddata():
    try:
        table_name = 'grabtable'
        print(f"Querying table {table_name}")
        dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
        table = dynamodb.Table(table_name)

        bookingid = '0.0'
        if 'getbookingid' in request.form:
            bookingid = request.form['getbookingid']
        response = table.scan(AttributesToGet=['bookingid', 'speedkmhour'])
        response2 = table.query(
            # KeyConditionExpression=key('bookingid').eq('0.0')
            # Add the name of the index you want to use in your query
            # IndexName is something like a primary key
            IndexName="bookingid-datetime_value-index",
            KeyConditionExpression=Key('bookingid').eq(bookingid),
            ScanIndexForward=False,
        )

        lst = []
        for i in response['Items']:
            lst.append(i['bookingid'])
        unique_booking = set(lst)
        unique_booking_count = len(unique_booking)
        print(unique_booking_count)

        max_speed = []
        for i in response2['Items']:
            max_speed.append(i['speedkmhour'])

        items = response2['Items']
        predicted = apidata_getPredict(items)

        predicted = predicted.astype(int)
        prediction = predicted[0]
        max_speed_value = max(max_speed)
        aver_speed_value = (sum(max_speed)/len(max_speed))
        aver_speed_value = round(aver_speed_value, 2)

        r = {}
        r['predict'] = prediction
        r['average_speed'] = aver_speed_value
        r['max_speed'] = max_speed_value

        return jsonify(json.loads(jsonc.data_to_json(r)))
        # return dashboarddata

    except:
        print(sys.exc_info()[0])
        print(sys.exc_info()[1])


def apidata_getPredict(items):
    try:
        df = pd.DataFrame(items, dtype=float)
        df['bearing'] = (df['bearing'] - df['bearing'].shift())
        df['bearing'] = df['bearing'].fillna(value=0)
        conv_bearings = [1 if values > 45 else 2 if values < -
                         45 else 0 for values in df.bearing]
        df['bearing'] = conv_bearings

        left_turn = [1 if values == 2 else 0 for values in df.bearing]
        df['left_turn'] = left_turn

        right_turn = [1 if values == 1 else 0 for values in df.bearing]
        df['right_turn'] = right_turn

        df['acc_gyro_x']=df['acceleration_x']*df['gyro_x']
        df['acc_gyro_y']=df['acceleration_y']*df['gyro_y']
        df['acc_gyro_z']=df['acceleration_z']*df['gyro_z']
        df['acc_gyro_xy']=np.sqrt(df['acc_gyro_x']**2+df['acc_gyro_y']**2)
        df['acc_gyro_xz']=np.sqrt(df['acc_gyro_x']**2+df['acc_gyro_z']**2)
        df['acc_gyro_yz']=np.sqrt(df['acc_gyro_z']**2+df['acc_gyro_y']**2)
        df['acc_gyro_xyz']=np.sqrt(df['acc_gyro_x']**2+df['acc_gyro_y']**2+df['acc_gyro_z']**2)

        
        pca_gyro = PCA(n_components=1).fit(
            df.loc[:, ['gyro_x', 'gyro_y', 'gyro_z']])
        pca_gyro.explained_variance_ratio_

        # transform triaxial gyro readings into its first principal components
        # need change gyro readings into
        df['gyro'] = pca_gyro.transform(
            df.loc[:, ('gyro_x', 'gyro_y', 'gyro_z')])
        df.drop(['gyro_x', 'gyro_y', 'gyro_z'], axis=1, inplace=True)
        df['acceleration_xy'] = df['acceleration_x']*df['acceleration_y']
        df['net_acceleration'] = np.sqrt(
            (df['acceleration_x'] ** 2) + (df['acceleration_y'] ** 2) + (df['acceleration_z'] ** 2))

        df.sort_values(['bookingid', 'seconds'], ascending=[True, True])

        df = df.drop(['id', 'speedkmhour', 'datetime_value', 'sort'], axis=1)
        # df.apply(pd.to_numeric)
        # df.astype(float)

        #df = pd.to_numeric(df['accuracy', 'bookingid', 'seconds', 'acceleration_y', 'acceleration_x', 'acceleration_z', 'speed', 'net_acceleration'])
        multi = ['min', 'max', 'mean']
        speedagg = ['max', 'mean', 'sum']
        features_data = df.groupby('bookingid', as_index=False).agg(
            {'left_turn' : 'sum' , 'right_turn' : 'sum','gyro': multi,'speed' : speedagg, 'seconds':'max', 'acc_gyro_x': 'mean', 'acc_gyro_y': 'mean', 'acc_gyro_z': 'mean', 'acc_gyro_xy': 'mean', 'acc_gyro_xz': 'mean', 'acc_gyro_yz': 'mean' ,'acc_gyro_xyz': 'mean', 'acceleration_xy': multi,'net_acceleration': multi})

        features_data.columns = features_data.columns.map(
            '_'.join).str.strip('_')

        X = features_data.drop(['bookingid'], axis=1)

        result = model.predict(X)

        return result

    except:
        print(sys.exc_info()[0])
        print(sys.exc_info()[1])

# @app.route("/api/getdashboarddata",methods=['GET', 'POST'])
# def apidata_getdashboarddata():
#     try:
#


#         #items = response['Items']

#         #n=10 # limit to last 10 items
#         dashboarddata = {'driver_data': unique_booking_count, 'average_speed_data': unique_booking_count, 'max_speed': unique_booking_count}

#         return dashboarddata
#     except:
#         print(sys.exc_info()[0])
#         print(sys.exc_info()[1])

# S3 bucket for Facial Recognition
BUCKET = 'iot-assignment2-fr'
location = {'LocationConstraint': 'us-east-1'}
# Get the images from static/saved_images
file_path = "../static/saved_images"


# Camera API
# Take Picture using CV2 library
@app.route("/api/camera", methods=['GET', 'POST'])
def camera():
    videoCaptureObject = cv2.VideoCapture(0)
    result = True
    date = datetime.now()
    while (result):
        ret, frame = videoCaptureObject.read()
        path = './static/saved_images'

        # datetime object containing current date and time
        now = datetime.now()

        # dd/mm/YY H:M:S
        date_string = datetime.now().strftime('-%d-%m-%Y-%H-%M-%S')
        cv2.imwrite(os.path.join(path, 'image'+date_string+'.jpg'), frame)
        result = False
        videoCaptureObject.release()
        cv2.destroyAllWindows()
        print('image saved!')

    return(path)


def uploadToS3(file_path, file_name, bucket_name, location):
    s3 = boto3.resource('s3')  # Create an S3 resource
    exists = True

    try:
        s3.meta.client.head_bucket(Bucket=bucket_name)
    except botocore.exceptions.ClientError as e:
        error_code = int(e.response['Error']['Code'])
        if error_code == 404:
            exists = False

    if exists == False:
        s3.create_bucket(Bucket=bucket_name,
                         CreateBucketConfiguration=location)

    # Upload the file
    full_path = file_path + "/" + file_name
    s3.Object(bucket_name, file_name).put(Body=open(full_path, 'rb'))
    print("File uploaded")


# Get Saved images
@app.route("/api/getImages", methods=['GET'])
def getImages():
    from PIL import Image
    import glob
    image_list = []
    for filename in glob.glob('./static/saved_images/*.jpg'):
        image_list.append(filename)

    print(image_list)

    return(jsonify(image_list))


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
    return render_template('profile.html', username=username)


@app.route("/showbookingid", methods=['GET', 'POST'])
def showbookingid():
    if 'getbookingid' in request.form:
        booking_value = request.form['getbookingid']
    if 'username' in session:
        username = escape(session['username'])
    return render_template('showbookingid.html', username=username, hidden_bookingid=booking_value)


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


@app.route("/facialRecog")
def facialRecog():
    if 'username' in session:
        username = escape(session['username'])
    return render_template('facerecog.html', username=username)


@app.route("/speedcheck")
def speedcheck():
    if 'username' in session:
        username = escape(session['username'])
    return render_template('speedcheck.html', username=username)


@app.route("/dashboard")
def dashboard():
    if 'username' in session:
        username = escape(session['username'])
    return render_template('dashboard.html', username=username)


if __name__ == '__main__':
    try:
        host = '0.0.0.0'
        port = 5000
        parser = argparse.ArgumentParser()
        parser.add_argument('port', type=int)

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
