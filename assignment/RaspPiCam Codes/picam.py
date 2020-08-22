import boto3
import botocore
from time import sleep
from AWSIoTPythonSDK.MQTTLib import AWSIoTMQTTClient

# Create an S3 resource
s3 = boto3.resource('s3')

full_path = '/home/pi/Desktop/image1.jpg'
file_name = 'image1.jpg'

host = "a19dfxc0pabiyn-ats.iot.us-east-1.amazonaws.com"
rootCAPath = "/home/pi/Desktop/labs/certs/AmazonRootCA1.pem"
certificatePath = "/home/pi/Desktop/labs/certs/certificate.pem.crt"
privateKeyPath = "/home/pi/Desktop/labs/certs/private.pem.key"
my_rpi = AWSIoTMQTTClient("PubSub-Capture")
my_rpi.configureEndpoint(host, 8883)
my_rpi.configureCredentials(rootCAPath, privateKeyPath, certificatePath)
my_rpi.configureOfflinePublishQueueing(-1)  # Infinite offline Publish queueing
my_rpi.configureDrainingFrequency(2)  # Draining: 2 Hz
my_rpi.configureConnectDisconnectTimeout(10)  # 10 sec
my_rpi.configureMQTTOperationTimeout(5)  # 5 sec

# Connect and subscribe to AWS IoT
my_rpi.connect()

def takePhotoWithPiCam():
	from picamera import PiCamera
	camera = PiCamera()
	sleep(1)
	camera.capture(full_path)
	sleep(1)

# Set the filename and bucket name
bucket = 'iot-assignment2-fr'
exists = True

try:
    s3.meta.client.head_bucket(Bucket=bucket)
except botocore.exceptions.ClientError as e:
    error_code = int(e.response['Error']['Code'])
    if error_code == 404:
        exists = False

if exists == False:
	s3.create_bucket(Bucket=bucket,CreateBucketConfiguration={
    	'LocationConstraint': 'us-east-1'})

def customCallback(client, userdata, message):
	print("Received a new message: ")
	print(message.payload)
	print("from topic: ")
	print(message.topic)
	print("--------------\n\n")
	takePhotoWithPiCam()
	s3.Object(bucket, file_name).put(Body=open(full_path, 'rb'))
	
my_rpi.subscribe("iot/capture", 1, customCallback)


while True:
	sleep(1)
# Take a photo
#takePhotoWithPiCam()





