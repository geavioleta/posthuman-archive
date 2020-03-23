from django.shortcuts import render
from django.http import HttpResponse, JsonResponse
import base64, hashlib, os, random, time
from Crypto import Random
from Crypto.Cipher import AES
from archive.models import ActiveIP
import boto3

class AESCipher(object):

    def __init__(self, key): 
        self.key = hashlib.sha256(key.encode()).digest()

    def encrypt(self, raw):
        raw = self._pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw))

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self._unpad(cipher.decrypt(enc[AES.block_size:]))

    def _pad(self, s):
        return s + (AES.block_size - len(s) % AES.block_size) * chr(AES.block_size - len(s) % AES.block_size).encode()

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s)-1:])]

def index(request):
    return render(request, 'index.html')

def ecies(request):
	return render(request, 'ecies.html')

def download(request):
	activeIP, created = ActiveIP.objects.get_or_create(ip=get_client_ip(request))
	now = int(time.time())
	if activeIP.time + 86400 < now:
		activeIP.downloads = 0
		activeIP.time = now
	if activeIP.downloads >= 5:
		return HttpResponse("LIMIT REACHED: MAXIMUM 5 DOWNLOADS EVERY 24 HOURS")
	east = boto3.Session(region_name = 'us-east-1')
	s3 = east.resource('s3', aws_access_key_id=os.environ.get('AWS_ACCESS_ID'), aws_secret_access_key=os.environ.get('AWS_SECRET_KEY'))
	dataBucketName = "secret-archive"
	dataBucket = s3.Bucket(dataBucketName)
	all_files = [obj.key for obj in dataBucket.objects.all()]
	file = random.choice(all_files)
	temp_name = randomString(25)
	s3.meta.client.download_file(dataBucketName, file, os.path.join(os.path.dirname(__file__), temp_name))
	with open(os.path.join(os.path.dirname(__file__), temp_name), "rb") as f:
		encdata = f.read()
	os.remove(os.path.join(os.path.dirname(__file__), temp_name))
	data = AESCipher(os.environ.get('ARCHIVE_KEY')).decrypt(encdata)
	extfinder = file.split(".")
	ext = ""
	if len(extfinder) > 1:
		ext = "."+extfinder[-1]
	filename = randomString(10)+ext
	response = HttpResponse(data)
	response['Content-Disposition'] = f'attachment; filename="{filename}"'
	activeIP.time = now
	activeIP.downloads += 1
	activeIP.save()
	return response

def upload(request):
	if request.method != "POST":
		return HttpResponse("Internal Server Error (500)")
	passphrase = request.POST.get("pass") 
	if passphrase != os.environ.get('ARCHIVE_KEY'):
		return HttpResponse("Incorrect Passphrase")
	if request.FILES['newUpload'].size > 25000000:
		return HttpResponse("File is too large to upload (25MB maximimum)")
	data = request.FILES['newUpload'].read()
	extfinder = request.FILES['newUpload'].name.split(".")
	ext = ""
	if len(extfinder) > 1:
		ext = extfinder[-1]
	encrypt_upload(data, ext)
	return HttpResponse("File uploaded")

def desktop_encrypt(request):
	return render(request, 'instructions.html')

def encrypt_upload(data, file_ext):
	filename = randomString(25)
	enc = AESCipher(os.environ.get('ARCHIVE_KEY')).encrypt(data)
	with open(os.path.join(os.path.dirname(__file__), filename), "wb") as f:
		f.write(enc)
	east = boto3.Session(region_name = 'us-east-1')
	s3 = east.resource('s3', aws_access_key_id=os.environ.get('AWS_ACCESS_ID'), aws_secret_access_key=os.environ.get('AWS_SECRET_KEY'))
	dataBucketName = "secret-archive"
	name = randomString(10)
	if file_ext != "":
		name += "."+file_ext
	s3.meta.client.upload_file(os.path.join(os.path.dirname(__file__), filename), dataBucketName, name)
	link = "https://s3.amazonaws.com/secret-archive/"+name
	obj = s3.Bucket('secret-archive').Object(name)
	obj.Acl().put(ACL='public-read')
	os.remove(os.path.join(os.path.dirname(__file__), filename))

def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[-1]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip

def randomString(n):
	chars = "a b c d e f g h i j k l m n o p q r s t u v q x y z A B C D E F G H I J K L M N O P Q R S T U V W X Y Z 1 2 3 4 5 6 7 8 9".split()
	return "".join([random.choice(chars) for _ in range(n)])

