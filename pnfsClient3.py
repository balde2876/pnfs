import socket
from Crypto.Cipher import AES
import os
import random
tcp_ip = "127.0.0.1"
tcp_port = 2871
buffer = 1280
prog1 = 0
sourceLength = 0
clientsocket = None
sharedSecret = 0
initVector = 0

def base256_encode(n, minwidth=0): # int/long to byte array
    if n > 0:
        arr = []
        while n:
            n, rem = divmod(n, 256)
            arr.append(rem)
        b = bytearray(reversed(arr))
    elif n == 0:
        b = bytearray(b'\x00')
    else:
        raise ValueError

    if minwidth > 0 and len(b) < minwidth: # zero padding needed?
        b = (minwidth-len(b)) * '\x00' + b
    return b

def sendFile(destinationFile,sourceFile):
    prepareConnection()
    aesobj = AES.new(bytes(base256_encode(sharedSecret)).ljust(32)[:32], AES.MODE_CFB, bytes(base256_encode(initVector)).ljust(16)[:16])

    sourceLength = os.path.getsize(sourceFile)
    sendMessage("ICFL" + "///" + destinationFile + "///" + str(sourceLength))
    prog1 = 0
    fs = open(sourceFile, "rb")
    fs.seek(0)
   
    while prog1 < sourceLength:
        b = encryptData(bytes(bytearray(fs.read(buffer))),aesobj)
        sendBytes(b)
        prog1 = prog1 + len(b)
        parsedata = getMessage().split("///")
        fcn = parsedata[0]
        if not (fcn == "ACK") :
            raise Exception('ACK command not recieved')

def getFile(destinationFile,sourceFile):
    prepareConnection()
    aesobj = AES.new(bytes(base256_encode(sharedSecret)).ljust(32)[:32], AES.MODE_CFB, bytes(base256_encode(initVector)).ljust(16)[:16])
    
    sendMessage("RCFL" + "///" + sourceFile)
    data = getMessage()
    parsedata = data.split("///")
    fileLength = int(parsedata[1])

    f = open(destinationFile,"wb")
    f.seek(fileLength-1)
    f.write(b"\0")
    f.close()
    
    fileRecv = False
    prog = 0
    if parsedata[0] == "FLEN":
        while fileRecv == False:
            dag = True
            sendMessage("NFCH")
            #print("NFCH")
            data = getBytes()
            while dag:
                try:
                    file = open(destinationFile, "r+b")
                    file.seek(prog)
                    file.write(decryptData(data,aesobj))
                    prog = prog + len(data)
                    #print(str(round(prog/recevinfo["length"]) * 100) + "% Downloaded")
                    file.close()
                    dag = False
                except Exception:
                    ##print("err,try again")
                    dag = True
            #print("written chunk")
            if (prog >= fileLength):
                fileRecv = True
                print("File Recieved")
                mode = -1
    else:
        print(parsedata[0])
        raise Exception("Invalid Response")

def sendMessage(message):
    message = bytes(message,"utf-8")
    clientsocket.send(message)

def sendBytes(bytes1):
    clientsocket.send(bytes1)

def getMessage():
    message = str(clientsocket.recv(buffer),"utf-8")
    return message

def getBytes():
    return clientsocket.recv(buffer)

def encryptData(bytes1,obj):
    return obj.encrypt(bytes1)

def decryptData(bytes1,obj):
    return obj.decrypt(bytes1)

def prepareConnection():
    global sharedSecret
    global initVector
    sendMessage("DHKE")
    commonKey = int(getMessage())
    secretKey = random.SystemRandom().randint(0,2**2048)
    #print(str(commonKey))
    genKeyA = commonKey * secretKey
    sendMessage(str(genKeyA))
    recKeyA = int(getMessage())
    #print(str(recKeyA))
    sharedSecret = int(recKeyA * secretKey)
    initVector = int(getMessage())
    #print(sharedSecret)
    #getMessage()

#try:
#sendFile("l.mp3","m.mp3")

#except Exception:
    #print("Fatal error")
clientsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
clientsocket.connect((tcp_ip, tcp_port))
getFile("2.mp3","m.mp3")
clientsocket.close()
clientsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
clientsocket.connect((tcp_ip, tcp_port))
sendFile("l.mp3","m.mp3")
clientsocket.close()
