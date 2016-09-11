import socket
from Crypto.Cipher import AES
import os
import random
tcp_port = 5006
buffer = 1280
recevinfo = {}
prog = 0
file = 0
timeout = 1000

print("TCP recieve port:" + str(tcp_port))

def sendMessage(message,cs):
    message = bytes(message,"utf-8")
    cs.send(message)

def sendBytes(bytes1,cs):
    cs.send(bytes1)

def encryptData(bytes1,obj):
    return obj.encrypt(bytes1)

def decryptData(bytes1,obj):
    return obj.decrypt(bytes1)

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

def openServer():
    try:
        mode = 0
        sharedSecret = 0
        serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        serversocket.bind(("", tcp_port))

        # accept connections from outside
        print("Ready for new client")

        serversocket.listen(1)
        (clientsocket, address) = serversocket.accept()
        ip = address[0]
        port = address[1]
        aesobj = None

        while mode > -1:

            data = clientsocket.recv(buffer)
            if (mode == 1) :
                dag = True
                while dag:
                    try:
                        file = open(recevinfo["dest"], "a+b")
                        file.write(decryptData(data,aesobj))
                        prog = prog + len(data)
                        #print(str(round(prog/recevinfo["length"]) * 100) + "% Uploaded")
                        file.close()
                        dag = False
                    except Exception:
                        dag = True
                sendMessage("ACK",clientsocket)
                if (prog >= recevinfo["length"]):
                    print("File Recieved")
                    mode = -1

            if (mode == 2) :
                sourceLength = os.path.getsize(recevinfo["source"])
                sendMessage(str(sourceLength),clientsocket)
                prog1 = 0
                fs = open(recevinfo["source"], "rb")
                fs.seek(0)
                while prog1 < sourceLength:
                    message = str(clientsocket.recv(buffer),"utf-8")
                    parsedata = message.split("///")
                    fcn = parsedata[0]
                    if fcn == "NFCH":                  
                        b = bytearray(encryptData(fs.read(buffer),aesobj))
                        sendBytes(b,clientsocket)
                        prog1 = prog1 + len(b)
                print("Delivered file")
                mode = -1

            if (mode == 0) :
                data = str(data,"utf-8")
                parsedata = data.split("///")
                fcn = parsedata[0]
                print(fcn)
                if (fcn == "ICFL") :
                    print("Recieving File : " + parsedata[1])
                    #print(parsedata[1])
                    mode = 1
                    recevinfo = {"dest":parsedata[1],"length":int(parsedata[2])}
                    file = open(recevinfo["dest"], "w+b")
                    file.close()
                    prog = 0
                if (fcn == "RCFL") :
                    print("Sending File : " + parsedata[1])
                    sourceLength = os.path.getsize(parsedata[1])
                    recevinfo = {"source":parsedata[1],"length":int(sourceLength)}
                    sendMessage("FLEN" + "///" + str(sourceLength),clientsocket)
                    mode = 2
                    prog = 0
                if (fcn == "DHKE") :
                    commonKey = random.SystemRandom().randint(0,2**2048)
                    secretKey = random.SystemRandom().randint(0,2**2048)
                    initVector = random.SystemRandom().randint(0,2**(16*8))
                    #print(commonKey)
                    sendMessage(str(commonKey),clientsocket)
                    genKeyA = commonKey * secretKey
                    recKeyA = int(str(clientsocket.recv(buffer),"utf-8"))
                    sendMessage(str(genKeyA),clientsocket)
                    sharedSecret = recKeyA * secretKey
                    sendMessage(str(initVector),clientsocket)
                    aesobj = AES.new(bytes(base256_encode(sharedSecret)).ljust(32)[:32], AES.MODE_CFB, bytes(base256_encode(initVector)).ljust(16)[:16])
                    #print(sharedSecret)
                    #print(str(recKeyA))
            #print(parsedata[1])
            #rint(parsedata[2])

        mode = 0
    except Exception:
        print("Socket terminated")

while True:
    openServer()
