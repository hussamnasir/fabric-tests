import struct
import array
import time
import select
import socket
import sys
maxfds = 1024
if(len(sys.argv)!=2):
    print("usage: ",sys.argv[0]," <send|receive>")
    sys.exit()
print(sys.argv[1]);
if(sys.argv[1]=='send'):
    MESSAGE = "Hello, World!"
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    s.connect(('10.33.128.130', 10000))
    s.send(MESSAGE.encode())
    time.sleep(0.0001)
    #time.sleep(5)
    s.send(MESSAGE.encode())
    s.close()
else:
    SO_TIMESTAMPNS = 35
    #s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setblocking(0)

    server.setsockopt(socket.SOL_SOCKET, SO_TIMESTAMPNS, 1)
    server.bind(('10.33.128.130', 10000))
    server.listen(5)
    inputs = [ server ]
    message_queues = {}
    outputs = []
    while inputs:
        print('\nwaiting for the next event')
        readable, writable, exceptional = select.select(inputs, outputs, inputs)
        for s in readable:
            if s is server:
                connection, client_address = s.accept()
                print('new connection from', client_address)
                connection.setblocking(0)
                inputs.append(connection)                
            else:
                fds = array.array("i")   # Array of ints
                #raw_data, ancdata, flags, address = s.recvmsg(65535, 1024)
                raw_data, ancdata, flags, address = s.recvmsg(65535,socket.CMSG_LEN(maxfds * fds.itemsize))
                #print(s.recvmsg(65535,socket.CMSG_LEN(maxfds * fds.itemsize)))
                print('received ', raw_data.decode(), '-',ancdata,'-',flags,'-',address)
                if(len(ancdata)>0):
                 #   print(len(ancdata),len(ancdata[0]),ancdata[0][0],ancdata[0][1],ancdata[0][2])
                 #   print('ancdata[0][2]:',type(ancdata[0][2])," - ",ancdata[0][2], " - ",len(ancdata[0][2]));
                    for i in ancdata:
                        print('ancdata: (cmsg_level, cmsg_type, cmsg_data)=(',i[0],",",i[1],", (",len(i[2]),") ",i[2],")");
                        if(i[0]!=socket.SOL_SOCKET or i[1]!=SO_TIMESTAMPNS):
                            continue
                        tmp=(struct.unpack("iiii",i[2]))
                        timestamp = tmp[0] + tmp[2]*1e-10
                        print("SCM_TIMESTAMPNS,", tmp, ", timestamp=",timestamp)
                if(not raw_data):
                    print('closing after reading no data')
                    # Stop listening for input on the connection
                    if s in outputs:
                        outputs.remove(s)
                    inputs.remove(s)
                    s.close()
