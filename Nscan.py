import requests
import IPy
import threading 
import socket
import sys
import time
import re
import queue

def getTitle(url, port = 80):
    """
      getTitle 
        Fix: May can get title from response message .
    """
    res = requests.get("http://"+url+":"+str(port))
    if(res.status_code == 200):
        try:
            title = re.findall("<title>(.*?)</title>", res.text)[0]
        except:
            title = ""
    
    return title

def portScan(q):
    """
     portScan use tcp socket connect .
    """
    global datas

    while True:
        (ip, port) = q.get()
        # print("Scaning "+ip+":"+str(port))

        if port>65535:
            print("Error: The port "+str(port)+"filed !")

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = s.connect_ex((ip, port))
        
        if result == 0:
            if port == 80:  # fix ：May can from response message judge http
                title = getTitle(ip, port)

            data = "[*] " + ip + ":"+str(port) + "   OPNE   " + title + "\n"
            print(data)
            datas.append(data)
        q.task_done()    

def scan(IPs, ports):
    for i in IPs:
        for p in ports:
            i = i.strNormal()
            p = int(p)
            q.put((i,p))

def threadPool(thread_num):
    print("[*] Start "+str(thread_num)+" threads scan !")
    threads = []
    for i in range(thread_num):
        t = threading.Thread(target=portScan, args = (q,))
        t.start()
        threads.append(t)


    # for thread in threads:
    #     thread.join()



def readfile():
    with open(file, "r") as f:
        pass

def getParaments():
    """

    """
    pms = sys.argv[1:]
    IPs = []
    ports = [80, 8080, 3389]
    file = "test_"+str(time.ctime())+".txt"
    thread_num = 100

    if len(pms) < 1:
        print("[-] Please input paraments !")
        help()
        exit(0)

    for pm in pms:
        if (pm == "-h"):
            help()
            exit(0)
        if pm == "-t":
            IPs = IPy.IP(pms[pms.index(pm)+1])
        if pm == "-r":
            IPs = readfile(pm+1) //Fix

        if pm == "-p":
            pList = []
            ports = pms[pms.index(pm)+1]
            ports = ports.split(",")

            for p in ports:
                if "-" in p:
                    p2p = p.split("-")
                    for i in range(int(p2p[0]), int(p2p[1])+1):
                        pList.append(i)
                else:
                    pList.append(p)

        if pm == "-o":
            file = pms[pms.index(pm)+1]

        if pm == "--t":
           tread_num = pms[pms.index(pm)+1]

    return IPs, pList, file, thread_num


def output(file, datas = []):
    try:
        with open(file, "w") as f:
            for data in datas:
                print(data)
                f.write(data)
            f.close()
        print("[*] The data successful saved "+file)
    except:
        pass

def help():
        print("------------------------------------------------------------------------\n")
        print("-h           help")
        print("-t           target IP address")
        print("-r           IP file")
        print("           -I file.txt(.xls|xlsx)")
        print("-p           port")
        print("           -p 80,8000-9000")
        print("-o           output file ")
        print("--t          thread number ")
        print()
        print("Usage:   python3 Nscan.py -t 192.168.100.0/24 -p 80,8080-10000 -o test.txt")
        print("         python3 Nscan.py -r file.txt -p 80-2333 -o test.txt")
        print("----------------------------------------------------------------------\n\n")



if __name__ == "__main__":
    datas = []
    stime = time.time()
    [IPs, ports, file, thread_num] = getParaments()
    lock = threading.Lock()

    q = queue.Queue()
    threadPool(thread_num)
    scan(IPs, ports)  
    print("[*] Runing ...") 

    # output(file, datas)  # FIX 
    # print("[*] This scan speed about "+str(time.time()-stime)+"s !")
