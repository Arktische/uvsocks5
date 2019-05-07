import socks

s = socks.socksocket() # Same API as socket.socket in the standard lib

s.set_proxy(socks.SOCKS5, "127.0.0.1",1080, True, "foo", "foobar") # SOCKS4 and SOCKS5 use port 1080 by default

# Can be treated identical to a regular socket object
s.connect(("www.baidu.com.com", 80))
s.sendall(bytes("GET / HTTP/1.1\r\nHost: baidu.com\r\nUser-Agent: curl/7.68.0\r\nAccept: */*\r\n\r\n", "utf8"))
print(s.recv(4096))