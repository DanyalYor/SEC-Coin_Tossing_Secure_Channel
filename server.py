import socket
import selectors
import sys
import types


def accept_wrapper(sock):
    conn, addr = sock.accept()
    print(f"Accepted connection from {addr}")
    conn.setblocking(False)
    data = types.SimpleNamespace(addr=addr, inb=b"", outb=b"")
    events = selectors.EVENT_READ | selectors.EVENT_WRITE
    sel.register(conn, events, data=data)


def service_connection(key, mask):
    sock = key.fileobj
    data = key.data
    if mask & selectors.EVENT_READ:
        recv_data = sock.recv(1024)
        if recv_data:
            data.outb += recv_data
        else:
            print(f"Closing connection to {data.addr}")
            sel.unregister(sock)
            sock.close()
    if mask & selectors.EVENT_WRITE:
        if data.outb:
            print(f"Echoing {data.outb!r} to {data.addr}")
            sent = sock.send(data.outb)
            data.outb = data.outb[sent:]


# Using selector for multiple connections
sel = selectors.DefaultSelector()

# Setting up the listening socket
host, port = sys.argv[1], int(sys.argv[2])
lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
lsock.bind((host, port))
lsock.listen()
print(f"Listening on {(host, port)}")

""""
Ensures that the socket does not Block whenever a call is made,
therefore, we can wait for events on one or more sockets
"""
lsock.setblocking(False)

# Setting the listening socket to read events
sel.register(lsock, selectors.EVENT_READ, data=None)

# Listening for sockets
try:
    while True:
        events = sel.select(timeout=None)
        for key, mask in events:
            if key.data is None:
                # New connection. Accept it.
                accept_wrapper(key.fileobj)
            else:
                # Already registered. Service it.
                service_connection(key, mask)
except KeyboardInterrupt:
    # Mac: Cmd + D
    # Linux & Windows: Ctrl + D
    print("Caught keyboard interrupt, exiting")
finally:
    sel.close()
