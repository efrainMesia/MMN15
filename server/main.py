import server

if __name__ == '__main__':

    port = 7777
    #if port is None:
    #    utils.stopServer(f"Failed to parse integer port from '{PORT_INFO}'!")
    svr = server.Server()  # don't care about host.
    svr.start()
    #if not svr.start():
    #    utils.stopServer(f"Server start exception: {svr.lastErr}")