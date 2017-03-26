// This class runs the server, in the real network scenario.  If you run the
// main, it will start a server that runs forever, always listening for new
// connections from clients.  
// Alternatively, you can write your own code that sets up a server.  To do 
// this, create a NetworkServer object (by calling the constructor), then
// call serverLoop on it.  Note that the constructor alone does some setup but
// it does not start the server actually running.  Note also that serverLoop
// never returns.  Instead, it sits in an infinite loop waiting for clients
// to connect to it, and starting a new ServerThread for every client that
// connects.
//

import java.net.ServerSocket;
import java.net.Socket;

import java.io.FileNotFoundException;
import java.io.IOException;


public class NetworkServer {
	private ServerContext context;
	private ServerSocket  serverSock;

	public NetworkServer(int portNum, RSAKey privateKey, PRGen prg, 
		String blockStoreDirectoryName) 
	throws DataIntegrityException, IOException, FileNotFoundException {
		BlockDevice bd = new BlockDevice(blockStoreDirectoryName);
		ServerSocket ssock = new ServerSocket(portNum);
		context = new ServerContext(bd, privateKey, prg);
		serverSock = new ServerSocket(portNum);
	}

	public void serverLoop() throws IOException {
		while(true) {
			Socket sock = serverSock.accept();
			ServerThread st = new ServerThread(context, 
				sock.getInputStream(), sock.getOutputStream());
			st.start();
		}
	}

	public static void main(String[] args) throws DataIntegrityException, 
	FileNotFoundException, IOException {
		int port = Integer.parseInt(args[0]);
		String blockDeviceDirectoryName = args[1];
		String privateKeyFileName = KeyHandler.defaultPrivKeyFileName;
		if(args.length > 2) {
			privateKeyFileName = args[2];
		}

		RSAKey privKey = KeyHandler.readKeyFromFile(privateKeyFileName);

		byte[] prgSeed = new byte[PRGen.KEY_SIZE_BYTES];
		byte[] randBytes = TrueRandomness.get();
		for(int i=0; i<TrueRandomness.NumBytes; ++i){
			prgSeed[i] = randBytes[i];
		}
		PRGen prg = new PRGen(prgSeed);

		NetworkServer ns = new NetworkServer(port, privKey, prg, 
			blockDeviceDirectoryName);
		ns.serverLoop();
	}
}