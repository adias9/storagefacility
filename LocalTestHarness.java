// This class allows you to run the full client and server together in a 
// single program, in a way that simulates across-the-network communication.
// This is useful for developing and testing your code, because it is less
// complicated to start and run your software using this, compared to running
// separate programs that communicate via the network.
//
// The constructor of this class sets up a server that is listening for
// connections.
//
// The newClientSession method creates a new client that connects to the server.
// On the server side, it creates a new ServerThread to handle requests from
// the new client.  On the client side, it creates a new StorageClientSession.
// This new StorageClientSession is returned from the method.
//
// DO NOT MODIFY THIS FILE.

import java.io.InputStream;
import java.io.OutputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;

import java.io.IOException;


public class LocalTestHarness {
	private ServerContext serverContext;
	private RSAKey        serverPublicKey;
	private PRGen         clientPrg;

	public LocalTestHarness(BlockDevice device, RSAKey serverPrivateKey,
		RSAKey serverPublicKey, PRGen prg) throws DataIntegrityException {

		serverContext = new ServerContext(device, serverPrivateKey, prg);
		this.serverPublicKey = serverPublicKey;
		clientPrg = prg;
	}

	public StorageClientSession newClientSession() throws IOException { 
		// create streams
		PipedInputStream serverIS = new PipedInputStream();
		PipedOutputStream clientOS = new PipedOutputStream(serverIS);
		PipedInputStream clientIS = new PipedInputStream();
		PipedOutputStream serverOS = new PipedOutputStream(clientIS);

		// start a server thread
		ServerThread st = new ServerThread(serverContext, serverIS, serverOS);
		st.setDaemon(true);
		st.start();

		// create a client session
		return new StorageClientSession(clientIS, clientOS,
			serverPublicKey, clientPrg);
	}
}