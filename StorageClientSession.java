
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;

import java.io.IOException;
import java.net.UnknownHostException;


public class StorageClientSession {
	private SecureChannel channel;
	private boolean       authenticated = false;

	public StorageClientSession(String serverHostname, int serverPort, 
		String serverPublicKeyFilename, PRGen prg) 
	throws UnknownHostException, IOException {
		// This constructor connects to a server across the network.
		Socket sock = new Socket(serverHostname, serverPort);
		RSAKey serverKey = KeyHandler.readKeyFromFile(serverPublicKeyFilename);
		channel = new SecureChannel(sock.getInputStream(), 
			sock.getOutputStream(), prg, false, serverKey);
	}

	public StorageClientSession(InputStream inStr, OutputStream outStr,
		RSAKey serverPublicKey, PRGen prg) throws IOException {
		// This constructor connects to a local server (e.g. one set up by
		// LocalTestHarness).
		channel = new SecureChannel(inStr, outStr, prg, false, 
			serverPublicKey); 
	}

	public void testPing(int nbytes, int offset, byte[] buf) throws IOException {
		// send bytes to server, see what server sends back
		// assertion will fail if server sends back something different
		DataOutputBuffer dob = new DataOutputBuffer(channel);
		dob.writeByte(ServerContext.CommandPing);
		dob.writeInt(nbytes);
		for(int i=0; i<nbytes; ++i){
			dob.writeByte(buf[i+offset]);
		}
		dob.send();
		DataInputBuffer dib = new DataInputBuffer(channel);
		int nbytesRecvd = dib.readInt();
		assert nbytesRecvd == nbytes;
		for(int i=0; i<nbytes; ++i){
			byte recvd = dib.readByte();
			assert recvd == buf[i+offset];
		}
	}

	public void authenticate(String name, String password) 
		throws AccessDeniedException, IOException {
		// Authenticate as the user <name>, with password <password>.
		// If no account exists for <name>, or if <password> is not the correct 
		// password for <name>, then throw AccessDeniedException.
		DataOutputBuffer dob = new DataOutputBuffer(channel);
		dob.writeByte(ServerContext.CommandAuthenticate);
		dob.writeString(name);
		dob.writeString(password);
		dob.send();

		DataInputBuffer dib = new DataInputBuffer(channel);
		boolean success = dib.readBoolean();
		if(success){
			authenticated = true;
		}else{
			throw new AccessDeniedException();
		}
	}

	public void createAccount(String name, String password) 
		throws AccessDeniedException, IOException {
		// If this client is already authenticated, throw AccessDeniedException.
		// Otherwise, if an account already exists for <name>, 
		// throw AccessDeniedException.
		// Otherwise, create an account for <name> with password <password>.
		if(authenticated){
			throw new AccessDeniedException();
		}
		DataOutputBuffer dob = new DataOutputBuffer(channel);
		dob.writeByte(ServerContext.CommandCreateAccount);
		dob.writeString(name);
		dob.writeString(password);
		dob.send();

		DataInputBuffer dib = new DataInputBuffer(channel);
		boolean success = dib.readBoolean();
		if(! success)    throw new AccessDeniedException();
	}

	public void write(int nbytes, int storageOffset, int bufOffset, byte[] buf) 
		throws AccessDeniedException, IOException {
		// If this client is not authenticated, throw AccessDeniedException.
		// Otherwise, write data to the storage of the authenticated user.
		if( ! authenticated){
			throw new AccessDeniedException();
		}

		DataOutputBuffer dob = new DataOutputBuffer(channel);
		dob.writeByte(ServerContext.CommandWrite);
		dob.writeInt(nbytes);
		dob.writeInt(storageOffset);
		for(int i=0; i<nbytes; ++i){
			dob.writeByte(buf[bufOffset+i]);
		}
		dob.send();

		DataInputBuffer dib = new DataInputBuffer(channel);
		int retCode = dib.readInt();
		if(retCode == ServerContext.UnauthorizedCode){
			throw new AccessDeniedException();
		}else if(retCode == ServerContext.DataIntegrityFailureCode){
			throw new IOException("Integrity failure on server");
		}
	}

	public void read(int nbytes, int storageOffset, int bufOffset, byte[] buf) 
		throws AccessDeniedException, IOException {
		// If this client is not authenticated, throw AccessDeniedException.
		// Otherwise, read data from the storage of the authenticated user.

		if( ! authenticated){
			throw new AccessDeniedException();
		}

		DataOutputBuffer dob = new DataOutputBuffer(channel);
		dob.writeByte(ServerContext.CommandRead);;
		dob.writeInt(nbytes);
		dob.writeInt(storageOffset);
		dob.send();

		DataInputBuffer dib = new DataInputBuffer(channel);
		int retCode = dib.readInt();
		if(retCode == ServerContext.UnauthorizedCode){
			throw new AccessDeniedException();
		}else if(retCode == ServerContext.DataIntegrityFailureCode){
			throw new IOException("Integrity failure on server");
		}
		for(int i=0; i<nbytes; ++i){
			buf[bufOffset+i] = dib.readByte();
		}
	}
}