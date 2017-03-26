// This class implements the server-side code to receive and execute 
// commands sent by a single client. There will be one ServerThread for each
// currently active client. 
// The bulk of the action here is in the big while loop in the run method,
// which receives a command, calls the correct server-side code to execute
// the command, then sends back a response to the client.
//
// DO NOT MODIFY CODE IN THIS FILE.
//

import java.io.InputStream;
import java.io.OutputStream;

import java.io.EOFException;
import java.io.IOException;


public class ServerThread extends Thread {
	private ServerContext context;
	private InputStream   inStream;
	private OutputStream  outStream;
	private ArrayStore    arrayStore;

	public ServerThread(ServerContext ctxt, 
		InputStream inStream, OutputStream outStream) throws IOException {

		context = ctxt;
		this.inStream = inStream;
		this.outStream = outStream;
	}

	public void run() {
		try {
			SecureChannel channel = new SecureChannel(inStream, outStream, 
				context.prg, true, context.privateKey);

			while(true) {
				DataInputBuffer dib = new DataInputBuffer(channel);
				byte cmd = dib.readByte();
				switch(cmd) {
				case ServerContext.CommandPing:
					int nbytes = dib.readInt();
					DataOutputBuffer dob = new DataOutputBuffer(channel);
					dob.writeInt(nbytes);
					for(int i=0; i<nbytes; ++i){
						dob.writeByte(dib.readByte());
					}
					dob.send();
					break;
				case ServerContext.CommandAuthenticate:
					String username = dib.readString();
					String password = dib.readString();
					try {
						BlockStore bs = context.auth.auth(username, password);
						if(bs==null) {
							// authentication failed
							arrayStore = null;
						}else{
							arrayStore = new ArrayStore(bs);
						}
					} catch(DataIntegrityException x) {
						x.printStackTrace();
						arrayStore = null;
					}
					dob = new DataOutputBuffer(channel);
					dob.writeBoolean(arrayStore != null);
					dob.send();
					break;
				case ServerContext.CommandCreateAccount:
					username = dib.readString();
					password = dib.readString();
					try {
						BlockStore bs = context.auth.createUser(username, password);
						if(bs==null){
							arrayStore = null;
						}else{
							arrayStore = new ArrayStore(bs);
						}
					} catch(DataIntegrityException x) {
						x.printStackTrace();
						arrayStore = null;
					}
					dob = new DataOutputBuffer(channel);
					dob.writeBoolean(arrayStore != null);
					dob.send();
					break;
				case ServerContext.CommandWrite:
					nbytes = dib.readInt();
					int storageOffset = dib.readInt();
					byte[] buf = new byte[nbytes];
					for(int i=0; i<nbytes; ++i){
						buf[i] = dib.readByte();
					}
					int retCode = ServerContext.SuccessCode;
					if(arrayStore == null){
						retCode = ServerContext.UnauthorizedCode;
					}else{
						try {
							arrayStore.write(buf, 0, storageOffset, nbytes);
						}catch(DataIntegrityException x){
							retCode = ServerContext.DataIntegrityFailureCode;
						}
					}
					dob = new DataOutputBuffer(channel);
					dob.writeInt(retCode);
					dob.send();
					break;
				case ServerContext.CommandRead:
					nbytes = dib.readInt();
					storageOffset = dib.readInt();
					buf = new byte[nbytes];
					retCode = ServerContext.SuccessCode;
					if(arrayStore == null){
						retCode = ServerContext.UnauthorizedCode;
					}else{
						try {
							arrayStore.read(buf, 0, storageOffset, nbytes);
						}catch(DataIntegrityException x){
							retCode = ServerContext.DataIntegrityFailureCode;
						}
					}
					dob = new DataOutputBuffer(channel);
					dob.writeInt(retCode);
					if(retCode==ServerContext.SuccessCode){
						for(int i=0; i<nbytes; ++i){
							dob.writeByte(buf[i]);
						}
					}
					dob.send();
					break;
				default:
					System.err.println("ServerThread: invalid command received\n");
				}
			}
		}catch(EOFException x) {
			return;
		}catch(IOException x) {
			x.printStackTrace();
			return;
		}
	}
}