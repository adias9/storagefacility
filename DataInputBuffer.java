// This class is useful for parsing messages that were built using the
// DataOutputBuffer class.  When you call the constructor, it receives a
// message on the (passed-in) SecureChannel. The received message can then
// be consumed, piece by piece, by calling the read* methods. 
//
// If a message was build using a DataOutputBuffer, you can consume it using
// this class.  Your calls to the read* methods of this class should follow 
// exactly the sequence of calls made to the corresponding write* methods of
// DataOutputBuffer.

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;

import java.io.IOException;


public class DataInputBuffer {
	private ByteArrayInputStream bais;
	private DataInputStream      dis;

	public DataInputBuffer(SecureChannel chan) throws IOException {
		byte[] msg = chan.receiveMessage();
		bais = new ByteArrayInputStream(msg);
		dis = new DataInputStream(bais);
	}

	public byte readByte() throws IOException {
		return dis.readByte();
	}

	public boolean readBoolean() throws IOException {
		byte b = readByte();
		return (b != (byte)0);
	}

	public int readInt() throws IOException {
		return dis.readInt();
	}

	public String readString() throws IOException {
		return dis.readUTF();
	}

	public byte[] readByteArray() throws IOException {
		int len = readInt();
		byte[] ret = new byte[len];
		for(int i=0; i<len; ++i){
			ret[i] = readByte();
		}
		return ret;
	}
}