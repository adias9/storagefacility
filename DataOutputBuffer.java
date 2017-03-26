// This class is useful for building messages to be sent on a channel.
// You make a DataOutputBuffer, giving the constructor a channel on which
// the message will eventually (but not immediately) be sent.  You then
// call the write* methods, one or more times, to build up a message.
// When you are done building the message, you call the send method, which
// sends the message you have constructed.
//
// This method helps you build a message containing multiple data fields.
// Messages built using this class will usually be consumed by an 
// an instance of the DataInputBuffer class.

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;

import java.io.IOException;


public class DataOutputBuffer {
	private SecureChannel         outChan;
	private ByteArrayOutputStream baos;
	private DataOutputStream      dos;

	public DataOutputBuffer(SecureChannel chan) {
		outChan = chan;
		baos = new ByteArrayOutputStream();
		dos = new DataOutputStream(baos);
	}

	public void writeByte(byte b) throws IOException {
		dos.writeByte(b);
	}

	public void writeBoolean(boolean b) throws IOException {
		if(b){
			writeByte((byte)1);
		}else{
			writeByte((byte)0);
		}
	}

	public void writeInt(int i) throws IOException {
		dos.writeInt(i);
	}

	public void writeString(String s) throws IOException {
		dos.writeUTF(s);
	}

	public void writeByteArray(byte[] barr) throws IOException {
		int len = barr.length;
		writeInt(len);
		for(int i=0; i<len; ++i){
			writeByte(barr[i]);
		}
	}

	public void send() throws IOException {
		byte[] msg = baos.toByteArray();
		outChan.sendMessage(msg);
	}
}