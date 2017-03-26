
// Useful utility that converts byte-array to long, and vice versa.

public class LongUtils {
	public static long bytesToLong(byte[] buf, int offset) {
		long ret = 0;
		for(int i=0; i<8; ++i){
			ret += ((((long)buf[offset+i])&0xff)<<(8*i));
		}
		return ret;
	}

	public static void longToBytes(long x, byte[] buf, int offset) {
		for(int i=0; i<8; ++i){
			buf[offset+i] = (byte)((x>>(8*i))&0xff);
		}
	}
}