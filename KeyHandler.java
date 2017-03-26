// This class is useful for handling RSA keys.  

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;

import java.io.FileNotFoundException;
import java.io.IOException;


public class KeyHandler {
	public static String defaultPubKeyFileName = "publickey.dat";
	public static String defaultPrivKeyFileName = "privatekey.dat";

	public static void writeKeyToFile(RSAKey key, String filename) 
	throws FileNotFoundException, IOException {
		// Write an RSAKey to a file
		BigInteger[] a = new BigInteger[2];
		a[0] = key.getExponent();
		a[1] = key.getModulus();

		FileOutputStream fos = new FileOutputStream(filename);
		ObjectOutputStream oos = new ObjectOutputStream(fos);
		oos.writeObject(a);
		oos.close();
		fos.close();
	}

	public static RSAKey readKeyFromFile(String filename) 
	throws FileNotFoundException, IOException {
		// Read an RSAKey from a file, return the key that was read
		FileInputStream fis = new FileInputStream(filename);
		ObjectInputStream ois = new ObjectInputStream(fis);
		try {
			BigInteger[] a = (BigInteger[]) ois.readObject();

			return new RSAKey(a[0], a[1]);
		}catch(ClassNotFoundException x) {
			return null;
		}
	}

	public static void main(String[] args) 
	throws FileNotFoundException, IOException{
		// Generate an RSA key-pair, and write them to separate files
		// This can be invoked with three arguments:
		//    java KeyHandler keysizebits pubkeyfilename privkeyfilename
		// If invoked with one command-line arg, it will use default filenames:
		//    java KeyHandler keysizebits
		// If invoked with no command-line args, it will use default values:
		//    java KeyHandler
		//
		int keySizeBits = 2048;
		String pubKeyFileName = defaultPubKeyFileName;
		String privKeyFileName = defaultPrivKeyFileName;

		if(args.length > 0){
			keySizeBits = Integer.parseInt(args[0]);
		}
		if(args.length > 1){
			pubKeyFileName = args[1];
			privKeyFileName = args[2];
		}

		byte[] prgSeed = new byte[PRGen.KEY_SIZE_BYTES];
		byte[] randBytes = TrueRandomness.get();
		for(int i=0; i<TrueRandomness.NumBytes; ++i) {
			prgSeed[i] = randBytes[i];
		}
		PRGen prg = new PRGen(prgSeed);

		RSAKeyPair pair = new RSAKeyPair(prg, keySizeBits);
		writeKeyToFile(pair.getPublicKey(), pubKeyFileName);
		writeKeyToFile(pair.getPrivateKey(), privKeyFileName);
	}
}