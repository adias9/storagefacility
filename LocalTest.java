// Perform some tests of client and server functionality, using the
// LocalTestHarness method of connecting them.  Students might want to 
// augment this with more tests.  You don't need to submit it for grading, 
// though.

import java.io.FileNotFoundException;
import java.io.IOException;


public class LocalTest {
	public static void main(String[] args) 
	throws FileNotFoundException, IOException, DataIntegrityException {
		// invoke with three command line arguments:
		//     java LocalTest blockStoreDir pubKey privKey
		// blockDeviceDir is the name of a directory that will be used to hold
		//   the contents of a BlockDevice used for testing
		// pubKey and privKey are names of files that contain the server's
		//   public and private keys, respectively
		//
		String blockDeviceDirectoryName = args[0];
		String publicKeyFileName = args[1];
		String privateKeyFileName = args[2];

		byte[] prgSeed = new byte[PRGen.KEY_SIZE_BYTES];
		byte[] randBytes = TrueRandomness.get();
		for(int i=0; i<TrueRandomness.NumBytes; ++i){
			prgSeed[i] = randBytes[i];
		}
		PRGen prg = new PRGen(prgSeed);

		RSAKey publicKey = KeyHandler.readKeyFromFile(publicKeyFileName);
		RSAKey privateKey = KeyHandler.readKeyFromFile(privateKeyFileName);

		BlockDevice device = new BlockDevice(blockDeviceDirectoryName);
		device.format();

		LocalTestHarness harness = new LocalTestHarness(device, privateKey, 
			publicKey, prg);

		StorageClientSession session = harness.newClientSession();

		testPing(session);
		testAuthentication(session);
		testReadWrite(session, prg);

		System.out.println("OK");
	}

	public static void testPing(StorageClientSession session) throws IOException {
		byte[] buf = { 3, 1, 4, 1, 5, 9, 26, 34, (byte)253 };

		session.testPing(buf.length, 0, buf);
		session.testPing(buf.length-2, 1, buf);
	}

	public static void testAuthentication(StorageClientSession session) 
	throws IOException {
		// leaves us logged in as a user
		String name[] = {"Alice", "Bob", "Charlie"};
		String pwd[] = {"apassword", "bob's password", "as0c9s83ks#1lasdp"};

		// trying to log in as Alice should fail
		try {
			session.authenticate(name[0], pwd[0]);
			System.out.println("ERROR: authenticated as nonexistent user (1)");
		}catch(AccessDeniedException x){
			// This exception should occur
		}

		// create an account for Alice
		try {
			session.createAccount(name[0], pwd[0]);
		}catch(AccessDeniedException x){
			x.printStackTrace();
		}

		// create an account for Bob
		try {
			session.createAccount(name[1], pwd[1]);
		}catch(AccessDeniedException x){
			x.printStackTrace();
		}
		// create an account for Charlie
		try {
			session.createAccount(name[2], pwd[2]);
		}catch(AccessDeniedException x){
			x.printStackTrace();
		}

		// should be able to log in as Alice now
		try {
			session.authenticate(name[0], pwd[0]);
		}catch(AccessDeniedException x){
			x.printStackTrace();
		}
	}

	public static void testReadWrite(StorageClientSession session, PRGen prg) {
		byte[] buf = new byte[10295];
		byte[] buf2 = new byte[buf.length];

		// read from initial zeroed state
		try {
			session.read(979, 5719, 13, buf);
			for(int i=0; i<979; ++i){
				assert buf[i+13] == 0;
			}
		}catch(AccessDeniedException x){
			x.printStackTrace();
		}catch(IOException x){
			x.printStackTrace();
		}

		// write to middle of array, then read back
		prg.nextBytes(buf);
		try {
			session.write(buf.length, 37, 0, buf);
			session.read(buf.length, 37, 0, buf2);
			for(int i=0; i<buf.length; ++i){
				assert buf[i] == buf2[i];
			}
		}catch(AccessDeniedException x){
			x.printStackTrace();
		}catch(IOException x){
			x.printStackTrace();
		}
	}
}