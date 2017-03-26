// A ServerContext reflects the state of a server that is listening for 
// connections from clients.  Every server that is running will have a 
// single ServerContext, plus zero or more ServerThreads.  The ServerContext
// will keep track of state that is shared by all of the ServerThreads, and
// each ServerThread will keep track of whatever state it needs to serve the
// one client that it is devoted to.
//

public class ServerContext {
	public static final int SuccessCode = 0;
	public static final int UnauthorizedCode = 1;
	public static final int DataIntegrityFailureCode = 2;

	public static final byte CommandPing = 0;
	public static final byte CommandAuthenticate = 1;
	public static final byte CommandCreateAccount = 2;
	public static final byte CommandWrite = 3;
	public static final byte CommandRead = 4;

	public PRGen 		  prg;
	public ServerAuth auth;
	public RSAKey     privateKey;
	public BlockStoreMultiplexor mux;

	public ServerContext(BlockDevice device, RSAKey privateKey, PRGen prg) 
	throws DataIntegrityException {
		this.prg = prg;
		this.privateKey = privateKey;
		BlockStoreAuthEnc bsae = new BlockStoreAuthEnc(device, prg);
		mux = new BlockStoreMultiplexor(bsae);

		BlockStore bs0;
		if(mux.numSubStores() == 0){
			bs0 = mux.newSubStore();
		}else{
			bs0 = mux.getSubStore(0);
		}
		auth = new ServerAuth(bs0, mux);
	}
}