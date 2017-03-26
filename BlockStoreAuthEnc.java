// This class provides a BlockStore that guarantees confidentiality and
// integrity of all the data it holds.  The constructor takes a BlockStore
// (which doesn't guarantee confidentiality and integrity).
//
// YOU WILL MODIFY THIS FILE.  The code we have provided here does not
// actually do anything to provide confidentiality and integrity.  You have
// to fix that.

import java.util.Arrays;

import java.io.FileNotFoundException;


public class BlockStoreAuthEnc implements BlockStore {
    private BlockStore    dev;
    private PRGen         prg;

    public BlockStoreAuthEnc(BlockStore underStore, PRGen thePrg) 
    throws DataIntegrityException {
        dev = underStore;
        prg = thePrg;
    }

    public void format() throws DataIntegrityException { 
        dev.format();
    }

    public int blockSize() {
        return dev.blockSize();
    }

    public int superBlockSize() {
        return dev.superBlockSize();
    }

    public void readSuperBlock(byte[] buf, int bufOffset, int blockOffset, 
        int nbytes) throws DataIntegrityException {

        dev.readSuperBlock(buf, bufOffset, blockOffset, nbytes);
    }

    public void writeSuperBlock(byte[] buf, int bufOffset, int blockOffset, 
        int nbytes) throws DataIntegrityException {

        dev.writeSuperBlock(buf, bufOffset, blockOffset, nbytes);
    }

    public void readBlock(int blockNum, byte[] buf, int bufOffset, 
        int blockOffset, int nbytes) throws DataIntegrityException {

        // Questions for InfoSec
        // do we need to treat un/pws differently than other encrypted data?
        // encrypting block data
        // different key for each block? for each write too?
        // nonce could be function of write count and block #?
        // reserve 4 bytes per block for counter (write count) (a la ParityBlockStore.java)?
        // re-encrypt entire block on each access?
        // use AuthDecryptor (which confirms integrity) and AuthEncryptor 

        // possible solution: ?
        // blockKey = (new PRF(keyForKeys)).eval(blockNum);
        // instanceNonce = (new PRF(keyForNonces)).eval(instanceNum);
        // AuthDecryptor(blockKey, instanceNonce, message);

        dev.readBlock(blockNum, buf, bufOffset, blockOffset, nbytes);
    }

    public void writeBlock(int blockNum, byte[] buf, int bufOffset, 
        int blockOffset, int nbytes) throws DataIntegrityException {

        dev.writeBlock(blockNum, buf, bufOffset, blockOffset, nbytes);
    }
}
