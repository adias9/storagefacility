// This class provides a BlockStore that guarantees confidentiality and
// integrity of all the data it holds.  The constructor takes a BlockStore
// (which doesn't guarantee confidentiality and integrity).
//
// YOU WILL MODIFY THIS FILE.  The code we have provided here does not
// actually do anything to provide confidentiality and integrity.  You have
// to fix that.

import java.util.Arrays;

import java.io.FileNotFoundException;
import java.nio.ByteBuffer;


public class BlockStoreAuthEnc implements BlockStore {
    private BlockStore    dev;
    private PRGen         prg;
    // for block storage
    private final int HASH_SIZE_BYTES = 32;
    private final int COUNTER_SIZE_BYTES = 8;
    private final int BLOCK_STORAGE_OFFSET_BYTES = HASH_SIZE_BYTES + COUNTER_SIZE_BYTES;
    private final int COUNTER_OFFSET_BYTES = 32;

    // for superblock storage
    private final int NONCE_BASE_OFFSET_BYTES = 32;
    private final int ROOT_HASH_OFFSET_BYTES = 64;
    private final int TREE_HASH_KEY_OFFSET_BYTES = 96;

    public BlockStoreAuthEnc(BlockStore underStore, PRGen thePrg) 
    throws DataIntegrityException {
        dev = underStore;
        prg = thePrg;

        byte[] keyOfKeys = new byte[HASH_SIZE_BYTES];
        byte[] keyOfNonces = new byte[HASH_SIZE_BYTES];
        byte[] treeHashKey = new byte[HASH_SIZE_BYTES];
        thePrg.nextBytes(keyOfKeys);
        thePrg.nextBytes(keyOfNonces);
        thePrg.nextBytes(treeHashKey);

        // compute hash of empty children
        PRF hasher = new PRF(treeHashKey);

        byte[] emptyData = new byte[this.blockSize()];
        // should we be hashing encrypted or unencrypted data?
        hasher.update(emptyData);

        byte[] writeInstance = new byte[COUNTER_SIZE_BYTES];
        hasher.update(writeInstance);
        // get children hashes
        byte[] leftChildHash = new byte[HASH_SIZE_BYTES];
        byte[] rightChildHash = new byte[HASH_SIZE_BYTES];
        hasher.update(leftChildHash);
        byte[] hash = hasher.eval(rightChildHash);


        dev.writeSuperBlock(keyOfKeys, 0, 0, HASH_SIZE_BYTES);
        dev.writeSuperBlock(keyOfNonces, 0, NONCE_BASE_OFFSET_BYTES, HASH_SIZE_BYTES);
        dev.writeSuperBlock(keyOfKeys, 0, ROOT_HASH_OFFSET_BYTES, HASH_SIZE_BYTES);
        dev.writeSuperBlock(treeHashKey, 0, TREE_HASH_KEY_OFFSET_BYTES, HASH_SIZE_BYTES);
    }

    public void format() throws DataIntegrityException { 
        dev.format();
    }

    public int blockSize() {
        return dev.blockSize() - HASH_SIZE_BYTES - COUNTER_SIZE_BYTES;
    }

    public int superBlockSize() {
        return dev.superBlockSize() - (HASH_SIZE_BYTES*4);
    }

    public void readSuperBlock(byte[] buf, int bufOffset, int blockOffset, 
        int nbytes) throws DataIntegrityException {

        dev.readSuperBlock(buf, bufOffset, blockOffset + (HASH_SIZE_BYTES*4), nbytes);
    }

    public void writeSuperBlock(byte[] buf, int bufOffset, int blockOffset, 
        int nbytes) throws DataIntegrityException {

        dev.writeSuperBlock(buf, bufOffset, blockOffset + (HASH_SIZE_BYTES*4), nbytes);
    }

    public void readBlock(int blockNum, byte[] buf, int bufOffset, 
        int blockOffset, int nbytes) throws DataIntegrityException {

        // Questions for InfoSec
        // 
        // do we need to treat un/pws differently than other encrypted data?
        // encrypting block data
        // different key for each block? for each write too?
        // nonce could be function of write count and block #?
        // reserve 4 bytes per block for counter (write count) (a la ParityBlockStore.java)?
        // re-encrypt entire block on each access?
        // use AuthDecryptor (which confirms integrity) and AuthEncryptor 

        byte[] writeInstance = new byte[COUNTER_SIZE_BYTES];
        dev.readBlock(blockNum, writeInstance, 0, COUNTER_OFFSET_BYTES, COUNTER_SIZE_BYTES);

        // needs to handle only partial writes!
        // decrypt current block first?
        byte[] encryptedData = new byte[this.blockSize()];
        dev.readBlock(blockNum, encryptedData, 0, BLOCK_STORAGE_OFFSET_BYTES, this.blockSize());
        // possible solution: ?
        // blockKey = (new PRF(keyForKeys)).eval(blockNum);
        // instanceNonce = (new PRF(keyForNonces)).eval(instanceNum);
        // AuthDecryptor(blockKey, instanceNonce, message);
        // recompute hash 
        byte[] treeHashKey = new byte[HASH_SIZE_BYTES];
        dev.readSuperBlock(treeHashKey, 0, TREE_HASH_KEY_OFFSET_BYTES, HASH_SIZE_BYTES);
        PRF hasher = new PRF(treeHashKey);

        // should we be hashing encrypted or unencrypted data?
        hasher.update(encryptedData);
        hasher.update(writeInstance);
        // get children hashes
        byte[] leftChildHash = new byte[HASH_SIZE_BYTES];
        byte[] rightChildHash = new byte[HASH_SIZE_BYTES];
        // will these indices always exist? THIS IS WRONG
        dev.readBlock(blockNum*2, leftChildHash, 0, 0, HASH_SIZE_BYTES);
        dev.readBlock(blockNum*2+1, rightChildHash, 0, 0, HASH_SIZE_BYTES);
        hasher.update(leftChildHash);
        byte[] hash = hasher.eval(rightChildHash);

        while (blockNum != 0) {
            blockNum /= 2;
            // should we be hashing encrypted or unencrypted data?
            dev.readBlock(blockNum, encryptedData, 0, BLOCK_STORAGE_OFFSET_BYTES, this.blockSize());
            dev.readBlock(blockNum, writeInstance, 0, COUNTER_OFFSET_BYTES, COUNTER_SIZE_BYTES);
            hasher.update(encryptedData);
            hasher.update(writeInstance);
            // get children hashes
            leftChildHash = new byte[HASH_SIZE_BYTES];
            rightChildHash = new byte[HASH_SIZE_BYTES];
            // will these indices always exist? THIS IS WRONG
            dev.readBlock(blockNum*2, leftChildHash, 0, 0, HASH_SIZE_BYTES);
            dev.readBlock(blockNum*2+1, rightChildHash, 0, 0, HASH_SIZE_BYTES);
            hasher.update(leftChildHash);
            hash = hasher.eval(rightChildHash);
        }

        byte[] superHash = new byte[HASH_SIZE_BYTES];
        dev.readSuperBlock(superHash, 0, ROOT_HASH_OFFSET_BYTES, HASH_SIZE_BYTES);


        if (!Arrays.equals(superHash, hash)) {
            throw new DataIntegrityException();
        }

        // update hash
        // get key
        byte[] keyOfKeys = new byte[HASH_SIZE_BYTES];
        dev.readSuperBlock(keyOfKeys, 0, 0, HASH_SIZE_BYTES);
        byte[] decryptorKey = (new PRF(keyOfKeys)).eval(ByteBuffer.allocate(4).putInt(blockNum).array());

        // get nonce, first by getting the key needed to generate nonce,
        //  then by getting the write instance from the block storage,
        //  then generating the nonce from those two things
        byte[] keyOfNonces = new byte[HASH_SIZE_BYTES];
        dev.readSuperBlock(keyOfNonces, 0, NONCE_BASE_OFFSET_BYTES, HASH_SIZE_BYTES);
        byte[] nonce = (new PRF(keyOfNonces)).eval(writeInstance);

        // decrypt with nonce
        AuthDecryptor decryptor = new AuthDecryptor(decryptorKey);
        byte[] decryptedData = decryptor.decrypt(encryptedData, nonce);

        System.arraycopy(decryptedData, blockOffset, buf, bufOffset, nbytes);
    }

    public void writeBlock(int blockNum, byte[] buf, int bufOffset, 
        int blockOffset, int nbytes) throws DataIntegrityException {

        // maybe need to check current path/integrity first?

        // write data

        // update hash
        // get key
        byte[] keyOfKeys = new byte[HASH_SIZE_BYTES];
        dev.readSuperBlock(keyOfKeys, 0, 0, HASH_SIZE_BYTES);
        byte[] encryptorKey = (new PRF(keyOfKeys)).eval(ByteBuffer.allocate(4).putInt(blockNum).array());

        // get nonce, first by getting the key needed to generate nonce,
        //  then by getting the write instance from the block storage,
        //  then generating the nonce from those two things
        byte[] keyOfNonces = new byte[HASH_SIZE_BYTES];
        dev.readSuperBlock(keyOfNonces, 0, NONCE_BASE_OFFSET_BYTES, HASH_SIZE_BYTES);
        byte[] writeInstance = new byte[COUNTER_SIZE_BYTES];
        dev.readBlock(blockNum, writeInstance, 0, COUNTER_OFFSET_BYTES, COUNTER_SIZE_BYTES);
        byte[] nonce = (new PRF(keyOfNonces)).eval(writeInstance);

        // needs to handle only partial writes!
        // decrypt current block first?
        byte[] currBlockBytes = new byte[this.blockSize()];
        this.readBlock(blockNum, currBlockBytes, 0, 0, this.blockSize());
        // now we can edit decrypted contents and then reencrypt
        System.arraycopy(buf, bufOffset, currBlockBytes, blockOffset, nbytes);

        // encrypt with new nonce and data changes
        AuthEncryptor encryptor = new AuthEncryptor(encryptorKey);
        byte[] encryptedData = encryptor.encrypt(currBlockBytes, nonce, false);

        // write new block data
        dev.writeBlock(blockNum, encryptedData, 0, BLOCK_STORAGE_OFFSET_BYTES, this.blockSize());

        // increment write instance
        long writeInstanceLong = LongUtils.bytesToLong(writeInstance, 0);
        writeInstanceLong++;
        byte[] incrementedWriteInstance = new byte[COUNTER_SIZE_BYTES];
        LongUtils.longToBytes(writeInstanceLong, incrementedWriteInstance, 0);
        dev.writeBlock(blockNum, incrementedWriteInstance, 0, COUNTER_OFFSET_BYTES, COUNTER_SIZE_BYTES);

        // recompute hash and update tree!!
        byte[] treeHashKey = new byte[HASH_SIZE_BYTES];
        dev.readSuperBlock(treeHashKey, 0, TREE_HASH_KEY_OFFSET_BYTES, HASH_SIZE_BYTES);
        PRF hasher = new PRF(treeHashKey);

        // should we be hashing encrypted or unencrypted data?
        hasher.update(encryptedData);
        hasher.update(incrementedWriteInstance);
        // get children hashes
        byte[] leftChildHash = new byte[HASH_SIZE_BYTES];
        byte[] rightChildHash = new byte[HASH_SIZE_BYTES];
        // will these indices always exist? THIS IS WRONG
        dev.readBlock(blockNum*2, leftChildHash, 0, 0, HASH_SIZE_BYTES);
        dev.readBlock(blockNum*2+1, rightChildHash, 0, 0, HASH_SIZE_BYTES);
        hasher.update(leftChildHash);
        byte[] hash = hasher.eval(rightChildHash);

        // write hash
        dev.writeBlock(blockNum, hash, 0, 0, HASH_SIZE_BYTES);

        // update the tree
        while (blockNum != 0) {
            blockNum /= 2;
            // should we be hashing encrypted or unencrypted data?
            dev.readBlock(blockNum, encryptedData, 0, BLOCK_STORAGE_OFFSET_BYTES, this.blockSize());
            dev.readBlock(blockNum, incrementedWriteInstance, 0, COUNTER_OFFSET_BYTES, COUNTER_SIZE_BYTES);
            hasher.update(encryptedData);
            hasher.update(incrementedWriteInstance);
            // get children hashes
            leftChildHash = new byte[HASH_SIZE_BYTES];
            rightChildHash = new byte[HASH_SIZE_BYTES];
            // will these indices always exist? THIS IS WRONG
            dev.readBlock(blockNum*2, leftChildHash, 0, 0, HASH_SIZE_BYTES);
            dev.readBlock(blockNum*2+1, rightChildHash, 0, 0, HASH_SIZE_BYTES);
            hasher.update(leftChildHash);
            hash = hasher.eval(rightChildHash);

            // write hash
            dev.writeBlock(blockNum, hash, 0, 0, HASH_SIZE_BYTES);
        }

        dev.writeSuperBlock(hash, 0, ROOT_HASH_OFFSET_BYTES, HASH_SIZE_BYTES);
    }
}
