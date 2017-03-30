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
    private byte[] zeroHash;
    private final byte[] zeroArr;
    private final byte[] emptyBlockData;


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
        emptyBlockData = new byte[this.blockSize()];

        // compute hash of empty children
        PRF hasher = new PRF(treeHashKey);
        byte[] emptyData = new byte[this.blockSize() + COUNTER_SIZE_BYTES + (2*HASH_SIZE_BYTES)];
        this.zeroHash = hasher.eval(emptyData);

        byte[] hash = new byte[HASH_SIZE_BYTES];
        zeroArr = new byte[HASH_SIZE_BYTES];
        dev.writeSuperBlock(keyOfKeys, 0, 0, HASH_SIZE_BYTES);
        dev.writeSuperBlock(keyOfNonces, 0, NONCE_BASE_OFFSET_BYTES, HASH_SIZE_BYTES);
        dev.writeSuperBlock(hash, 0, ROOT_HASH_OFFSET_BYTES, HASH_SIZE_BYTES);
        dev.writeSuperBlock(treeHashKey, 0, TREE_HASH_KEY_OFFSET_BYTES, HASH_SIZE_BYTES);
    }

    public void format() throws DataIntegrityException {
        dev.format();

        byte[] keyOfKeys = new byte[HASH_SIZE_BYTES];
        byte[] keyOfNonces = new byte[HASH_SIZE_BYTES];
        byte[] treeHashKey = new byte[HASH_SIZE_BYTES];
        prg.nextBytes(keyOfKeys);
        prg.nextBytes(keyOfNonces);
        prg.nextBytes(treeHashKey);

        // compute hash of empty children
        PRF hasher = new PRF(treeHashKey);
        byte[] emptyData = new byte[this.blockSize() + COUNTER_SIZE_BYTES + (2*HASH_SIZE_BYTES)];
        this.zeroHash = hasher.eval(emptyData);

        byte[] hash = new byte[HASH_SIZE_BYTES];
        dev.writeSuperBlock(keyOfKeys, 0, 0, HASH_SIZE_BYTES);
        dev.writeSuperBlock(keyOfNonces, 0, NONCE_BASE_OFFSET_BYTES, HASH_SIZE_BYTES);
        dev.writeSuperBlock(hash, 0, ROOT_HASH_OFFSET_BYTES, HASH_SIZE_BYTES);
        dev.writeSuperBlock(treeHashKey, 0, TREE_HASH_KEY_OFFSET_BYTES, HASH_SIZE_BYTES);
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
        if (blockOffset + nbytes > this.blockSize()) {
            throw new StudentArrayIndexOutOfBoundsException("that part of block doesn't exist");
        }
        if (bufOffset + nbytes > buf.length) {
            throw new StudentArrayIndexOutOfBoundsException("input buf not large enough");
        }

        System.out.println("reading block " + blockNum);

        // get write instance and data of block
        byte[] writeInstance = new byte[COUNTER_SIZE_BYTES];
        dev.readBlock(blockNum, writeInstance, 0, COUNTER_OFFSET_BYTES, COUNTER_SIZE_BYTES);
        byte[] encryptedData = new byte[this.blockSize()];
        dev.readBlock(blockNum, encryptedData, 0, BLOCK_STORAGE_OFFSET_BYTES, this.blockSize());

        // get the key for the hasher
        byte[] treeHashKey = new byte[HASH_SIZE_BYTES];
        dev.readSuperBlock(treeHashKey, 0, TREE_HASH_KEY_OFFSET_BYTES, HASH_SIZE_BYTES);

        // make copy of our data (so we still have our )
        byte[] encryptedDataCopy = new byte[encryptedData.length];
        System.arraycopy(encryptedData, 0, encryptedDataCopy, 0, encryptedData.length);

        int tempBlockNum = blockNum;
        byte[] hash = new byte[HASH_SIZE_BYTES];
        while (true) {
            dev.readBlock(tempBlockNum, encryptedDataCopy, 0, BLOCK_STORAGE_OFFSET_BYTES, this.blockSize());
            dev.readBlock(tempBlockNum, writeInstance, 0, COUNTER_OFFSET_BYTES, COUNTER_SIZE_BYTES);
            
            PRF hasher = new PRF(treeHashKey);
            byte[] leftChildHash = new byte[HASH_SIZE_BYTES];
            byte[] rightChildHash = new byte[HASH_SIZE_BYTES];
            dev.readBlock(tempBlockNum*2+1, leftChildHash, 0, 0, HASH_SIZE_BYTES);
            dev.readBlock(tempBlockNum*2+2, rightChildHash, 0, 0, HASH_SIZE_BYTES);
            hasher.update(encryptedDataCopy);
            hasher.update(writeInstance);
            hasher.update(leftChildHash);
            hash = hasher.eval(rightChildHash);

            if (Arrays.equals(hash, zeroHash)) {
                System.arraycopy(zeroArr, 0, hash, 0, hash.length);
            }

            dev.writeBlock(tempBlockNum, hash, 0, 0, HASH_SIZE_BYTES);

            if (tempBlockNum == 0) break;

            tempBlockNum = (tempBlockNum-1) / 2;
        }

        byte[] superHash = new byte[HASH_SIZE_BYTES];
        dev.readSuperBlock(superHash, 0, ROOT_HASH_OFFSET_BYTES, HASH_SIZE_BYTES);

        if (!Arrays.equals(superHash, hash)) {
            throw new DataIntegrityException();
        }

        // get key
        byte[] keyOfKeys = new byte[HASH_SIZE_BYTES];
        dev.readSuperBlock(keyOfKeys, 0, 0, HASH_SIZE_BYTES);
        byte[] decryptorKey = (new PRF(keyOfKeys)).eval(ByteBuffer.allocate(4).putInt(blockNum).array());

        // get nonce by getting the key needed to generate nonce
        byte[] keyOfNonces = new byte[HASH_SIZE_BYTES];
        dev.readSuperBlock(keyOfNonces, 0, NONCE_BASE_OFFSET_BYTES, HASH_SIZE_BYTES);
        byte[] nonce = (new PRF(keyOfNonces)).eval(writeInstance);

        // if block is empty, no need to decrypt
        if (Arrays.equals(emptyBlockData, encryptedData)) {
            System.arraycopy(encryptedData, blockOffset, buf, bufOffset, nbytes);
            return;
        }

        // not empty, so decrypt with nonce
        StreamCipher cipher = new StreamCipher(decryptorKey, nonce);
        byte[] decryptedData = new byte[encryptedData.length];
        cipher.cryptBytes(encryptedData, 0, decryptedData, 0, encryptedData.length);
        System.arraycopy(decryptedData, blockOffset, buf, bufOffset, nbytes);
    }

    public void writeBlock(int blockNum, byte[] buf, int bufOffset, 
        int blockOffset, int nbytes) throws DataIntegrityException {
        if (blockOffset + nbytes > this.blockSize()) {
            throw new StudentArrayIndexOutOfBoundsException("that part of block doesn't exist");
        }
        if (bufOffset + nbytes > buf.length) {
            throw new StudentArrayIndexOutOfBoundsException("input buf not large enough");
        }

        // write data
        System.out.println("writing block " + blockNum);

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

        // get and increment write instance number
        byte[] writeInstance = new byte[COUNTER_SIZE_BYTES];
        dev.readBlock(blockNum, writeInstance, 0, COUNTER_OFFSET_BYTES, COUNTER_SIZE_BYTES);
        long writeInstanceLong = LongUtils.bytesToLong(writeInstance, 0);
        writeInstanceLong++;
        byte[] incrementedWriteInstance = new byte[COUNTER_SIZE_BYTES];
        LongUtils.longToBytes(writeInstanceLong, incrementedWriteInstance, 0);

        // get nonce from incremented write instance
        byte[] nonce = (new PRF(keyOfNonces)).eval(incrementedWriteInstance);

        // needs to handle only partial writes!
        // decrypt current block first
        byte[] currBlockBytes = new byte[this.blockSize()];
        this.readBlock(blockNum, currBlockBytes, 0, 0, this.blockSize());
        // now we can edit decrypted contents and then reencrypt
        System.arraycopy(buf, bufOffset, currBlockBytes, blockOffset, nbytes);

        // encrypt with new nonce and data changes
        // AuthEncryptor encryptor = new AuthEncryptor(encryptorKey);
        // byte[] encryptedData = encryptor.encrypt(currBlockBytes, nonce, false);
        StreamCipher cipher = new StreamCipher(encryptorKey, nonce);
        byte[] encryptedData = new byte[currBlockBytes.length];
        cipher.cryptBytes(currBlockBytes, 0, encryptedData, 0, currBlockBytes.length);

        // write new block data
        dev.writeBlock(blockNum, encryptedData, 0, BLOCK_STORAGE_OFFSET_BYTES, this.blockSize());
        dev.writeBlock(blockNum, incrementedWriteInstance, 0, COUNTER_OFFSET_BYTES, COUNTER_SIZE_BYTES);

        // recompute hash and update tree!!
        byte[] treeHashKey = new byte[HASH_SIZE_BYTES];
        dev.readSuperBlock(treeHashKey, 0, TREE_HASH_KEY_OFFSET_BYTES, HASH_SIZE_BYTES);

        int tempBlockNum = blockNum;
        // update the tree
        byte[] hash = new byte[HASH_SIZE_BYTES];
        while (true) {

            dev.readBlock(tempBlockNum, encryptedData, 0, BLOCK_STORAGE_OFFSET_BYTES, this.blockSize());
            dev.readBlock(tempBlockNum, incrementedWriteInstance, 0, COUNTER_OFFSET_BYTES, COUNTER_SIZE_BYTES);

            // get children hashes
            byte[] leftChildHash = new byte[HASH_SIZE_BYTES];
            byte[] rightChildHash = new byte[HASH_SIZE_BYTES];
            dev.readBlock(tempBlockNum*2+1, leftChildHash, 0, 0, HASH_SIZE_BYTES);
            dev.readBlock(tempBlockNum*2+2, rightChildHash, 0, 0, HASH_SIZE_BYTES);

            PRF hasher = new PRF(treeHashKey);
            hasher.update(encryptedData);
            hasher.update(incrementedWriteInstance);
            hasher.update(leftChildHash);
            hash = hasher.eval(rightChildHash);

            // write hash
            dev.writeBlock(tempBlockNum, hash, 0, 0, HASH_SIZE_BYTES);

            if (tempBlockNum == 0) break;

            tempBlockNum = (tempBlockNum-1) / 2;
        }

        dev.writeSuperBlock(hash, 0, ROOT_HASH_OFFSET_BYTES, HASH_SIZE_BYTES);
    }
}
