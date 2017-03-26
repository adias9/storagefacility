
//  This file illustrates a useful trick, a BlockStore wrapper.
//  The idea is that you take one BlockStore, and build on top of it another
//  BlockStore that has enahnced functionality.  In this case, the added
//  functionality isn't very useful---it just adds a parity check on every
//  regular block.  It reserves one byte at the end of every block, which 
//  stores the xor of all of the other bytes of the block.  When a
//  block is read, this class checks whether the parity byte matches the
//  xor of rest of the block, and if not it throws a DataIntegrityException.
//
//  Notice the approach to doing this. The constructor takes a BlockStore that
//  we are "wrapping", and it uses the wrapped BlockStore to actually store 
//  information.  This class reduces the block size by one byte, because
//  it needs to reserve one byte in each wrapped block, to store the parity
//  information.  This class is careful to bounds-check reads and writes, to
//  prevent callers from overrunning the (reduced) block length.  Note that
//  the same approach---reserving space, reducing the blocksize, and adding
//  bounds-checking---could be applied to the superblock too, although that 
//  doesn't happen in this class.
//
//  You probably won't want to include this class directly in your solution,
//  but you're welcome to learn from it and use it as a model for building 
//  more useful classes.

public class ParityBlockStore implements BlockStore {
	private BlockStore wrappedStore;

	public ParityBlockStore(BlockStore bs) {
		wrappedStore = bs;
	}

	public void format() throws DataIntegrityException {
		wrappedStore.format();
		// don't need to do anything else, because all-zeroes state has 
		// correct parity already
	}

	public int blockSize() {
		return wrappedStore.blockSize() - 1;   // reserve one byte for parity
	}

	public void writeBlock(int blockNum, byte[] buf, int bufOffset,
		int blockOffset, int nbytes) throws DataIntegrityException {

		// check for out-of-bounds access
		// other cases will be caught by the wrapped store
		if(bufOffset+nbytes > blockSize()){
			throw new ArrayIndexOutOfBoundsException();
		}

		// write the new data to the block
		wrappedStore.writeBlock(blockNum, buf, bufOffset, blockOffset, nbytes);

		// recompute the parity and write it to the last byte of the wrapped block
		byte[] parityBuf = new byte[1];
		parityBuf[0] = computeParity(blockNum);
		wrappedStore.writeBlock(blockNum, parityBuf, 0, blockSize(), 1);
	}

	public void readBlock(int blockNum, byte[] buf, int bufOffset,
		int blockOffset, int nbytes) throws DataIntegrityException {

		// check for out-of-bounds access
		// other cases will be caught by the wrapped store
		if(bufOffset+nbytes > blockSize()){
			throw new ArrayIndexOutOfBoundsException();
		}

		// read the new data from the block
		wrappedStore.readBlock(blockNum, buf, bufOffset, blockOffset, nbytes);

		// verify that the block's parity matches
		byte computedParity = computeParity(blockNum);
		byte parityBuf[] = new byte[1];
		wrappedStore.readBlock(blockNum, parityBuf, 0, blockSize(), 1);
		if(computedParity != parityBuf[0]) {
			throw new DataIntegrityException();
		}
	}

	private byte computeParity(int blockNum) throws DataIntegrityException {
		byte buf[] = new byte[blockSize()];
		wrappedStore.readBlock(blockNum, buf, 0, 0, blockSize());
		byte ret = 0;
		for(int i=0; i<blockSize(); ++i) {
			ret ^= buf[i];
		}
		return ret;
	}

	public int superBlockSize() {
		return wrappedStore.superBlockSize(); 
	}

	public void writeSuperBlock(byte[] buf, int bufOffset, int blockOffset,
		int nbytes) throws DataIntegrityException {

		wrappedStore.writeSuperBlock(buf, bufOffset, blockOffset, nbytes);
	}

	public void readSuperBlock(byte[] buf, int bufOffset, int blockOffset,
		int nbytes) throws DataIntegrityException {
		wrappedStore.readSuperBlock(buf, bufOffset, blockOffset, nbytes);
	}
}