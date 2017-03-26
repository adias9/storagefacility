
public interface BlockStore {
	// Interface for a "block store" functionality that provides persistent
	// storage of data. The store consists of a single "superblock" 
	// plus a large number of ordinary blocks which are numbered 
	// consecutively starting with zero.


	// Put the store into an initial "clean" state.  
	// After formatting, reading the superblock will yield all zeroes.
	// There is no guarantee about what data you'll get if you
	// read an ordinary block.
	public void format() throws DataIntegrityException;

	// Get the size of an ordinary block on the store.
	public int blockSize();

	// Write data to an ordinary block. The contents of 
	// buf[bufOffset] thru buf[bufOffset+nbytes-1] will be written
	// to bytes (blockOffset) thru (blockOffset+nbytes-1).  
	// Throws IndexOutOfBoundException is either offset is negative,
	// or if access would go past the end of buf or the end of the
	// block, or if blockNum is negative.
	// Throws DataIntegrityException if the operation could not be
	// completed due to tampering with data in the store.
	public void writeBlock(int blockNum, byte[] buf, int bufOffset, 
		int blockOffset, int nbytes) throws DataIntegrityException;

	// Read data from an ordinary block. The contents of 
	// bytes (blockOffset) thru (blockOffset+nbytes-1) of the block
	// will be copied into buf[bufOffset] thru buf[bufOffset+nbytes-1]. 
	// Throws IndexOutOfBoundException is either offset is negative,
	// or if access would go past the end of buf or the end of the
	// block, or if blockNum is negative.
	// Throws DataIntegrityException if the operation could not
	// completed due to tampering with data in the store.
	public void readBlock(int blockNum, byte[] buf, int bufOffset, 
		int blockOffset, int nbytes) throws DataIntegrityException;

	// Get the size of the superblock on the store.
	public int superBlockSize();

	// Write data to the superblock. The contents of 
	// buf[bufOffset] thru buf[bufOffset+nbytes-1] will be written
	// to bytes (blockOffset) thru (blockOffset+nbytes-1) of the superblock.  
	// Throws IndexOutOfBoundException is either offset is negative,
	// or if access would go past the end of buf or the end of the
	// superblock.
	// Throws DataIntegrityException if the operation could not be
	// completed due to tampering with data in the store.
	public void writeSuperBlock(byte[] buf, int bufOffset, int blockOffset, 
		int nbytes) throws DataIntegrityException;

	// Read data from an ordinary block. The contents of 
	// bytes (blockOffset) thru (blockOffset+nbytes-1) of the superblock
	// will be copied into buf[bufOffset] thru buf[bufOffset+nbytes-1]. 
	// Throws IndexOutOfBoundException is either offset is negative,
	// or if access would go past the end of buf or the end of the
	// superblock.
	// Throws DataIntegrityException if the operation could not
	// completed due to tampering with data in the store.
	public void readSuperBlock(byte[] buf, int bufOffset, int blockOffset, 
		int nbytes) throws DataIntegrityException;
}