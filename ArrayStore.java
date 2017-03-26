// This class takes a DataStore, which allows access only to discrete
// fixed-size blocks, and provides a continuous byte-array of storage
// that is built on top of the block-oriented storage.
// This is simple but useful.
//
// Here is the API:
// 
// ArrayStore as = ArrayStore(blockStore);
//   Make a new ArrayStore that uses blockStore for storage.
//
// as.write(buf, bufOffset, storageOffset, nbytes);
//   Copy data from buf[bufOffset] thru buf[bufOffset+nbytes-1] into
//   the ArrayStore at locations storageOffset thru storageOffset+nbytes-1
//
// as.read(buf, bufOffset, storageOffset, nbytes)
//   Copy data the ArrayStore at locations storageOffset 
//   thru storageOffset+nbytes-1 into 
//   buf[bufOffset] thru buf[bufOffset+nbytes-1].
//
// The read and write methods throw DataIntegrityException if
// there was a data integrity problem in the underlying DataStore.
//

public class ArrayStore {
	private int        blockSize;
	private BlockStore bs;

	public ArrayStore(BlockStore bss) {
		bs = bss;
		blockSize = bs.blockSize();
	}

	public void write(byte[] buf, int bufOffset, int storageOffset, int nbytes) 
		throws DataIntegrityException {

		while(nbytes > 0){
			int blockNum = storageOffset / blockSize;
			int blockOffset = storageOffset % blockSize;
			int nbytesThisTime = nbytes;
			if(nbytes > (blockSize-blockOffset)){
				nbytesThisTime = blockSize-blockOffset;
			}
			bs.writeBlock(blockNum, buf, bufOffset, blockOffset, nbytesThisTime);
			nbytes -= nbytesThisTime;
			storageOffset += nbytesThisTime;
			bufOffset += nbytesThisTime;
		}
	}

	public void read(byte[] buf, int bufOffset, int storageOffset, int nbytes) 
		throws DataIntegrityException {
			
		while(nbytes > 0){
			int blockNum = storageOffset / blockSize;
			int blockOffset = storageOffset % blockSize;
			int nbytesThisTime = nbytes;
			if(nbytes > (blockSize-blockOffset)){
				nbytesThisTime = blockSize-blockOffset;
			}
			bs.readBlock(blockNum, buf, bufOffset, blockOffset, nbytesThisTime);
			nbytes -= nbytesThisTime;
			storageOffset += nbytesThisTime;
			bufOffset += nbytesThisTime;
		}
	}
}