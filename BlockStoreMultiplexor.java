// This class implements a BlockStore multiplexor.  
// You pass the constructor a BlockStore that it can use to store 
// information. It then provides a service that can create and manage 
// multiple BlockStores.  This class handles all of
// the necessary bookkeeping.
//
// Here is the relevant API:
// 
// BlockStoreMultiplexor bsm = BlockStoreMultiplexor(BlockStore ws);
//   Create a new instance. <ws> is a BlockStore that the new instance
//   can use for storing data.  It should either be freshly formatted, or
//   should be in a state set up previously by a BlockStoreMultiplexor.
//   If <ws> is freshly formatted, then <bsm> will contain zero BlockStores.
//
//  int ns = bsm.numSubStores();
//    Get the number of BlockStores that currently exist in <bsm>.
//
//  BlockStore bs = bsm.getSubStore(int index);
//     Get a handle to the <index>'th BlockStore in <bsm>.  
//
//  BlockStore bs = bsm.newSubStore();
//     Add a new BlockStore to <bsm>, and return a pointer to it.  The
//     new BlockStore will not be formatted, so you might want to 
//     call format on it next.

// The BlockStores returned by getSubStore and newSubStore behave just
// like regular BlockStores.  The point of this class is that you start out
// with one BlockStore, and on top of it you create a structure that can
// give you as many BlockStores as you want.


import java.util.List;
import java.util.Vector;

import java.io.FileNotFoundException;


public class BlockStoreMultiplexor {
	private static byte[]     masterBlockTemplate = null;
	private static byte[]     dataBlockTemplate = null;

	private BlockStore        wrappedStore;
	private List<Multiplexed> stores;
	private int               firstFreeBlock;
  private int               msbSize = 64;   // size of superblock exposed to multiplexed stores
  private int               mPtrSize = 8;   // size of a block-pointer
  private int               mNumPtrs;       // number of block-pointers in a metablock
  private int               dPtrSize = mPtrSize;  // size of a datablock-pointer
  private int               dNumPtrs = 4;   // number of block-pointers in a data block
  private int               dbSize;
    
  public BlockStoreMultiplexor(BlockStore ws) throws DataIntegrityException {
    wrappedStore = ws;

    byte[] buf = new byte[16];
    wrappedStore.readSuperBlock(buf, 0, wrappedStore.superBlockSize()-16, 16);
    long numStores = LongUtils.bytesToLong(buf, 0);
    stores = new Vector<Multiplexed>();
    for(int i=0; i<numStores; ++i){
      stores.add(new Multiplexed(i));
    }
    firstFreeBlock = (int) LongUtils.bytesToLong(buf, 8);

    mNumPtrs = (wrappedStore.blockSize()-(msbSize+dPtrSize)) / mPtrSize;
    dbSize = wrappedStore.blockSize()-(dPtrSize*dNumPtrs);

    byte[] minusOne = new byte[8];
    LongUtils.longToBytes((long)(-1), minusOne, 0);
    if(masterBlockTemplate == null){
      buf = new byte[wrappedStore.blockSize()];
      for(int i=0; i<mNumPtrs; ++i){
        for(int j=0; j<8; ++j){
          buf[i*8+j] = minusOne[j];
        }
      }
      for(int j=0; j<8; ++j){
        buf[wrappedStore.blockSize()-(msbSize+dPtrSize)+j] = minusOne[j];
      }
      masterBlockTemplate = buf;
    }
    if(dataBlockTemplate == null){
      buf = new byte[wrappedStore.blockSize()];
      for(int i=0; i<dNumPtrs; ++i){
        for(int j=0; j<8; ++j){
          int idx = (wrappedStore.blockSize()-dNumPtrs*dPtrSize)+i*dPtrSize+j;
          buf[idx] = minusOne[j];
        }
      }
      dataBlockTemplate = buf;
    }

    if(firstFreeBlock == 0){
      wrappedStore.writeBlock(0, masterBlockTemplate, 0, 0, 
        wrappedStore.blockSize());
    }
  }

  private int allocateBlock() throws DataIntegrityException {
    int ret = firstFreeBlock;
    ++firstFreeBlock;

    byte[] buf = new byte[8];
    LongUtils.longToBytes((long)firstFreeBlock, buf, 0);
    wrappedStore.writeSuperBlock(buf, 0, wrappedStore.superBlockSize()-8, 8);

    return ret;
  }

  public int numSubStores() throws DataIntegrityException {
    return stores.size();
  }

  public BlockStore getSubStore(int idx) {
    return stores.get(idx);
  }

  public BlockStore newSubStore() throws DataIntegrityException {
    int storeNum = stores.size();

	 // write new number of stores to superblock
    byte[] buf = new byte[8];
    LongUtils.longToBytes((long)(storeNum+1), buf, 0);
    wrappedStore.writeSuperBlock(buf, 0, wrappedStore.superBlockSize()-16, 8);

    Multiplexed newStore = new Multiplexed(storeNum);
    stores.add(newStore);
    int masterBlockNum = allocateBlock();
    wrappedStore.writeBlock(masterBlockNum, masterBlockTemplate, 0, 0, 
      wrappedStore.blockSize());
    newStore.writeMasterPointer(masterBlockNum);

    return newStore;
  }

  class Multiplexed implements BlockStore {
    private int storeNum;

    Multiplexed(int sn) throws DataIntegrityException {
      storeNum = sn;
    }

    private void writeMasterPointer(int masterBlockNum) 
    throws DataIntegrityException {

      if(storeNum==0){
		    // storeNum 0 always uses block 0; the code already knows this
        return;
      }
      byte[] buf = new byte[mPtrSize];
      LongUtils.longToBytes((long)masterBlockNum, buf, 0);

      int num = storeNum;
      int base = 0;
      while(num-1 >= mNumPtrs){
        int slot = (num-1) % mNumPtrs;
        num = (num-1) / mNumPtrs;
        byte[] slotContents = new byte[mPtrSize];
        wrappedStore.readBlock(base, slotContents, 0, 
          slot*mPtrSize, mPtrSize);
        base = (int) LongUtils.bytesToLong(slotContents, 0);
      }
      int slot = num-1;
      wrappedStore.writeBlock(base, buf, 0, slot*mPtrSize, mPtrSize);
      
      /*
      int slot = (storeNum-1) % mNumPtrs;
      int parentStoreNum = (storeNum-1) / mNumPtrs;
      int parentBlockNum = getMasterBlockNum(parentStoreNum, 0);

      wrappedStore.writeBlock(parentBlockNum, buf, 0, slot*mPtrSize, mPtrSize);
      */
    }

    public void format() throws DataIntegrityException {
      byte[] zeroes = new byte[msbSize];
      writeSuperBlock(zeroes, 0, 0, msbSize);
    }

    public int superBlockSize() {
      return msbSize;
    }

    private int getMasterBlockNum(int num, int baseBlock) 
    throws DataIntegrityException {
      if(num == 0){
        return baseBlock;
      }else{
        int slot = (num-1) % mNumPtrs;
        int newNum = (num-1) / mNumPtrs;

        byte[] slotContents = new byte[mPtrSize];
        wrappedStore.readBlock(baseBlock, slotContents, 0, 
          slot*mPtrSize, mPtrSize);
        int newBase = (int) LongUtils.bytesToLong(slotContents, 0);

        return getMasterBlockNum(newNum, newBase);
      }
    }

    private int getDBRec(int num, int baseBlock) 
    throws DataIntegrityException {
      if(num == 0){
        return baseBlock;
      }else{
        int slot = (num-1) % dNumPtrs;
        int newNum = (num-1) / dNumPtrs;

        byte[] slotContents = new byte[dPtrSize];
        wrappedStore.readBlock(baseBlock, slotContents, 0, 
          wrappedStore.blockSize()-dPtrSize*(dNumPtrs-slot), dPtrSize); 
        int newBase = (int) LongUtils.bytesToLong(slotContents, 0);
        if(newBase == -1){
		      // block isn't allocated yet; allocate it and initialize
          newBase = allocateBlock();
          wrappedStore.writeBlock(newBase, dataBlockTemplate, 0, 0, 
            wrappedStore.blockSize());

		      // update block pointer
          LongUtils.longToBytes((long)newBase, slotContents, 0);
          wrappedStore.writeBlock(baseBlock, slotContents, 0, 
          wrappedStore.blockSize()-dPtrSize*(dNumPtrs-slot), dPtrSize);
        }
        return getDBRec(newNum, newBase);
      }
    }

    private int getDataBlockNum(int blockNum) throws DataIntegrityException {
      int mblock = getMasterBlockNum(storeNum, 0);
      byte[] dbBuf = new byte[dPtrSize];
      wrappedStore.readBlock(mblock, dbBuf, 0, 
        wrappedStore.blockSize()-(msbSize+dPtrSize), dPtrSize);
      int dbNum = (int) LongUtils.bytesToLong(dbBuf, 0);
      if(dbNum == -1){
		    // no data blocks exist in this store, need to allocate the first one
        dbNum = allocateBlock();
        LongUtils.longToBytes((long)dbNum, dbBuf, 0);
        wrappedStore.writeBlock(mblock, dbBuf, 0, 
          wrappedStore.blockSize()-(msbSize+dPtrSize), dPtrSize);

		    // fill in the data block
        wrappedStore.writeBlock(dbNum, dataBlockTemplate, 0, 0, 
          dataBlockTemplate.length);
      }
      return getDBRec(blockNum, dbNum);
    }

    public void readSuperBlock(byte[] buf, int bufOffset, int blockOffset, 
      int nbytes) throws DataIntegrityException {

      if(blockOffset+nbytes > superBlockSize()){
        throw new ArrayIndexOutOfBoundsException();
      }

      int masterBlockNum = getMasterBlockNum(storeNum, 0);
      wrappedStore.readBlock(masterBlockNum, buf, bufOffset, 
        blockOffset+wrappedStore.blockSize()-msbSize, nbytes);
    }

    public void writeSuperBlock(byte[] buf, int bufOffset, 
      int blockOffset, int nbytes) throws DataIntegrityException {

      if ((blockOffset<0) || (blockOffset+nbytes > superBlockSize())) {
        throw new ArrayIndexOutOfBoundsException();
      }

      int masterBlockNum = getMasterBlockNum(storeNum, 0);
      wrappedStore.writeBlock(masterBlockNum, buf, bufOffset, 
        blockOffset+wrappedStore.blockSize()-msbSize, nbytes);
    }

    public int blockSize() {
      return dbSize;
    }

    public void readBlock(int blockNum, byte[] buf, int bufOffset, 
      int blockOffset, int nbytes) throws DataIntegrityException {

      if(blockOffset+nbytes > dbSize){
        throw new ArrayIndexOutOfBoundsException();
      }
      int realBlockNum = getDataBlockNum(blockNum);
      wrappedStore.readBlock(realBlockNum, buf, bufOffset, blockOffset, nbytes);
    }

    public void writeBlock(int blockNum, byte[] buf, int bufOffset, 
      int blockOffset, int nbytes) throws DataIntegrityException {

      if(blockOffset+nbytes > dbSize){
        throw new ArrayIndexOutOfBoundsException();
      }
      int realBlockNum = getDataBlockNum(blockNum);
      wrappedStore.writeBlock(realBlockNum, buf, bufOffset, blockOffset, 
        nbytes);
    }
  }
}