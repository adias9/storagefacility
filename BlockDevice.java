
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;

import java.io.FileNotFoundException;
import java.io.IOException;


public class BlockDevice implements BlockStore {
	private static final int BlockSize = 4096;
	private static final int SuperBlockSize = 256;

	private byte[] zeroBlockBytes = new byte[BlockSize];

	private String pathPrefix;
	private String pathForSB;

	public BlockDevice(String pathname) throws FileNotFoundException {
		// Open a block device, which will be backed by a directory at
		// <pathname>.  If there is not a directory at that pathname, one
		// will be created.  
		pathPrefix = pathname;
		if(! pathPrefix.endsWith("/")){
			pathPrefix = pathPrefix + "/";
		}
		pathForSB = pathPrefix + "SuperBlock";
		pathPrefix = pathPrefix + "OrdinaryBlocks/";

	// create directory, if it doesn't already exist
		File f = new File(pathPrefix);
		if(f.exists()){
			if(! f.isDirectory()){
				throw new FileNotFoundException();
			}
		}else{
			f.mkdir();
		}
	}

	public void format() {
		try{
			byte[] zeroes = new byte[SuperBlockSize];
			writeEntireFile(pathForSB, zeroes, 0, SuperBlockSize);
			destroyDirectoryContents(pathPrefix);
		}catch(FileNotFoundException x){
			x.printStackTrace();
		}catch(IOException x){
			x.printStackTrace();
		}
	}

	public int blockSize() {    return BlockSize;    }
	public int superBlockSize() {    return SuperBlockSize;    }

	private String pathForBlock(int blockNum) {
		return pathPrefix+Integer.toString(blockNum);
	}

	private void createDirectoryParents(String filename) {
		String parentName = new File(filename).getParent();
		if(parentName != null){
			File parentFile = new File(parentName);
			if(! parentFile.isDirectory()){
				createDirectoryParents(parentName);
				parentFile.mkdir();
			}
		}
	}

	private void writeEntireFile(String filename, byte[] buf, int bufOffset, 
		int nbytes) throws FileNotFoundException, IOException {

		FileOutputStream fos;
		try {
			fos = new FileOutputStream(filename);
		}catch(FileNotFoundException x){
			createDirectoryParents(filename);
			fos = new FileOutputStream(filename);
		}
		fos.write(buf, bufOffset, nbytes);
		fos.close();
	}

	private void writePartialFile(String filename, byte[] buf, int bufOffset, 
		int fileOffset, int nbytes, int fullSize) 
		throws FileNotFoundException, IOException {

		byte[] mybuf = new byte[fullSize];
		readFromFile(filename, mybuf, 0, 0, fullSize);
		for(int i=0; i<nbytes; ++i){
			mybuf[fileOffset+i] = buf[bufOffset+i];
		}
		writeEntireFile(filename, mybuf, 0, fullSize);
	}

	private void readFromFile(String filename, byte[] buf, int bufOffset, 
		int fileOffset, int nbytes) 
		throws FileNotFoundException, IOException {

		FileInputStream fis;
		try {
			fis = new FileInputStream(filename);
		} catch (FileNotFoundException x) {
			writeEntireFile(filename, zeroBlockBytes, 0, BlockSize);
			fis = new FileInputStream(filename);
		}
		fis.skip(fileOffset);
		fis.read(buf, bufOffset, nbytes);
		fis.close();
	}

	private void destroyDirectoryContents(String pathPrefix) {
		File dir = new File(pathPrefix);
		if(dir != null){
			File[] filesList = new File(pathPrefix).listFiles();
			if(filesList != null){
				for(File file : filesList) {
					file.delete();
				}
			}
		}
	}

	public void writeBlock(int blockNum, byte[] buf, int bufOffset, 
		int blockOffset, int nbytes) {

		try {
			if( (blockOffset==0) && (blockOffset+nbytes==BlockSize) ){
				writeEntireFile(pathForBlock(blockNum), buf, bufOffset, BlockSize);
			}else{
				writePartialFile(pathForBlock(blockNum), buf, bufOffset, blockOffset, 
					nbytes, BlockSize);
			}
		} catch(FileNotFoundException x) {
			x.printStackTrace();
		} catch(IOException x) {
			x.printStackTrace();
		}
	}

	public void readBlock(int blockNum, byte[] buf, int bufOffset, 
		int blockOffset, int nbytes) {

		try {
			assert blockOffset >= 0;
			assert (blockOffset+nbytes) <= BlockSize;
			readFromFile(pathForBlock(blockNum), buf, bufOffset, blockOffset, nbytes);
		} catch(FileNotFoundException x) {
			x.printStackTrace();
		} catch(IOException x) {
			x.printStackTrace();
		}
	}

	public void writeSuperBlock(byte[] buf, int bufOffset, int blockOffset, 
		int nbytes) {

		try {
			if( (blockOffset==0) && (blockOffset+nbytes==SuperBlockSize) ){
				writeEntireFile(pathForSB, buf, bufOffset, nbytes);
			}else{
				writePartialFile(pathForSB, buf, bufOffset, blockOffset, nbytes, 
					SuperBlockSize);
			}
		} catch(FileNotFoundException x) {
			x.printStackTrace();
		} catch(IOException x) {
			x.printStackTrace();
		}
	}

	public void readSuperBlock(byte[] buf, int bufOffset, int blockOffset, 
		int nbytes) {

		try {
			assert blockOffset >= 0;
			assert (blockOffset+nbytes) <= SuperBlockSize;
			readFromFile(pathForSB, buf, bufOffset, blockOffset, nbytes);
		} catch(FileNotFoundException x) {
			x.printStackTrace();
		} catch(IOException x) {
			x.printStackTrace();
		}
	}
}