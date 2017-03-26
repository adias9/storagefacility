
import java.io.FileNotFoundException;


public class TestBlockStoreAuthEnc {
		public static void main(String[] args) 
		throws FileNotFoundException, DataIntegrityException {
			
		BlockStore dev = new BlockDevice("testDevice");
		dev.format();

		byte[] prgSeed = new byte[PRGen.KEY_SIZE_BYTES];
		byte[] randBytes = TrueRandomness.get();
		for(int i=0; i<TrueRandomness.NumBytes; ++i) {
			prgSeed[i] = randBytes[i];
		}
		PRGen prg = new PRGen(prgSeed);
		BlockStore bs = new BlockStoreAuthEnc(dev, prg);
		boolean passed = TestBlockStore.test(bs);
		if(passed){
			System.out.println("OK");
		}else{
			System.out.println("FAILED");
		}
	}
}