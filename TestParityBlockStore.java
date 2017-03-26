
import java.io.FileNotFoundException;


public class TestParityBlockStore {
	public static void main(String[] args) 
	throws FileNotFoundException, DataIntegrityException {
		BlockDevice bd = new BlockDevice("TestParityBlockStoreDevice");
		ParityBlockStore pbs = new ParityBlockStore(bd);
		boolean result = TestBlockStore.test(pbs);
		if(result) {
			System.out.println("OK");
		}else{
			System.out.println("FAILED TestParityBlockStore");
		}
	}
}