
import java.io.FileNotFoundException;


public class TestBlockDevice {
	public static void main(String[] args) 
		throws FileNotFoundException, DataIntegrityException {

		BlockStore bs = new BlockDevice("testDevice");
		boolean passed = TestBlockStore.test(bs);
		if(passed){
			System.out.println("OK");
		}else{
			System.out.println("FAILED");
		}
	}	
}