
import java.io.FileNotFoundException;


public class TestBlockStoreMultiplexor {
 public static void main(String[] args) 
  throws FileNotFoundException, DataIntegrityException {
    BlockDevice wrappedStore = new BlockDevice("testDevice");
    wrappedStore.format();
    BlockStoreMultiplexor mux = new BlockStoreMultiplexor(wrappedStore);
    for(int i=0; i<800; ++i){
      BlockStore st = mux.newSubStore();
      boolean worked = TestBlockStore.test(st);
      if(! worked){
        System.out.printf("Data failure %d\n", i);
      }
    }
    System.out.println("Done");
  }	
}