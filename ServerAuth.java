
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.util.Arrays;
import java.util.List;
import java.util.Vector;

import java.io.IOException;


public class ServerAuth {
  private ArrayStore            as;
  private BlockStoreMultiplexor multiplexor;

  private BlockStore            lastBlockStoreAllocated;
  // CREATE, MODIFY, OR DELETE FIELDS AS NEEDED

  public ServerAuth(BlockStore myBlockStore, BlockStoreMultiplexor bsm) {
    // bsm is a BlockStoreMultiplexor we can use
    // myBlockStore is a BlockStore that was created using bsm, which
    // is available for use in keeping track of authentication info
    //
    // YOU SHOULD MODIFY THIS CONSTRUCTOR AS NEEDED
    as = new ArrayStore(myBlockStore);
    multiplexor = bsm;
  }

  public BlockStore createUser(String username, String password) 
  throws DataIntegrityException {
    // If there is already a user with the same name, return null.
    // Otherwise, create an account for the new user, and return a
    // BlockStore that the new user can use
    //
    // The code we are providing here is insecure.  It just sets up a new
    // BlockStore in all cases, without checking if the name is already taken,
    // and without storing any information that might be needed for 
    // authentication later.
    //
    // YOU SHOULD MODIFY THIS METHOD TO FIX THIS PROBLEM.
    lastBlockStoreAllocated = multiplexor.newSubStore();
    return lastBlockStoreAllocated;  
  }

  public BlockStore auth(String username, String password) 
  throws DataIntegrityException {    
    // If there is not already a user with the name <username>, or if there
    // is such a user but not with the given <password>, then return null.
    // Otherwise return the BlockStore that holds the given user's data.
    //
    // The code we are providing here is insecure. Its behavior doesn't 
    // depend on <username> or <password>.  And if it returns a BlockStore,
    // it isn't necessarily the one associated with the given username.
    //
    // YOU SHOULD MODIFY THIS METHOD TO FIX THIS PROBLEM.
    return lastBlockStoreAllocated;
    }
}
