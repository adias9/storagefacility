
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.util.Arrays;
import java.util.List;
import java.util.Vector;

import java.io.IOException;


public class ServerAuth {
  private ArrayStore            as;
  private BlockStoreMultiplexor multiplexor;
  private int                   userInfoSize;
  // CREATE, MODIFY, OR DELETE FIELDS AS NEEDED

  public ServerAuth(BlockStore myBlockStore, BlockStoreMultiplexor bsm) {
    // bsm is a BlockStoreMultiplexor we can use
    // myBlockStore is a BlockStore that was created using bsm, which
    // is available for use in keeping track of authentication info
    //
    // YOU SHOULD MODIFY THIS CONSTRUCTOR AS NEEDED
    userInfoSize = 0;
    as = new ArrayStore(myBlockStore);
    multiplexor = bsm;
  }

  private String[][] getUserData()
  throws DataIntegrityException {
    byte[] buf = new byte[this.userInfoSize];
    as.read(buf, 0, 0, userInfoSize);
    String rawUserInfo = new String(buf);
    if (rawUserInfo.length() == 0) return new String[0][0];

    String[] userInfo = rawUserInfo.split(",");
    String[][] parsedUserInfo = new String[userInfo.length][3];
    for (int i = 0; i < userInfo.length; i++) {
      String[] parsed = userInfo[i].split(":");
      parsedUserInfo[i][0] = parsed[0];
      parsedUserInfo[i][1] = parsed[1];
      parsedUserInfo[i][2] = parsed[2];
    }
    return parsedUserInfo;
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

    String[][] parsedUserInfo = this.getUserData();

    // check for existing
    for (int i = 0; i < parsedUserInfo.length; i++) {
      if (parsedUserInfo[i][0].equals(username)) {
        return null;
      }
    }

    byte[] updatedUserInfo = (username + ':' + password + ':' + multiplexor.numSubStores() + ',').getBytes();

    as.write(updatedUserInfo, 0, userInfoSize, updatedUserInfo.length);

    userInfoSize += updatedUserInfo.length;
    BlockStore newStore = multiplexor.newSubStore();
    
    return newStore;  
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
    
    String[][] parsedUserInfo = this.getUserData();

    // check for existing
    for (int i = 0; i < parsedUserInfo.length; i++) {
      if (parsedUserInfo[i][0].equals(username)) {
        if (!parsedUserInfo[i][1].equals(password)) {
          System.out.println("wrong pw!");
          return null;
        } 
        int multiInd = Integer.parseInt(parsedUserInfo[i][2]);
        System.out.println("multi_ind: " + multiInd);
        return multiplexor.getSubStore(multiInd);
      }
    }

    return null;
  }
}
