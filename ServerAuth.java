
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.util.Arrays;
import java.util.List;
import java.util.Vector;
import java.util.Random;

import java.io.IOException;


public class ServerAuth {
  private ArrayStore            as;
  private BlockStoreMultiplexor multiplexor;
  private Random                rand;
  private byte[]                hashKey;
  private final int             USER_INFO_SIZE_BYTES = 80;
  private final int             HASH_SIZE_BYTES = 32;
  private final int             SALT_SIZE_BYTES = 16;
  // CREATE, MODIFY, OR DELETE FIELDS AS NEEDED

  public ServerAuth(BlockStore myBlockStore, BlockStoreMultiplexor bsm) {
    // bsm is a BlockStoreMultiplexor we can use
    // myBlockStore is a BlockStore that was created using bsm, which
    // is available for use in keeping track of authentication info
    //
    // YOU SHOULD MODIFY THIS CONSTRUCTOR AS NEEDED

    as = new ArrayStore(myBlockStore);
    multiplexor = bsm;
    rand = new Random();
    hashKey = new byte[HASH_SIZE_BYTES];
    rand.nextBytes(hashKey);
  }

  private byte[][][] getUserData() throws DataIntegrityException {

    int numUsers = multiplexor.numSubStores()-1;
    byte[] buf = new byte[USER_INFO_SIZE_BYTES*numUsers];
    // as.read(buf, 0, 0, USER_INFO_SIZE_BYTES*numUsers);

    // hash(un):hash(salt, pw):salt
    // 32, 32, 16
    byte[][][] userInfo = new byte[numUsers][3][];
    for (int i = 0; i < numUsers; i++) {
      int offset = i*USER_INFO_SIZE_BYTES;
      userInfo[i][0] = new byte[HASH_SIZE_BYTES];
      userInfo[i][1] = new byte[HASH_SIZE_BYTES];
      userInfo[i][2] = new byte[SALT_SIZE_BYTES];
      as.read(userInfo[i][0], 0, offset, HASH_SIZE_BYTES);
      as.read(userInfo[i][1], 0, offset+HASH_SIZE_BYTES, HASH_SIZE_BYTES);
      as.read(userInfo[i][2], 0, offset+(HASH_SIZE_BYTES*2), SALT_SIZE_BYTES);
    }
    return userInfo;
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

    // hash(un):hash(salt, pw):salt
    // HASH_SIZE_BYTES, HASH_SIZE_BYTES, 16

    byte[] salt = new byte[SALT_SIZE_BYTES];
    rand.nextBytes(salt);

    PRF hasher = new PRF(hashKey);
    byte[] usernameHash = hasher.eval(username.getBytes());
    hasher.eval(new byte[0]);
    hasher.update(salt);
    byte[] hashedVal = hasher.eval(password.getBytes());

    // int storeNum = multiplexor.numSubStores();
    // byte[] storeNum = ByteBuffer.allocate(4).putInt(storeNum).array();
    byte[] newUserInfo = new byte[USER_INFO_SIZE_BYTES];
    System.arraycopy(usernameHash, 0, newUserInfo, 0, usernameHash.length);
    System.arraycopy(hashedVal, 0, newUserInfo, HASH_SIZE_BYTES, hashedVal.length);
    System.arraycopy(salt, 0, newUserInfo, HASH_SIZE_BYTES*2, salt.length);

    byte[][][] parsedUserInfo = this.getUserData();

    // check for existing
    for (int i = 0; i < parsedUserInfo.length; i++) {
      if (Arrays.equals(parsedUserInfo[i][0],usernameHash)) {
        return null;
      }
    }

    int numUsers = multiplexor.numSubStores()-1;
    as.write(newUserInfo, 0, numUsers*USER_INFO_SIZE_BYTES, newUserInfo.length);

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
    
    byte[][][] userInfo = this.getUserData();
    PRF hasher = new PRF(hashKey);
    byte[] usernameHash = hasher.eval(username.getBytes());

    // check for existing
    for (int i = 0; i < userInfo.length; i++) {
      if (Arrays.equals(userInfo[i][0], usernameHash)) {
        byte[] salt = userInfo[i][2];
        hasher.eval(new byte[0]);
        hasher.update(salt);
        byte[] hashedPW = hasher.eval(password.getBytes());   
        if (!Arrays.equals(userInfo[i][1], hashedPW)) {
          System.out.println("wrong pw!");
          return null;
        } 
        int multiInd = i+1;
        System.out.println("multi_ind: " + multiInd);
        return multiplexor.getSubStore(multiInd);
      }
    }

    return null;
  }
}
