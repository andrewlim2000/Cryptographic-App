import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * 
 * @author Andrew Lim
 *
 */
public class SymmetricCryptography {
	
	private static final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();
	
	// Computing a cryptographic hash h of a byte array m
	public static String computeCryptographicHash(byte[] m) {
		// h <- KMACXOF256(“”, m, 512, “D”)
		return bytesToHex(SHAKE.KMACXOF256("".getBytes(), m, 512, "D".getBytes()));
	}
	
	// Encrypting a byte array m symmetrically under passphrase pw
	public static byte[] encryptDataFile(byte[] m, byte[] pw) {
		// z <- Random(512)
		SecureRandom random = new SecureRandom();
	    byte[] z = new byte[64];
	    random.nextBytes(z);
	    
	    // (ke || ka) <- KMACXOF256(z || pw, “”, 1024, “S”)
	    byte[] keka = SHAKE.KMACXOF256(concatenateByteArrays(z, pw), "".getBytes(), 1024, "S".getBytes());
	    
	    // c <- KMACXOF256(ke, “”, |m|, “SKE”) ^ m
	    byte[] ke = Arrays.copyOfRange(keka, 0, keka.length / 2);
	    byte[] c = new byte[m.length];
	    byte[] temp = SHAKE.KMACXOF256(ke, "".getBytes(), m.length * 8, "SKE".getBytes());
	    for (int i = 0; i < m.length; i++) {
	    	c[i] = (byte) (temp[i] ^ m[i]);
	    }
	    
	    // t <- KMACXOF256(ka, m, 512, “SKA”)
	    byte[] ka = Arrays.copyOfRange(keka, keka.length / 2, keka.length);
	    byte[] t = SHAKE.KMACXOF256(ka, m, 512, "SKA".getBytes());
	    
	    // symmetric cryptogram: (z, c, t)
	    ByteArrayOutputStream output = new ByteArrayOutputStream();
	    try {
	    	output.write(z);
			output.write(c);
			output.write(t);
		} catch (IOException e) {
			e.printStackTrace();
		}
	    
	    return output.toByteArray();
	}
	
	// Decrypting a symmetric cryptogram (z, c, t) under passphrase pw
	public static byte[] decryptCryptogram(byte[] zct, byte[] pw) {
		// (ke || ka) <- KMACXOF256(z || pw, “”, 1024, “S”)
		byte[] z = Arrays.copyOfRange(zct, 0, 64);
		byte[] keka = SHAKE.KMACXOF256(concatenateByteArrays(z, pw), "".getBytes(), 1024, "S".getBytes());
		
		// m <- KMACXOF256(ke, “”, |c|, “SKE”) ^ c
		byte[] ke = Arrays.copyOfRange(keka, 0, keka.length / 2);
		byte[] c = Arrays.copyOfRange(zct, 64, zct.length - 64);
		byte[] temp = SHAKE.KMACXOF256(ke, "".getBytes(), c.length * 8, "SKE".getBytes());
		byte[] m = new byte[c.length];
		for (int i = 0; i < c.length; i++) {
			m[i] = (byte) (temp[i] ^ c[i]);
		}
		
		// t’ <- KMACXOF256(ka, m, 512, “SKA”)
		byte[] ka = Arrays.copyOfRange(keka, keka.length / 2, keka.length);
		byte[] tp = SHAKE.KMACXOF256(ka, m, 512, "SKA".getBytes());
		
		// accept if, and only if, t’ = t
		byte[] t = Arrays.copyOfRange(zct, zct.length - 64, zct.length);
		if (Arrays.equals(tp, t)) {
			return m;
		} else {
			return null;
		}
	}
	
	// Compute an authentication tag t of a byte array m under passphrase pw
	public static String computeAuthenticationTag(byte[] m, byte[] pw) {
		// t <- KMACXOF256(pw, m, 512, “T”)
		byte[] t = SHAKE.KMACXOF256(pw, m, 512, "T".getBytes());
		return bytesToHex(t);
	}
	
	private static String bytesToHex(byte[] bytes) {
	    char[] hexChars = new char[bytes.length * 2];
	    for (int j = 0; j < bytes.length; j++) {
	        int v = bytes[j] & 0xFF;
	        hexChars[j * 2] = HEX_ARRAY[v >>> 4];
	        hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
	    }
	    return new String(hexChars);
	}
	
	private static byte[] concatenateByteArrays(byte[] a, byte[] b) {
	    byte[] result = new byte[a.length + b.length]; 
	    System.arraycopy(a, 0, result, 0, a.length); 
	    System.arraycopy(b, 0, result, a.length, b.length); 
	    return result;
	} 
}
