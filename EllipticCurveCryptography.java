import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * 
 * @author Andrew Lim
 *
 */
public class EllipticCurveCryptography {
	
	// public generator
	private static final CurvePoint G = new CurvePoint(new BigInteger("4"), new BigInteger("2"));
	
	private static final BigInteger r = BigInteger.valueOf(2).pow(519).subtract(new BigInteger
			("337554763258501705789107630418782636071904961214051226618635150085779108655765"));
	
	// Generating a (Schnorr/ECDHIES) key pair from passphrase pw
	public static KeyPair generateEllipticKeyPair(byte[] pw) {
		// s <- KMACXOF256(pw, “”, 512, “K”)
		byte[] temp = SHAKE.KMACXOF256(pw, "".getBytes(), 512, "K".getBytes());
		
		// s <- 4s
		BigInteger s = BigInteger.valueOf(4).multiply(new BigInteger(temp));
		
		// V <- s*G
		CurvePoint V = G.multiply(s);
		
		// key pair: (s, V)
		KeyPair sV = new KeyPair(s, V);
		return sV;
	}
	
	// Encrypting a byte array m under the (Schnorr/ECDHIES) public key V
	public static Cryptogram encryptDataFile(byte[] m, CurvePoint V) {
		// k <- Random(512)
		SecureRandom random = new SecureRandom();
	    byte[] temp = new byte[64];
	    random.nextBytes(temp);
	    
		// k <- 4k
	    BigInteger k = BigInteger.valueOf(4).multiply(new BigInteger(temp));
	    
		// W <- k*V
	    CurvePoint W = V.multiply(k);
	    
		// Z <- k*G
	    CurvePoint Z = G.multiply(k);
	    
		// (ke || ka) <- KMACXOF256(W_x, “”, 1024, “P”)
	    byte[] keka = SHAKE.KMACXOF256(W.getX().toByteArray(), "".getBytes(), 1024, "P".getBytes());
	    
		// c <- KMACXOF256(ke, “”, |m|, “PKE”) ^ m
	    byte[] ke = Arrays.copyOfRange(keka, 0, keka.length / 2);
	    byte[] c = new byte[m.length];
	    byte[] temp2 = SHAKE.KMACXOF256(ke, "".getBytes(), m.length * 8, "PKE".getBytes());
	    for (int i = 0; i < m.length; i++) {
	    	c[i] = (byte) (temp2[i] ^ m[i]);
	    }
	    
		// t <- KMACXOF256(ka, m, 512, “PKA”)
	    byte[] ka = Arrays.copyOfRange(keka, keka.length / 2, keka.length);
	    byte[] t = SHAKE.KMACXOF256(ka, m, 512, "PKA".getBytes());
	    
		// cryptogram: (Z, c, t)
	    Cryptogram Zct = new Cryptogram(Z, c, t);
		return Zct;
	}
	
	// Decrypting a cryptogram (Z, c, t) under passphrase pw:
	public static byte[] decryptCryptogram(Cryptogram Zct, byte[] pw) {
		// s <- KMACXOF256(pw, “”, 512, “K”)
		byte[] temp = SHAKE.KMACXOF256(pw, "".getBytes(), 512, "K".getBytes());
		
		// s <- 4s
		BigInteger s = BigInteger.valueOf(4).multiply(new BigInteger(temp));
		
		// W <- s*Z
		CurvePoint W = Zct.getZ().multiply(s);
		
		// (ke || ka) <- KMACXOF256(W_x, “”, 1024, “P”)
		byte[] keka = SHAKE.KMACXOF256(W.getX().toByteArray(), "".getBytes(), 1024, "P".getBytes());
		
		// m <- KMACXOF256(ke, “”, |c|, “PKE”) ^ c
		byte[] ke = Arrays.copyOfRange(keka, 0, keka.length / 2);
		byte[] m = new byte[Zct.getC().length];
		byte[] temp2 = SHAKE.KMACXOF256(ke, "".getBytes(), Zct.getC().length * 8, "PKE".getBytes());
		for (int i = 0; i < m.length; i++) {
	    	m[i] = (byte) (temp2[i] ^ Zct.getC()[i]);
	    }
		
		// t’ <- KMACXOF256(ka, m, 512, “PKA”)
		byte[] ka = Arrays.copyOfRange(keka, keka.length / 2, keka.length);
		byte[] tp = SHAKE.KMACXOF256(ka, m, 512, "PKA".getBytes());
		
		// accept if, and only if, t’ = t
		if (Arrays.equals(tp, Zct.getT())) {
			return m;
		} else {
			return null;
		}
	}
	
	// Generating a signature for a byte array m under passphrase pw
	public static Signature generateSignature(byte[] m, byte[] pw) {
		// s <- KMACXOF256(pw, “”, 512, “K”)
		byte[] temp = SHAKE.KMACXOF256(pw, "".getBytes(), 512, "K".getBytes());
		
		// s <- 4s
		BigInteger s = BigInteger.valueOf(4).multiply(new BigInteger(temp));
		
		// k <- KMACXOF256(s, m, 512, “N”)
		byte[] temp2 = SHAKE.KMACXOF256(s.toByteArray(), m, 512, "N".getBytes());
		
		// k <- 4k
		BigInteger k = BigInteger.valueOf(4).multiply(new BigInteger(temp2));
		
		// U <- k*G
		CurvePoint U = G.multiply(k);
		
		// h <- KMACXOF256(U_x, m, 512, “T”)
		byte[] h = SHAKE.KMACXOF256(U.getX().toByteArray(), m, 512, "T".getBytes());
		
		// z <- (k – hs) mod r
		BigInteger z = k.subtract((new BigInteger(h)).multiply(s)).mod(r);
		
		// signature: (h, z)
		Signature hz = new Signature(h, z);
		return hz;
	}
	
	// Verifying a signature (h, z) for a byte array m under the (Schnorr/
	// ECDHIES) public key V
	public static boolean verifySignature(Signature hz, byte[] m, CurvePoint V) {
		// U <- z*G + h*V
		CurvePoint U = (G.multiply(hz.getZ())).add(V.multiply(new BigInteger(hz.getH())));
		
		// accept if, and only if, KMACXOF256(Ux, m, 512, “T”) = h
		if (Arrays.equals(SHAKE.KMACXOF256(U.getX().toByteArray(), m, 512, "T".getBytes()), 
				hz.getH())) {
			return true;
		} else {
			return false;
		}
	}
 
	/**
	 * Compute a square root of v mod p with a specified
	 * least significant bit, if such a root exists.
	 *
	 * @param v the radicand.
	 * @param p the modulus (must satisfy p mod 4 = 3).
	 * @param lsb desired least significant bit (true: 1, false: 0).
	 * @return a square root r of v mod p with r mod 2 = 1 iff lsb = true
	 * if such a root exists, otherwise null.
	 */
	public static BigInteger sqrt(BigInteger v, BigInteger p, boolean lsb) {
	    assert(p.testBit(0) && p.testBit(1)); // p = 3 (mod 4)
	    if (v.signum() == 0) {
	        return BigInteger.ZERO;
	    }
	    BigInteger r = v.modPow(p.shiftRight(2).add(BigInteger.ONE), p);
	    if (r.testBit(0) != lsb) {
	        r = p.subtract(r); // correct the lsb
	    }
	    return (r.multiply(r).subtract(v).mod(p).signum() == 0) ? r : null;
	}
	
}
