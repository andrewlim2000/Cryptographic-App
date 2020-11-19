import java.io.Serializable;
import java.math.BigInteger;

/**
 * 
 * @author Andrew Lim
 *
 */
public class Signature implements Serializable {

    /**
     * 
     */
    private static final long serialVersionUID = -1344366669421706026L;

    private byte[] h;
    private BigInteger z;

    public Signature(byte[] h, BigInteger z) {
        this.h = h;
        this.z = z;
    }

    public byte[] getH() {
        return h;
    }

    public BigInteger getZ() {
        return z;
    }

}