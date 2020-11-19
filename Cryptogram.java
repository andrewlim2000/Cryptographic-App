import java.io.Serializable;

/**
 * 
 * @author Andrew Lim
 *
 */
public class Cryptogram implements Serializable {

    /**
     * 
     */
    private static final long serialVersionUID = -2050194787249960063L;

    private CurvePoint Z;
    private byte[] c;
    private byte[] t;

    public Cryptogram(CurvePoint Z, byte[] c, byte[] t) {
        this.Z = Z;
        this.c = c;
        this.t = t;
    }

    public CurvePoint getZ() {
        return Z;
    }

    public byte[] getC() {
        return c;
    }

    public byte[] getT() {
        return t;
    }

}