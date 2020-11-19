import java.io.Serializable;
import java.math.BigInteger;

/**
 * 
 * @author Andrew Lim
 *
 */
public class KeyPair implements Serializable {

    /**
     * 
     */
    private static final long serialVersionUID = 1075750823702779411L;

    private BigInteger s;
    private CurvePoint V;

    public KeyPair(BigInteger s, CurvePoint V) {
        this.s = s;
        this.V = V;
    }

    public BigInteger getS() {
        return s;
    }

    public CurvePoint getV() {
        return V;
    }

}