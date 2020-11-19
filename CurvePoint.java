import java.io.Serializable;
import java.math.BigInteger;


/**
 * 
 * @author Andrew Lim
 *
 */
public class CurvePoint implements Serializable {

    /**
     * 
     */
    private static final long serialVersionUID = -7013157408734130838L;
    
    // Mersenne prime
 	private static final BigInteger p = BigInteger.valueOf(2).pow(521).subtract(BigInteger.ONE);
 	
 	private static final Integer d = -376014;

    private BigInteger x;
    private BigInteger y;

    public CurvePoint(BigInteger x, BigInteger y) {
        this.x = x;
        this.y = y;
    }

    public BigInteger getX() {
        return x;
    }

    public BigInteger getY() {
        return y;
    }

    public CurvePoint multiply(BigInteger scalar) {
        CurvePoint V = new CurvePoint(x, y);
        CurvePoint P = new CurvePoint(x, y);
        String s = scalar.toString(2);
        for (int i = s.length() - 1; i >= 0; i--) {
            V = V.add(V);
            if (s.charAt(i) == '1') {
                V = V.add(P);
            }
        }
        return V;
    }

    public CurvePoint add(CurvePoint V) {
        BigInteger xNumerator = x.multiply(V.getY()).add(y.multiply(V.getX()));
        BigInteger xDenominator = BigInteger.ONE.add(BigInteger.valueOf(d).multiply(x)
            .multiply(V.getX()).multiply(y).multiply(V.getY()));
        BigInteger xResult = xNumerator.multiply(xDenominator.modInverse(p)).mod(p);
        BigInteger yNumerator = y.multiply(V.getY()).subtract(x.multiply(V.getX()));
        BigInteger yDenominator = BigInteger.ONE.subtract(BigInteger.valueOf(d).multiply(x)
            .multiply(V.getX()).multiply(y).multiply(V.getY()));
        BigInteger yResult = yNumerator.multiply(yDenominator.modInverse(p)).mod(p);
        return new CurvePoint(xResult, yResult);
    }

}