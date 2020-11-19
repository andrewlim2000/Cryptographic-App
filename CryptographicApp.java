import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Scanner;

import javax.swing.JFileChooser;

/**
 * 
 * @author Andrew Lim
 *
 */
public class CryptographicApp {

    public static void main(String[] args) {
    	// Symmetric Cryptography
        System.out.println("1. Compute a plain cryptographic hash of a given file.");
        System.out.println("2. Compute a plain cryptographic hash of text input.");
        System.out.println("3. Encrypt a given data file symmetrically under a given " +
            "passphrase.");
        System.out.println("4. Decrypt a given symmetric cryptogram under a given " +
            "passphrase.");
        System.out.println("5. Compute an authentication tag (MAC) of a given file " + 
        	"under a given passphrase.");
        
        // Elliptic Curve Cryptography
        System.out.println("6. Generate an elliptic key pair from a given passphrase and " + 
        		"write the public key to a file.");
        System.out.println("7. Encrypt a data file under a given elliptic public key file.");
        System.out.println("8. Decrypt a given elliptic-encrypted file from a given password.");
        System.out.println("9. Sign a given file from a given password and write the " + 
        		"signature to a file.");
        System.out.println("10. Verify a given data file and its signature file under a given " + 
        		"public key file.");
        System.out.print("Select service: ");
        Scanner in = new Scanner(System.in);
        int service = in.nextInt(); 
        in.nextLine();
        if (service == 1) {
            service1();
        } else if (service == 2) {
            service2(in);
        } else if (service == 3) {
            service3(in);
        } else if (service == 4) {
            service4(in);
        } else if (service == 5) {
        	service5(in);
        } else if (service == 6) {
        	service6(in);
        } else if (service == 7) {
        	service7();
        } else if (service == 8) {
        	service8(in);
        } else if (service == 9) {
        	service9(in);
        } else {
        	service10();
        }
    }
    
    public static void service1() {
    	System.out.println("Select file: ");
    	final JFileChooser fc = new JFileChooser();
        int returnVal = fc.showOpenDialog(null);
        if (returnVal == JFileChooser.APPROVE_OPTION) {
            File file = fc.getSelectedFile();
            try {
                byte[] m = Files.readAllBytes(Paths.get(file.getAbsolutePath()));
                String h = SymmetricCryptography.computeCryptographicHash(m);
                System.out.print("Plain cryptographic hash: ");
                System.out.println(h);
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }
    
    public static void service2(Scanner in) {
    	System.out.print("Enter text: ");
        String m = in.nextLine();
        String h = SymmetricCryptography.computeCryptographicHash(m.getBytes());
        System.out.println(h);
    }
    
    public static void service3(Scanner in) {
    	System.out.println("Select data file: ");
    	final JFileChooser fc = new JFileChooser();
        int returnVal = fc.showOpenDialog(null);
        if (returnVal == JFileChooser.APPROVE_OPTION) {
            File file = fc.getSelectedFile();
            try {
                byte[] m = Files.readAllBytes(Paths.get(file.getAbsolutePath()));
                System.out.print("Enter passphrase: ");
                String pw = in.nextLine();
                byte[] cryptogram = SymmetricCryptography.encryptDataFile(m, pw.getBytes());
                OutputStream os = new FileOutputStream(file);
                os.write(cryptogram);
                os.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }
    
    public static void service4(Scanner in) {
    	System.out.println("Select symmetric cryptogram: ");
    	final JFileChooser fc = new JFileChooser();
        int returnVal = fc.showOpenDialog(null);
        if (returnVal == JFileChooser.APPROVE_OPTION) {
            File file = fc.getSelectedFile();
            try {
                byte[] cryptogram = Files.readAllBytes(Paths.get(file.getAbsolutePath()));
                System.out.print("Enter passphrase: ");
                String pw = in.nextLine();
                byte[] m = SymmetricCryptography.decryptCryptogram(cryptogram, pw.getBytes());
                OutputStream os = new FileOutputStream(file);
                os.write(m);
                os.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }
    
    public static void service5(Scanner in) {
    	System.out.println("Select file: ");
    	final JFileChooser fc = new JFileChooser();
        int returnVal = fc.showOpenDialog(null);
        if (returnVal == JFileChooser.APPROVE_OPTION) {
            File file = fc.getSelectedFile();
            try {
            	byte[] m = Files.readAllBytes(Paths.get(file.getAbsolutePath()));
            	System.out.print("Enter passphrase: ");
                String pw = in.nextLine();
                String t = SymmetricCryptography.computeAuthenticationTag(m, pw.getBytes());
                System.out.println(t);
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }
    
    public static void service6(Scanner in) {
    	System.out.print("Enter passphrase: ");
        String pw = in.nextLine();
        KeyPair sV = EllipticCurveCryptography.generateEllipticKeyPair(pw.getBytes());
        CurvePoint V = sV.getV();
        System.out.print("Enter file name to save as: ");
        String fileName = in.nextLine();
        File file = new File(fileName + ".public_key");
        try {
			file.createNewFile();
		} catch (IOException e) {
			e.printStackTrace();
		}        
        FileOutputStream fout = null;
		ObjectOutputStream oos = null;
		try {
			fout = new FileOutputStream(file);
			oos = new ObjectOutputStream(fout);
			oos.writeObject(V);
			System.out.println("Done");
		} catch (Exception ex) {
			ex.printStackTrace();
		}
    }
    
    public static void service7() {
    	System.out.println("Select data file: ");
    	final JFileChooser fc = new JFileChooser();
        int returnVal = fc.showOpenDialog(null);
        if (returnVal == JFileChooser.APPROVE_OPTION) {
            File file = fc.getSelectedFile();
            try {
                byte[] m = Files.readAllBytes(Paths.get(file.getAbsolutePath()));
                CurvePoint V = null;
                System.out.println("Select public key file: ");
                returnVal = fc.showOpenDialog(null);
                if (returnVal == JFileChooser.APPROVE_OPTION) {
                	File file2 = fc.getSelectedFile();
                	try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(file2))) {
                		V = (CurvePoint) ois.readObject();
                	} catch (Exception ex) {
                		ex.printStackTrace();
                	}
                }
                Cryptogram c = EllipticCurveCryptography.encryptDataFile(m, V);
                FileOutputStream fout = null;
        		ObjectOutputStream oos = null;
        		try {
        			fout = new FileOutputStream(file);
        			oos = new ObjectOutputStream(fout);
        			oos.writeObject(c);
        			System.out.println("Done");
        		} catch (Exception ex) {
        			ex.printStackTrace();
        		}
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    public static void service8(Scanner in) {
    	System.out.println("Select elliptic-encrypted file: ");
    	final JFileChooser fc = new JFileChooser();
        int returnVal = fc.showOpenDialog(null);
        if (returnVal == JFileChooser.APPROVE_OPTION) {
            File file = fc.getSelectedFile();
            try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(file))) {
        		Cryptogram Zct = (Cryptogram) ois.readObject();
        		System.out.print("Enter passphrase: ");
                String pw = in.nextLine();
        		byte[] m = EllipticCurveCryptography.decryptCryptogram(Zct, pw.getBytes());
        		OutputStream os = new FileOutputStream(file);
                os.write(m);
                os.close();
        	} catch (Exception ex) {
        		ex.printStackTrace();
        	}
        }
    }
    
    public static void service9(Scanner in) {
    	System.out.print("Select file: ");
    	final JFileChooser fc = new JFileChooser();
        int returnVal = fc.showOpenDialog(null);
        if (returnVal == JFileChooser.APPROVE_OPTION) {
            File file = fc.getSelectedFile();
            try {
                byte[] m = Files.readAllBytes(Paths.get(file.getAbsolutePath()));
                System.out.print("Enter passphrase: ");
                String pw = in.nextLine();
                Signature hz = EllipticCurveCryptography.generateSignature(m, pw.getBytes());
                System.out.print("Enter file name to save as: ");
                String fileName = in.nextLine();
                File file2 = new File(fileName + ".signature");
                try {
        			file2.createNewFile();
        		} catch (IOException e) {
        			e.printStackTrace();
        		}        
                FileOutputStream fout = null;
        		ObjectOutputStream oos = null;
        		try {
        			fout = new FileOutputStream(file2);
        			oos = new ObjectOutputStream(fout);
        			oos.writeObject(hz);
        			System.out.println("Done");
        		} catch (Exception ex) {
        			ex.printStackTrace();
        		}
            } catch (IOException e) {
            	e.printStackTrace();
            }
        }
    }
    
    public static void service10() {
    	System.out.println("Select data file: ");
    	final JFileChooser fc = new JFileChooser();
        int returnVal = fc.showOpenDialog(null);
        if (returnVal == JFileChooser.APPROVE_OPTION) {
        	File file = fc.getSelectedFile();
        	try {
                byte[] m = Files.readAllBytes(Paths.get(file.getAbsolutePath()));
                System.out.println("Select signature file: ");
                returnVal = fc.showOpenDialog(null);
                File file2 = null;
                Signature hz = null;
                if (returnVal == JFileChooser.APPROVE_OPTION) {
                	file2 = fc.getSelectedFile();
                	try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(file2))) {
                		hz = (Signature) ois.readObject();
                	} catch (Exception ex) {
                		ex.printStackTrace();
                	}
                }
                System.out.println("Select public key file: ");
                returnVal = fc.showOpenDialog(null);
                CurvePoint V = null;
                if (returnVal == JFileChooser.APPROVE_OPTION) {
                	File file3 = fc.getSelectedFile();
                	try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(file3))) {
                		V = (CurvePoint) ois.readObject();
                	} catch (Exception ex) {
                		ex.printStackTrace();
                	}
                }
                System.out.println(EllipticCurveCryptography.verifySignature(hz, m, V));
        	} catch (IOException e) {
        		e.printStackTrace();
        	}
        }
    }
    
}
