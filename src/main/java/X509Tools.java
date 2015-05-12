import javax.xml.bind.DatatypeConverter;
import java.io.ByteArrayInputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.*;

public final class X509Tools {

  private static final String
    BEGIN = "-----BEGIN PUBLIC KEY-----",
    END = "-----END PUBLIC KEY-----";

  /**
    * Prints the hex string of the thumbprint digest bytes
  * for the provided certificate.
  *
    * @param cert
  * @return
    * @throws NoSuchAlgorithmException
  * @throws CertificateEncodingException
  */
  public static final String getThumbPrint(Certificate cert)
    throws NoSuchAlgorithmException, CertificateEncodingException {
    MessageDigest md = MessageDigest.getInstance( "SHA1" );
    byte[] der = cert.getEncoded();
    md.update(der);
    byte[] digest = md.digest();
    return DatatypeConverter.printHexBinary( digest );
  }

  /**
   * Converts PEM String to Certificate object
   *
   * @param pemCert PEM certificate
   * @return Certificate object of PEM
   * @throws CertificateException
   */
  public static final X509Certificate getCertificate(String pemCert) throws CertificateException {
    CertificateFactory fact = CertificateFactory.getInstance("X.509");
    X509Certificate cert = (X509Certificate) fact.generateCertificate(new ByteArrayInputStream(pemCert.getBytes()));
    return cert;
  }

  /**
   * Converts XAML BinarySecurityToken data into PEM format.
   *
   * @param x509Data base 64 text
   * @return PEM formatted certificate String
   */
  public static final String binarySecurityTokenToPEM(String x509Data) {
    x509Data = x509Data.trim();
    StringBuilder pem = new StringBuilder();
    pem.append(BEGIN);
    int i, len;
    for (i = 0, len = x509Data.length(); i + 64 < len; i += 64) {
      pem.append("\n");
      pem.append(x509Data.substring(i, i + 64));
    }
    pem.append("\n").append(x509Data.substring(i));
    if (!"\n".equals(pem.substring(pem.length() - 1, pem.length()))) {
      pem.append("\n");
    }
    pem.append(END);

    return pem.toString();
  }

}
