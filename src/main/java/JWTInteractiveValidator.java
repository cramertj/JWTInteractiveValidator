import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.jose4j.base64url.Base64;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.IOException;
import java.net.URL;
import java.security.Key;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Scanner;

public class JWTInteractiveValidator {

  public static void main( String[] args ) {
    String federationMetaDocPath = "";
    String jwtString = "";
    String audience = "";

    if ( args.length == 3 ) {
      federationMetaDocPath = args[0];
      jwtString = args[1];
      audience = args[2];
    } else if ( args.length != 0 ) {
      System.err.println( "Usage: path to federation metadata document, jwt string, audience" );
      System.exit( 0 );
    } else {
      Scanner scanner = new Scanner( System.in );

      System.out.println( "Enter the path to the federation metadata document: " );
      federationMetaDocPath = scanner.next();

      System.out.println( "Enter the JWT you wish to verify: " );
      jwtString = scanner.next();
    }


    try {

      NodeList certList = getCertList( federationMetaDocPath );

      // Create map from x5t thumbprint to cert
      HashMap<String, Key> x5tToCertMap = new HashMap<String, Key>();

      for ( int i = 0; i < certList.getLength(); i++ ) {
        String base64cert = certList.item( i ).getTextContent();
        String pemString = X509Tools.binarySecurityTokenToPEM( base64cert );
        X509Certificate cert = X509Tools.getCertificate( pemString );

        String x5t = X509Tools.getThumbPrint( cert );
        Key publicKey = cert.getPublicKey();

        System.out.println( "Mapping from " + x5t + " to " + cert.getEncoded() );

        x5tToCertMap.put( x5t, publicKey );
      }

      JsonObject jwtProperties = null;

      String header = new String( Base64.decode( jwtString.split( "\\." )[0] ) );
      String x5t = new JsonParser().parse( header ).getAsJsonObject().get( "x5t" ).getAsString();
      x5t = getHex( Base64.decode( x5t ) );

      System.out.println( "Looking for map from " + x5t );

      Key publicKey = x5tToCertMap.get( x5t );

      TokenValidator jwtValidator = new TokenValidator( publicKey, audience );
      jwtProperties = jwtValidator.getTokenProperties( jwtString );

      Gson gson = new GsonBuilder().setPrettyPrinting().create();

      if ( jwtProperties != null ) {
        System.out.println(
          "public key:\t" + Base64.encode( publicKey.getEncoded() ) + "\n" +
            "json result: " + gson.toJson( jwtProperties )
        );
      }

    } catch ( Exception e ) {
      e.printStackTrace();
    }

  }

  /**
   * Gets the list of XML Nodes containing valid certificates
   *
   * @param federationMetaDocPath URL of the Federation Meta Doc
   * @return
   * @throws ParserConfigurationException
   * @throws IOException
   * @throws SAXException
   */
  public static final NodeList getCertList( String federationMetaDocPath ) throws ParserConfigurationException, IOException, SAXException {
    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
    dbf.setNamespaceAware( true );

    DocumentBuilder db = dbf.newDocumentBuilder();
    Document doc = db.parse( new URL( federationMetaDocPath ).openStream() );

    Element root = doc.getDocumentElement();
    NodeList roleDescriptorList = root.getElementsByTagName( "RoleDescriptor" );

    if ( roleDescriptorList.getLength() < 1 ) {
      System.err.println( "Invalid federation metadata" );
      System.exit( 0 );
    }

    Node roleDescriptor = roleDescriptorList.item( 0 );

    NodeList certList = new NodeList() {
      @Override
      public Node item( int index ) {
        return null;
      }

      @Override
      public int getLength() {
        return 0;
      }
    };

    if ( roleDescriptor instanceof Element ) {
      Element elem = (Element) roleDescriptor;
      certList = elem.getElementsByTagName( "X509Certificate" );
    } else {
      System.err.println( "Invalid federation metadata" );
      System.exit( 0 );
    }

    return certList;
  }

  /**
   * Converts a byte array to a hex-encoded String
   *
   * @param bytes to encode
   * @return hexadecimal String
   */
  private static final String getHex( byte bytes[] ) {

    char[] hexDigits =
      {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D',
        'E', 'F'};

    StringBuffer buf = new StringBuffer( bytes.length * 2 );

    for ( int i = 0; i < bytes.length; ++i ) {
      buf.append( hexDigits[(bytes[i] & 0xf0) >> 4] );
      buf.append( hexDigits[bytes[i] & 0x0f] );
    }

    return buf.toString();
  }
}
