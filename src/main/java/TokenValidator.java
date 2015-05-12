import com.google.gson.JsonParser;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.InvalidJwtException;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;

import com.google.gson.JsonObject;

import java.security.Key;

/**
 * Set of utilities for managing authentication tasks
 */
public final class TokenValidator {

  // JWT Validator
  private final JwtConsumer jwtConsumer;

  public TokenValidator( Key verificationKey, String audience ) {

    this.jwtConsumer =
      new JwtConsumerBuilder()
        .setRequireSubject()
        .setExpectedAudience( audience )
        .setVerificationKey( verificationKey )
        .build();
  }

  public final JsonObject getTokenProperties( String token ) {
    try {
      // Validate JWT and process
      JwtClaims jwtClaims = jwtConsumer.processToClaims( token );
      String jsonClaims = jwtClaims.getRawJson();
      JsonObject result = new JsonParser().parse(jsonClaims).getAsJsonObject();
      return result;

    } catch ( InvalidJwtException ije ) {
      System.err.println("Error processing JWT: " + ije.getMessage());
      return null;
    }
  }
}