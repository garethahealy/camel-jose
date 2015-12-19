package org.apache.camel.component.jose.jwt;

import java.security.PrivateKey;

import org.apache.camel.Exchange;
import org.apache.camel.Message;
import org.apache.camel.Processor;
import org.apache.camel.util.KeyValueHolder;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class TokenGeneratorProcessor implements Processor {

    private static final Logger LOG = LoggerFactory.getLogger(TokenGeneratorProcessor.class);

    @Override
    public void process(Exchange exchange) throws Exception {
        Message inMessage = exchange.getIn();
        PrivateKey key = inMessage.getHeader(PrivateKey.class.getName(), PrivateKey.class);
        String issuer = inMessage.getHeader(JwtHeaderConstants.ISSUER, String.class);
        String audience = inMessage.getHeader(JwtHeaderConstants.AUDIENCE, String.class);
        Integer expirationTimeMinutesInTheFuture = inMessage.getHeader(JwtHeaderConstants.EXPIRATION_TIME_MINUTES_IN_THE_FUTURE, Integer.class);
        Integer notBeforeMinutesInThePast = inMessage.getHeader(JwtHeaderConstants.NOT_BEFORE_MINUTES_IN_THE_PAST, Integer.class);
        String subject = inMessage.getHeader(JwtHeaderConstants.SUBJECT, String.class);
        KeyValueHolder<String, String> claim = (KeyValueHolder<String, String>)inMessage.getHeader(JwtHeaderConstants.CLAIM, KeyValueHolder.class);
        String keyIdHeaderValue = inMessage.getHeader(JwtHeaderConstants.KEY_ID_HEADER_VALUE, String.class);
        String algorithmHeaderValue = inMessage.getHeader(JwtHeaderConstants.ALGORITHM_HEADER_VALUE, String.class);

        JwtClaims claims = new JwtClaims();
        claims.setIssuer(issuer);
        claims.setAudience(audience);
        claims.setExpirationTimeMinutesInTheFuture(expirationTimeMinutesInTheFuture);
        claims.setGeneratedJwtId();
        claims.setIssuedAtToNow();
        claims.setNotBeforeMinutesInThePast(notBeforeMinutesInThePast);
        claims.setSubject(subject);
        claims.setClaim(claim.getKey(), claim.getValue());

        LOG.trace("Claims: {}", claims.toString());

        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(claims.toJson());
        jws.setKey(key);
        jws.setKeyIdHeaderValue(keyIdHeaderValue);
        jws.setAlgorithmHeaderValue(algorithmHeaderValue);

        LOG.trace("JWS: {}", jws.toString());

        String compactSerialization = jws.getCompactSerialization();

        LOG.trace("CompactSerialization: {}", compactSerialization);

        exchange.getIn().setBody(compactSerialization, String.class);
    }
}
