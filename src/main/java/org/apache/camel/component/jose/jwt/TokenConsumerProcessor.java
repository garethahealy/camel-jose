package org.apache.camel.component.jose.jwt;

import java.security.PublicKey;

import org.apache.camel.Exchange;
import org.apache.camel.Message;
import org.apache.camel.Processor;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;

public class TokenConsumerProcessor implements Processor {

    @Override
    public void process(Exchange exchange) throws Exception {
        Message inMessage = exchange.getIn();
        String jwt = inMessage.getHeader(JwtHeaderConstants.JWT, String.class);

        if (jwt == null || jwt.length() <= 0) {
            throw new IllegalArgumentException("" + JwtHeaderConstants.JWT + " header is null or empty");
        }

        JwtConsumer jwtConsumer = buildJwtConsumer(exchange);
        jwtConsumer.processToClaims(jwt);
    }

    protected JwtConsumer buildJwtConsumer(Exchange exchange) {
        Message inMessage = exchange.getIn();
        PublicKey key = inMessage.getHeader(PublicKey.class.getName(), PublicKey.class);
        String expectedIssuer = inMessage.getHeader(JwtHeaderConstants.EXPECTED_ISSUER, String.class);
        String expectedAudience = inMessage.getHeader(JwtHeaderConstants.EXPECTED_AUDIENCE, String.class);

        if (key == null) {
            throw new IllegalArgumentException("" + PublicKey.class.getName() + " header is null");
        }

        if (expectedIssuer == null || expectedIssuer.length() <= 0) {
            throw new IllegalArgumentException("" + JwtHeaderConstants.EXPECTED_ISSUER + " header is null or empty");
        }

        if (expectedAudience == null || expectedAudience.length() <= 0) {
            throw new IllegalArgumentException("" + JwtHeaderConstants.EXPECTED_AUDIENCE + " header is null or empty");
        }

        JwtConsumer jwtConsumer = new JwtConsumerBuilder()
                .setRequireExpirationTime()
                .setAllowedClockSkewInSeconds(30)
                .setRequireSubject()
                .setExpectedIssuer(expectedIssuer)
                .setExpectedAudience(expectedAudience)
                .setVerificationKey(key)
                .build();

        return jwtConsumer;
    }
}
