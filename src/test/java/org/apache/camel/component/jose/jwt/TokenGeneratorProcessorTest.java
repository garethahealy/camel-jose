package org.apache.camel.component.jose.jwt;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

import org.apache.camel.component.jose.JoseTestSupport;
import org.apache.camel.impl.DefaultCamelContext;
import org.apache.camel.impl.DefaultExchange;
import org.apache.camel.util.KeyValueHolder;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.keys.EllipticCurves;
import org.junit.Assert;
import org.junit.Test;

public class TokenGeneratorProcessorTest extends JoseTestSupport {

    @Test
    public void canGenerate() throws Exception {
        KeyPair keyPair = getKeypair(EllipticCurves.P256);

        DefaultExchange exchange = new DefaultExchange(new DefaultCamelContext());
        exchange.getIn().setHeader(PrivateKey.class.getName(), keyPair.getPrivate());
        exchange.getIn().setHeader(JwtHeaderConstants.ISSUER, "Camel");
        exchange.getIn().setHeader(JwtHeaderConstants.AUDIENCE, "GarethHealy");
        exchange.getIn().setHeader(JwtHeaderConstants.EXPIRATION_TIME_MINUTES_IN_THE_FUTURE, 1);
        exchange.getIn().setHeader(JwtHeaderConstants.NOT_BEFORE_MINUTES_IN_THE_PAST, 1);
        exchange.getIn().setHeader(JwtHeaderConstants.SUBJECT, "UnitTest");
        exchange.getIn().setHeader(JwtHeaderConstants.CLAIM, new KeyValueHolder<String, String>("email", "gareth@healy.com"));
        exchange.getIn().setHeader(JwtHeaderConstants.KEY_ID_HEADER_VALUE, "1");
        exchange.getIn().setHeader(JwtHeaderConstants.ALGORITHM_HEADER_VALUE, AlgorithmIdentifiers.ECDSA_USING_P256_CURVE_AND_SHA256);

        TokenGeneratorProcessor processor = new TokenGeneratorProcessor();
        processor.process(exchange);

        String body = exchange.getIn().getBody(String.class);

        Assert.assertNotNull(body);

        consume(keyPair, body);
    }

    private void consume(KeyPair keyPair, String token) throws Exception {
        DefaultExchange exchange = new DefaultExchange(new DefaultCamelContext());
        exchange.getIn().setHeader(PublicKey.class.getName(), keyPair.getPublic());
        exchange.getIn().setHeader(JwtHeaderConstants.JWT, token);
        exchange.getIn().setHeader(JwtHeaderConstants.EXPECTED_ISSUER, "Camel");
        exchange.getIn().setHeader(JwtHeaderConstants.EXPECTED_AUDIENCE, "GarethHealy");

        TokenConsumerProcessor processor = new TokenConsumerProcessor();
        processor.process(exchange);
    }
}
