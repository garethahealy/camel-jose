package org.apache.camel.component.jose.jws;

import java.security.PublicKey;

import org.apache.camel.Exchange;
import org.apache.camel.Message;
import org.apache.camel.Processor;
import org.jose4j.jws.JsonWebSignature;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class VerifacationProcessor implements Processor {

    private static final Logger LOG = LoggerFactory.getLogger(VerifacationProcessor.class);

    @Override
    public void process(Exchange exchange) throws Exception {
        Message inMessage = exchange.getIn();
        String body = inMessage.getMandatoryBody(String.class);
        PublicKey key = inMessage.getHeader(PublicKey.class.getName(), PublicKey.class);

        if (body == null || body.length() <= 0) {
            throw new IllegalArgumentException("body is null or empty");
        }

        if (key == null) {
            throw new IllegalArgumentException("" + PublicKey.class.getName() + " header is null");
        }

        JsonWebSignature jws = new JsonWebSignature();
        jws.setCompactSerialization(body);
        jws.setKey(key);

        LOG.trace("JWS: {}", jws.toString());

        boolean signatureVerified = jws.verifySignature();
        if (!signatureVerified) {
            LOG.trace("Failed to verify: ", body);

            throw new SecurityException("Failed to verify");
        }

        exchange.getIn().setBody(jws.getPayload(), String.class);
    }
}
