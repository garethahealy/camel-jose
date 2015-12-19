package org.apache.camel.component.jose.jws;

import java.security.PrivateKey;

import org.apache.camel.Exchange;
import org.apache.camel.Message;
import org.apache.camel.Processor;
import org.jose4j.jws.JsonWebSignature;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SigningProcessor implements Processor {

    private static final Logger LOG = LoggerFactory.getLogger(SigningProcessor.class);

    @Override
    public void process(Exchange exchange) throws Exception {
        Message inMessage = exchange.getIn();
        String body = inMessage.getBody(String.class);
        String algorithmIdentifiers = inMessage.getHeader(JwsHeaderConstants.ALGORITHM_IDENTIFIERS, String.class);
        PrivateKey key = inMessage.getHeader(PrivateKey.class.getName(), PrivateKey.class);

        if (body == null || body.length() <= 0) {
            throw new IllegalArgumentException("body is null or empty");
        }

        if (algorithmIdentifiers == null || algorithmIdentifiers.length() <= 0) {
            throw new IllegalArgumentException("" + JwsHeaderConstants.ALGORITHM_IDENTIFIERS + " header is null or empty");
        }

        if (key == null) {
            throw new IllegalArgumentException("" + PrivateKey.class.getName() + " header is null");
        }

        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload(body);
        jws.setAlgorithmHeaderValue(algorithmIdentifiers);
        jws.setKey(key);

        LOG.trace("JWS: {}", jws.toString());

        String jwsCompactSerialization = jws.getCompactSerialization();

        LOG.trace("CompactSerialization: {}", jwsCompactSerialization);

        exchange.getIn().setBody(jwsCompactSerialization, String.class);
    }
}
