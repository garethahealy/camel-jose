package org.apache.camel.component.jose.jws;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

import org.apache.camel.component.jose.JoseTestSupport;
import org.apache.camel.component.jose.MyRequest;
import org.apache.camel.impl.DefaultCamelContext;
import org.apache.camel.impl.DefaultExchange;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.keys.EllipticCurves;
import org.junit.Assert;
import org.junit.Test;

public class SigningProcessorTest extends JoseTestSupport {

    @Test
    public void canSign() throws Exception {
        KeyPair keyPair = getKeypair(EllipticCurves.P256);

        DefaultExchange exchange = new DefaultExchange(new DefaultCamelContext());

        MyRequest request = new MyRequest("Hello Gareth");
        String jsonRequest = getJsonRequest(request, exchange);

        exchange.getIn().setBody(jsonRequest);
        exchange.getIn().setHeader(JwsHeaderConstants.ALGORITHM_IDENTIFIERS, AlgorithmIdentifiers.ECDSA_USING_P256_CURVE_AND_SHA256);
        exchange.getIn().setHeader(PrivateKey.class.getName(), keyPair.getPrivate());

        SigningProcessor processor = new SigningProcessor();
        processor.process(exchange);

        String body = exchange.getIn().getBody(String.class);

        Assert.assertNotNull(body);

        verify(keyPair, body);
    }

    private void verify(KeyPair keyPair, String signed) throws Exception {
        DefaultExchange exchange = new DefaultExchange(new DefaultCamelContext());
        exchange.getIn().setBody(signed);
        exchange.getIn().setHeader(PublicKey.class.getName(), keyPair.getPublic());

        VerifacationProcessor processor = new VerifacationProcessor();
        processor.process(exchange);
    }
}
