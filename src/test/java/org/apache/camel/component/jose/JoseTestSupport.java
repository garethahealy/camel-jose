package org.apache.camel.component.jose;

import java.io.ByteArrayOutputStream;
import java.security.KeyPair;
import java.security.spec.ECParameterSpec;

import org.apache.camel.Exchange;
import org.apache.camel.component.jackson.JacksonDataFormat;
import org.apache.camel.test.junit4.TestSupport;
import org.jose4j.keys.EcKeyUtil;
import org.jose4j.lang.JoseException;

public class JoseTestSupport extends TestSupport {

    protected String getJsonRequest(MyRequest request, Exchange marshallExchange) throws Exception {
        ByteArrayOutputStream jsonStream = new ByteArrayOutputStream();
        new JacksonDataFormat().marshal(marshallExchange, request, jsonStream);

        String json = new String(jsonStream.toByteArray());

        jsonStream.close();

        return json;
    }

    /**
     * @param spec - see: EllipticCurves
     * @return
     * @throws JoseException
     */
    protected KeyPair getKeypair(ECParameterSpec spec) throws JoseException {
        EcKeyUtil keyUtil = new EcKeyUtil();
        KeyPair keyPair = keyUtil.generateKeyPair(spec);

        return keyPair;
    }
}
