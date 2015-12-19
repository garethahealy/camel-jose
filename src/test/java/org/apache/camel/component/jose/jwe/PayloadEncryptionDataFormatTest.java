package org.apache.camel.component.jose.jwe;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.Key;

import org.apache.camel.Exchange;
import org.apache.camel.component.jackson.JacksonDataFormat;
import org.apache.camel.component.jose.JoseTestSupport;
import org.apache.camel.component.jose.MyRequest;
import org.apache.camel.impl.DefaultCamelContext;
import org.apache.camel.impl.DefaultExchange;
import org.jose4j.jwe.ContentEncryptionAlgorithmIdentifiers;
import org.jose4j.jwe.KeyManagementAlgorithmIdentifiers;
import org.jose4j.keys.AesKey;
import org.jose4j.lang.ByteUtil;
import org.junit.Assert;
import org.junit.Test;

public class PayloadEncryptionDataFormatTest extends JoseTestSupport {

    @Test
    public void canUnmarshallAndMarshal() throws Exception {
        AesKey key = new AesKey(ByteUtil.randomBytes(16));

        Exchange marshallExchange = new DefaultExchange(new DefaultCamelContext());
        marshallExchange.getIn().setHeader(Key.class.getName(), key);
        marshallExchange.getIn().setHeader(JweHeaderConstants.ALGORITHM_HEADER_VALUE, KeyManagementAlgorithmIdentifiers.A128KW);
        marshallExchange.getIn().setHeader(JweHeaderConstants.ENCRYPTION_METHOD_HEADER_PARAMETER, ContentEncryptionAlgorithmIdentifiers.AES_128_CBC_HMAC_SHA_256);

        MyRequest request = new MyRequest("Hello Gareth");
        String jsonRequest = getJsonRequest(request, marshallExchange);

        ByteArrayOutputStream stream = new ByteArrayOutputStream();

        PayloadEncryptionDataFormat format = new PayloadEncryptionDataFormat();
        format.marshal(marshallExchange, jsonRequest, stream);

        Exchange unmarshalExchange = new DefaultExchange(new DefaultCamelContext());
        unmarshalExchange.getIn().setHeader(Key.class.getName(), key);

        String jsonResponse = (String)format.unmarshal(unmarshalExchange, new ByteArrayInputStream(stream.toByteArray()));

        Assert.assertNotNull(jsonResponse);

        MyRequest response = (MyRequest)new JacksonDataFormat(MyRequest.class).unmarshal(marshallExchange, new ByteArrayInputStream(jsonResponse.getBytes()));
        Assert.assertNotNull(response);
        Assert.assertNotNull(response.getMessage());
        Assert.assertEquals(request.getMessage(), response.getMessage());
    }
}
