package org.apache.camel.component.jose.jwe;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.security.Key;

import org.apache.camel.Exchange;
import org.apache.camel.Message;
import org.apache.camel.spi.DataFormat;
import org.apache.camel.util.IOHelper;
import org.apache.commons.io.IOUtils;
import org.jose4j.jwe.JsonWebEncryption;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class PayloadEncryptionDataFormat implements DataFormat {

    private static final Logger LOG = LoggerFactory.getLogger(PayloadEncryptionDataFormat.class);

    @Override
    public void marshal(Exchange exchange, Object graph, OutputStream outputStream) throws Exception {
        if (!(graph instanceof String)) {
            throw new IllegalArgumentException("Expected body to be a String");
        }

        Message inMessage = exchange.getIn();
        Key key = inMessage.getHeader(Key.class.getName(), Key.class);
        String algorithmHeaderValue = inMessage.getHeader(JweHeaderConstants.ALGORITHM_HEADER_VALUE, String.class);
        String encryptionMethodHeaderParameter = inMessage.getHeader(JweHeaderConstants.ENCRYPTION_METHOD_HEADER_PARAMETER, String.class);

        if (key == null) {
            throw new IllegalArgumentException("" + Key.class.getName() + " header is null");
        }

        if (algorithmHeaderValue == null || algorithmHeaderValue.length() <= 0) {
            throw new IllegalArgumentException("" + JweHeaderConstants.ALGORITHM_HEADER_VALUE + " header is null or empty");
        }

        if (encryptionMethodHeaderParameter == null || algorithmHeaderValue.length() <= 0) {
            throw new IllegalArgumentException("" + JweHeaderConstants.ENCRYPTION_METHOD_HEADER_PARAMETER + " header is null or empty");
        }

        JsonWebEncryption senderJwe = new JsonWebEncryption();
        senderJwe.setPayload(graph.toString());
        senderJwe.setAlgorithmHeaderValue(algorithmHeaderValue);
        senderJwe.setEncryptionMethodHeaderParameter(encryptionMethodHeaderParameter);
        senderJwe.setKey(key);

        LOG.trace("JWE: {}", senderJwe.toString());

        String compactSerialization = senderJwe.getCompactSerialization();

        LOG.trace("CompactSerialization: {}", compactSerialization);

        outputStream.write(compactSerialization.getBytes(IOHelper.getCharsetName(exchange)));
    }

    @Override
    public Object unmarshal(Exchange exchange, InputStream inputStream) throws Exception {
        Key key = exchange.getIn().getHeader(Key.class.getName(), Key.class);

        if (key == null) {
            throw new IllegalArgumentException("" + Key.class.getName() + " header is null");
        }

        BufferedReader reader = IOHelper.buffered(new InputStreamReader(inputStream, IOHelper.getCharsetName(exchange)));
        String body = IOUtils.toString(reader);
        IOHelper.close(reader);

        JsonWebEncryption receiverJwe = new JsonWebEncryption();
        receiverJwe.setCompactSerialization(body);
        receiverJwe.setKey(key);

        return receiverJwe.getPlaintextString();
    }
}
