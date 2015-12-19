package org.apache.camel.component.jose.jwt;

import org.apache.camel.Consumer;
import org.apache.camel.Processor;
import org.apache.camel.Producer;
import org.apache.camel.RuntimeCamelException;
import org.apache.camel.impl.DefaultEndpoint;

public class JwtEndpoint extends DefaultEndpoint {

    @Override
    public Producer createProducer() throws Exception {
        return new JwtProducer(this, new TokenConsumerProcessor());
    }

    @Override
    public Consumer createConsumer(Processor processor) throws Exception {
        throw new RuntimeCamelException("Cannot consume to a JwtEndpoint: " + getEndpointUri());
    }

    @Override
    public boolean isSingleton() {
        return true;
    }
}
