package org.apache.camel.component.jose.jwt;

import org.apache.camel.Endpoint;
import org.apache.camel.Exchange;
import org.apache.camel.impl.DefaultProducer;

public class JwtProducer extends DefaultProducer {

    private TokenConsumerProcessor processor;

    public JwtProducer(Endpoint endpoint, TokenConsumerProcessor processor) {
        super(endpoint);

        this.processor = processor;
    }

    @Override
    public void process(Exchange exchange) throws Exception {
        processor.process(exchange);
    }
}
