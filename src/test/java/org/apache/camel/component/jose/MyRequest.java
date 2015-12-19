package org.apache.camel.component.jose;

public class MyRequest {

    private String message;

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public MyRequest(String message) {
        this.message = message;
    }

    public MyRequest() {

    }
}
