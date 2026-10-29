package es.codeurjc.mastercloudapps.amqp;

import tools.jackson.databind.ObjectMapper;

public class ExampleData {
    private String data;
    private int index;
    private boolean isEvenIndex;

    public ExampleData(String data, int index, boolean isEvenIndex) {
        this.data = data;
        this.index = index;
        this.isEvenIndex = isEvenIndex;
    }

    public String getData() {
        return data;
    }

    public void setData(String data) {
        this.data = data;
    }

    public int getIndex() {
        return index;
    }

    public void setIndex(int index) {
        this.index = index;
    }

    public boolean isEvenIndex() {
        return isEvenIndex;
    }

    public void setEvenIndex(boolean isEvenIndex) {
        this.isEvenIndex = isEvenIndex;
    }

    @Override
    public String toString() {
        ObjectMapper mapper = new ObjectMapper();
        try {
            return mapper.writeValueAsString(this);
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

}
