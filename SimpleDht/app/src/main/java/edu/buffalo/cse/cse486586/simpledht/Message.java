package edu.buffalo.cse.cse486586.simpledht;

public class Message {
    int myPort;
    String status;
    String key;
    String value;

    public Message(int myPort, String status, String key, String value) {
        this.myPort = myPort;
        this.status = status;
        this.key = key;
        this.value = value;
    }

    @Override
    public String toString() {
        StringBuilder res = new StringBuilder();
        res.append(this.myPort);
        res.append(";");
        res.append(this.status);
        res.append(";");
        res.append(this.key);
        res.append(";");
        res.append(this.value);
        return res.toString();
    }
}
