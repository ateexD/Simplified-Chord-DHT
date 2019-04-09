package edu.buffalo.cse.cse486586.simpledht;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Formatter;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

import android.content.ContentProvider;
import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.database.MatrixCursor;
import android.net.Uri;
import android.os.AsyncTask;
import android.provider.ContactsContract;
import android.telephony.TelephonyManager;
import android.util.JsonReader;
import android.util.Log;

import org.json.JSONObject;

import static android.content.ContentValues.TAG;
import static android.content.Context.MODE_PRIVATE;


public class SimpleDhtProvider extends ContentProvider {

    // HashMaps
    public TreeMap<String, Integer> allNodeHashMap = new TreeMap<String, Integer>();
    public HashMap<Integer, Socket> clientSocketHashMap = new HashMap<Integer, Socket>();

    public String myHash = null;

    // Telephone number - Port number hack
    TelephonyManager tel;
    String portStr;
    Integer myPort;

    // Timeout variable
    Integer TIMEOUT = 3000;

    // All ports
    final int[] portsToSend = {11108, 11112, 11116, 11120, 11124};

    // Again, one lock to rule them all
    public Lock lock = new ReentrantLock();

    // Successor and predecessor ID
    Integer succId = null, prevId = null;


    private String genHash(String input) throws NoSuchAlgorithmException {
        MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
        byte[] sha1Hash = sha1.digest(input.getBytes());
        Formatter formatter = new Formatter();
        for (byte b : sha1Hash) {
            formatter.format("%02x", b);
        }
        return formatter.toString();
    }

    public boolean canDoOperation(String lookupHash) {
        String predHash = "", succHash = "";
        try {
            predHash = genHash(Integer.toString(prevId));
            succHash = genHash(Integer.toString(succId));
        } catch (Exception e) {
            e.printStackTrace();
        }
        boolean isFirstNode = (predHash.compareTo(myHash) > 0) && (succHash.compareTo(myHash) > 0);
        boolean prevCondition = lookupHash.compareTo(predHash) > 0;
        boolean currCondition = lookupHash.compareTo(myHash) < 0;

        return ((isFirstNode && (prevCondition || currCondition)) ||
                (!isFirstNode && prevCondition && currCondition));
    }

    public Socket addOrGetSocket(int portNum) {
        try {
            if (clientSocketHashMap.containsKey(portNum))
                return clientSocketHashMap.get(portNum);

            Socket socket = new Socket(InetAddress.getByAddress(new byte[]{10, 0, 2, 2}), portNum);
            clientSocketHashMap.put(portNum, socket);
            return socket;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public Message deserialize(String messageString) {

        String[] split = messageString.split("\\;");
        int port = Integer.parseInt(split[0]);
        String status = split[1];
        String key = split[2];
        String value = split[3];
        return new Message(port, status, key, value);
    }

    public String getJSONAsString() {
        // Convert JSON file to string
        int i;

        FileInputStream fileInputStream;
        StringBuilder sb = new StringBuilder();

        try {
            fileInputStream = getContext().openFileInput("myJSON.json");

            if (fileInputStream != null)
                while ((i = fileInputStream.read()) != -1)
                    sb.append((char) i);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return sb.toString();
    }

    public void writeToJSON(JSONObject jsonObject) {
        // Dump JsonObject to myJSON.json
        try {
            FileOutputStream fileOutputStream = getContext().openFileOutput("myJSON.json", MODE_PRIVATE);
            if (fileOutputStream != null) {
                OutputStreamWriter outputStreamWriter = new OutputStreamWriter(fileOutputStream);
                outputStreamWriter.write(jsonObject.toString());
                outputStreamWriter.flush();
                outputStreamWriter.close();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void persist(String key, String value) {
        try {
            JSONObject jsonObject = new JSONObject(getJSONAsString());
            jsonObject.put(key, value);
            writeToJSON(jsonObject);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public String getPredecessorAndSuccessorNodes(String hash, int nodePort) {

        // Format of return string - [predecessor port;successor port]
        // String to return
        StringBuilder res = new StringBuilder();

        Map.Entry<String, Integer> predId = allNodeHashMap.floorEntry(hash);
        Map.Entry<String, Integer> succId = allNodeHashMap.ceilingEntry(hash);

        // If no predecessor, this should be head
        if (predId == null) {
            res.append(allNodeHashMap.get(allNodeHashMap.lastKey()));
            res.append(";");
            res.append(succId.getValue());
        }

        // If no successor, this should be tail
        else if (succId == null) {
            res.append(predId.getValue());
            res.append(";");
            res.append(allNodeHashMap.get(allNodeHashMap.firstKey()));
        }

        // If neither are null, send rightful position
        else {
            res.append(predId.getValue());
            res.append(";");
            res.append(succId.getValue());
        }
        allNodeHashMap.put(hash, nodePort);

        Log.d("Ring status", "------");
        for (String key : allNodeHashMap.keySet()) {
            Log.d(key, allNodeHashMap.get(key) + "");
        }
        Log.d("Ring status", "------");
        Log.d("Computed res", hash + ";" + res.toString());
        return res.toString();
    }


    @Override
    public int delete(Uri uri, String selection, String[] selectionArgs) {
        // TODO Auto-generated method stub
        lock.lock();
        try {
            JSONObject jsonObject = new JSONObject(getJSONAsString());
            if (selection.equals("@")) {

                Iterator<String> keys = jsonObject.keys();

                while (keys.hasNext())
                    jsonObject.remove(keys.next());

            } else
                jsonObject.remove(selection);

            writeToJSON(jsonObject);

        } catch (Exception e) {
            e.printStackTrace();
        }
        lock.unlock();
        return 0;
    }


    @Override
    public String getType(Uri uri) {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public Uri insert(Uri uri, ContentValues values) {
        // TODO Auto-generated method stub
        Log.d("..", "Inserting..");
        lock.lock();
        try {
            String key = (String) values.get("key"), value = (String) values.get("value");
            String keyHash = genHash(key);

            if ((prevId == null && succId == null) || canDoOperation(keyHash)) {
                persist(key, value);
            } else {
                Message message = new Message(myPort, "INSERT", key, value);
                new Client().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR, message);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        lock.unlock();
        return uri;
    }

    @Override
    public boolean onCreate() {
        lock.lock();
        Log.d("..", "Creation");
        try {
            tel = (TelephonyManager) this.getContext().getSystemService(Context.TELEPHONY_SERVICE);
            portStr = tel.getLine1Number().substring(tel.getLine1Number().length() - 4);
            myPort = Integer.parseInt(portStr);

            try {
                ServerSocket serverSocket = new ServerSocket(10000);
                new Server().executeOnExecutor(AsyncTask.THREAD_POOL_EXECUTOR, serverSocket);
            } catch (IOException e) {
                e.printStackTrace();
            }

            Log.d("Port", portStr);

            if (!portStr.equals("5554")) {
                Log.d("Joining", portsToSend[0] + "");
                Message m = new Message(myPort, "JOIN", " ", " ");
                Log.d("Join Message", m.toString());
                new Client().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR, m);
            } else {
                myHash = genHash(myPort + "");
                allNodeHashMap.put(myHash, myPort);
            }
            JSONObject jsonObject = new JSONObject();
            writeToJSON(jsonObject);
        } catch (Exception e) {
            e.printStackTrace();
        }
        lock.unlock();
        return true;

    }

    @Override
    public Cursor query(Uri uri, String[] projection, String selection, String[] selectionArgs,
                        String sortOrder) {
        // TODO Auto-generated method stub
        lock.lock();
        MatrixCursor matrixCursor = new MatrixCursor(new String[]{"key", "value"});
        try {
            JSONObject jsonObject = new JSONObject(getJSONAsString());
            Log.d(TAG, selection);

            if ((selection.equals("*") && prevId == null && succId == null) || selection.equals("@")) {
                Iterator<String> keys = jsonObject.keys();
                Log.d("Query", selection);
                while (keys.hasNext()) {
                    String currKey = (keys.next());
                    Object[] row = {currKey, jsonObject.get(currKey)};
                    matrixCursor.addRow(row);
                }
            }
            else if (selection.equals("*")) {
                Message m = new Message(myPort, "QUERY", "*", getJSONAsString());

                Socket socket = addOrGetSocket(succId * 2);
                DataInputStream dataInputStream = new DataInputStream(socket.getInputStream());
                DataOutputStream dataOutputStream = new DataOutputStream(socket.getOutputStream());

                dataOutputStream.writeUTF(m.toString());
                dataOutputStream.flush();

                String reply = dataInputStream.readUTF();
                JSONObject replyJSON = new JSONObject(deserialize(reply).value);
                Iterator<String> keys = replyJSON.keys();

                Log.d("Query", selection);
                while (keys.hasNext()) {
                    String currKey = (keys.next());
                    Object[] row = {currKey, replyJSON.get(currKey)};
                    matrixCursor.addRow(row);
                }

            }
            else {
                String keyHash = genHash(selection);
                if (jsonObject.has(selection) || canDoOperation(keyHash)) {
                    String val = (String) jsonObject.get(selection);
                    Log.d("Query", selection + " - " + val);
                    Object[] row = {selection, val};
                    matrixCursor.addRow(row);
                }
                else {
                    Message m = new Message(myPort, "QUERY", selection, " ");
                    Socket socket = addOrGetSocket(succId * 2);
                    DataInputStream dataInputStream = new DataInputStream(socket.getInputStream());
                    DataOutputStream dataOutputStream = new DataOutputStream(socket.getOutputStream());

                    dataOutputStream.writeUTF(m.toString());
                    dataOutputStream.flush();

                    String reply = dataInputStream.readUTF();
                    Object[] row = {selection, reply};
                    matrixCursor.addRow(row);
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
            Log.e(TAG, "Not found");
        }

        Log.v("query", selection);
        lock.unlock();
        return matrixCursor;
    }

    @Override
    public int update(Uri uri, ContentValues values, String selection, String[] selectionArgs) {
        // TODO Auto-generated method stub
        return 0;
    }


    private class Server extends AsyncTask<ServerSocket, Void, Void> {

        private class ServerThread implements Runnable {
            Socket socket;

            public ServerThread(Socket socket) {
                this.socket = socket;
            }

            @Override
            public void run() {
                DataInputStream dis = null;
                InputStream is;
                Message m = null;
                DataOutputStream dos = null;
                OutputStream os;

                try {
                    os = socket.getOutputStream();
                    is = socket.getInputStream();
                    dis = new DataInputStream(is);
                    dos = new DataOutputStream(os);
                } catch (Exception e) {
                    e.printStackTrace();
                }

                while (true) {
                    try {
                        m = deserialize(dis.readUTF());

                        if (m.status.equals("JOIN")) {
                            lock.lock();
                            Log.d("Adding to ring", m.myPort + "");
                            String nodeHash = genHash(Integer.toString(m.myPort));
                            String toSend = getPredecessorAndSuccessorNodes(nodeHash, m.myPort);

                            dos.writeUTF(nodeHash + ";" + toSend);
                            dos.flush();
                            lock.unlock();
                        } else if (m.status.equals("UPDATE_SUCCESSOR")) {
                            lock.lock();
                            succId = m.myPort;
                            lock.unlock();

                        } else if (m.status.equals("UPDATE_PREDECESSOR")) {
                            lock.lock();
                            prevId = m.myPort;
                            lock.unlock();
                        } else if (m.status.equals("INSERT")) {
                            lock.lock();
                            String keyHash = genHash(m.key);
                            if (canDoOperation(keyHash))
                                persist(m.key, m.value);
                            else
                                new Client().executeOnExecutor(AsyncTask.SERIAL_EXECUTOR, m);
                            lock.unlock();
                        } else if (m.status.equals("QUERY")) {
                            lock.lock();
                            Log.d("query", m.toString());
                            String keyHash = genHash(m.key);
                            if (m.key.equals("*")) {
                                JSONObject jsonObject = new JSONObject(getJSONAsString());
                                JSONObject accumulatedSoFar = new JSONObject(m.value);

                                Iterator<String> keys = jsonObject.keys();

                                while(keys.hasNext()) {
                                    String currKey = keys.next();
                                    accumulatedSoFar.put(currKey, jsonObject.get(currKey));
                                }
                                m.value = accumulatedSoFar.toString();

                                if (succId == m.myPort) {
                                    Log.d("QUERY *", m.value);
                                    dos.writeUTF(m.toString());
                                    dos.flush();
                                }
                                else {
                                    Socket socket = addOrGetSocket(succId * 2);
                                    DataOutputStream dataOutputStream = new DataOutputStream(socket.getOutputStream());
                                    dataOutputStream.writeUTF(m.toString());
                                    dataOutputStream.flush();

                                    DataInputStream dataInputStream = new DataInputStream(socket.getInputStream());
                                    String result = dataInputStream.readUTF();
                                    dos.writeUTF(result);
                                    dos.flush();

                                }
                            }
                            else if (canDoOperation(keyHash)) {
                                JSONObject jsonObject = new JSONObject(getJSONAsString());
                                dos.writeUTF((String)jsonObject.get(m.key));
                                dos.flush();
                            }
                            else {
                                Socket socket = addOrGetSocket(succId * 2);
                                DataOutputStream dataOutputStream = new DataOutputStream(socket.getOutputStream());
                                dataOutputStream.writeUTF(m.toString());
                                dataOutputStream.flush();

                                DataInputStream dataInputStream = new DataInputStream(socket.getInputStream());
                                String result = dataInputStream.readUTF();
                                dos.writeUTF(result);
                                dos.flush();
                            }
                            lock.unlock();
                        }
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }
            }

        }

        @Override
        protected Void doInBackground(ServerSocket... serverSockets) {

            ServerSocket serverSocket = serverSockets[0];
            try {
                while (true) {
                    Socket socket = serverSocket.accept();
                    new Thread(new ServerThread(socket)).start();
                }

            } catch (Exception e) {
                e.printStackTrace();
            }
            return null;
        }
    }

    private class Client extends AsyncTask<Message, Void, Void> {
        @Override
        protected Void doInBackground(Message... messages) {
            Message message = messages[0];
            try {
                if (message.status.equals("JOIN")) {
                    Socket socket = addOrGetSocket(portsToSend[0]);

                    DataOutputStream dos = new DataOutputStream(socket.getOutputStream());
                    DataInputStream dis = new DataInputStream(socket.getInputStream());

                    dos.writeUTF(message.toString());
                    dos.flush();

                    // Reply - This node's hash; Predecessor; Successor;
                    String reply = dis.readUTF();

                    String[] replies = reply.split("\\;");

                    myHash = replies[0];

                    prevId = Integer.parseInt(replies[1]);
                    succId = Integer.parseInt(replies[2]);

                    Log.d("Predecessor", prevId + "");
                    Log.d("Successor", succId + "");

                    message.status = "UPDATE_SUCCESSOR";
                    Log.d("Updating successor", message.toString());
                    Socket prevSocket = addOrGetSocket(prevId * 2);
                    DataOutputStream dataOutputStream = new DataOutputStream(prevSocket.getOutputStream());
                    dataOutputStream.writeUTF(message.toString());
                    dataOutputStream.flush();

                    message.status = "UPDATE_PREDECESSOR";
                    Log.d("Updating predecessor", message.toString());
                    Socket succSocket = addOrGetSocket(succId * 2);
                    dataOutputStream = new DataOutputStream(succSocket.getOutputStream());
                    dataOutputStream.writeUTF(message.toString());
                    dataOutputStream.flush();
                } else if (message.status.equals("INSERT")) {
                    Socket socket = addOrGetSocket(succId * 2);
                    DataOutputStream dos = new DataOutputStream(socket.getOutputStream());
                    dos.writeUTF(message.toString());
                    dos.flush();
                }

            } catch (Exception e) {
                e.printStackTrace();
            }

            return null;
        }
    }
}
