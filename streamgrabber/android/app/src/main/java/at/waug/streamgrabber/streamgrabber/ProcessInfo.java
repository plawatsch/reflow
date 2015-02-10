package at.waug.streamgrabber.streamgrabber;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileDescriptor;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.InetSocketAddress;
import java.net.Socket;

import java.net.SocketImpl;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.callbacks.XC_LoadPackage;

/**
 * Created by philip on 1/19/15.
 */
public class ProcessInfo {

    public static final int MSG_SHALL_MONITOR = 1;
    public static final int MSG_CONNECT = 2;
    public static final int MSG_DISCONNECT = 3;
    public static final int MSG_PLAIN_READ = 4;
    public static final int MSG_PLAIN_WRITE = 5;
    public static final int MSG_TLS_READ = 6;
    public static final int MSG_TLS_WRITE = 7;


    private static ProcessInfo instance_ = null;

    private Method fd_getint = null;
    private Method socket_get_fd = null;

    private DataExfiltration exfiltrator_thread = null;

    private int getFD(FileDescriptor fd){
        try {
            return (Integer)fd_getint.invoke(fd);
        } catch (IllegalAccessException e) {
            e.printStackTrace();
        } catch (InvocationTargetException e) {
            e.printStackTrace();
        }
        return -2;
    }

    private FileDescriptor getSocketFileDescriptor(SocketImpl s)
    {
        try {
            return (FileDescriptor)socket_get_fd.invoke(s);
        } catch (IllegalAccessException e) {
            e.printStackTrace();
        } catch (InvocationTargetException e) {
            e.printStackTrace();
        }
        return null;
    }
    private ProcessInfo(){
        try {
            fd_getint = FileDescriptor.class.getDeclaredMethod("getInt$");
            socket_get_fd = SocketImpl.class.getDeclaredMethod("getFileDescriptor");
            socket_get_fd.setAccessible(true); // it's protected, or rather it was protected :)


        } catch (NoSuchMethodException e) {
            e.printStackTrace();
        }
    }

    public static synchronized ProcessInfo getInstance(){
        if (instance_ == null)
            instance_ = new ProcessInfo();

        return instance_;
    }

    public synchronized void addPackageName(String name)
    {
        for (String n : package_names_)
        {
            if (n.equals(name))
                return;
        }
        if (!shall_monitor)
            have_been_instructed = false;

        package_names_.add(new String(name));
    }

    private HashMap<FileDescriptor, InetSocketAddress> intermediate_connections = new HashMap<FileDescriptor, InetSocketAddress>();

    public synchronized void handleConnectPre(FileDescriptor fd, InetSocketAddress addr){
//        XposedBridge.log("Connecting " + getFD(fd) + addr.toString());
//        intermediate_connections.put(fd, addr);

    }

    public synchronized void handleConnectPost(FileDescriptor fdo, InetSocketAddress addr){
        int fd = getFD(fdo);
        if (!known_connections_.containsKey(fd)) {
            known_connections_.put(fd, addr);
            sendMessage(MSG_CONNECT, fdo, null, 0, 0);
        }
    }

    public synchronized void handlePlainSocketClose(SocketImpl s){
        FileDescriptor fdo = getSocketFileDescriptor(s);
        int fd = getFD(fdo);
        if (known_connections_.containsKey(fd)) {
            sendMessage(MSG_DISCONNECT, fdo, null, 0, 0);
            known_connections_.remove(fd);
        }
        else
        {
          //  XposedBridge.log("Close for socket that we did not know anything about!");
        }
    }

    public synchronized void handleTLSWrite(FileDescriptor fd, byte[] b, int off, int len){
        if (known_connections_.containsKey(getFD(fd)))
            sendMessage(MSG_TLS_WRITE, fd, b, off, len);
    }

    public synchronized void handleTLSRead(FileDescriptor fd, byte[] b, int off, int len){
        if (known_connections_.containsKey(getFD(fd)))
            sendMessage(MSG_TLS_READ, fd, b, off, len);
    }

    public synchronized void handlePlainSocketWrite (SocketImpl s, byte[] b, int off, int len ) {
        if (known_connections_.containsKey(getFD(getSocketFileDescriptor(s))))
            sendMessage(MSG_PLAIN_WRITE, getSocketFileDescriptor(s), b, off, len);
    }

    public synchronized void handlePlainSocketRead (SocketImpl s, byte[] b, int off, int len ) {
        if (known_connections_.containsKey(getFD(getSocketFileDescriptor(s))))
            sendMessage(MSG_PLAIN_READ, getSocketFileDescriptor(s), b, off, len);
    }


    private synchronized void sendMessage(int msg_type, FileDescriptor fdo, byte[] b, int off, int len)
    {
        try {
            ByteArrayOutputStream buffer = new ByteArrayOutputStream();
            DataOutputStream out = new DataOutputStream(buffer);
            sendMessagePreamble(out, msg_type, fdo);
            if (b != null) {
                out.writeInt(len);
                if (len > 0) {
                    out.write(b, off, len);
                }
            }
            else
            {
                out.writeInt(0);
            }
            out.flush();
            Message m = new Message();
            m.buffer = buffer;
            if (exfiltrator_thread != null)
                exfiltrator_thread.queueData(m);
        }
        catch (Exception e)
        {
            XposedBridge.log("Exception in send msg " + msg_type + " error: " + e.toString());
        }
    }

    private synchronized void sendMessagePreamble(DataOutputStream out, int msg_type, FileDescriptor fdo) throws IOException {
            out.writeInt(msg_type);
            out.writeInt(android.os.Process.myPid());
            out.writeInt(android.os.Process.myTid());
            out.writeInt(android.os.Process.myUid());
            out.writeInt(getFD(fdo));
            writePackageNamesToStream(out);
            writeDestinationToStream(out, fdo);
    }


    public synchronized boolean doHijack(){
        return doHijack(true);
    }
    public synchronized boolean doHijack(boolean query_server){
        // prevent endless recursion due to us trying to figure out if we have to hook our
        // request for monitoring ....
        // been there, done that, had to boot to rescue image :(
        if (monitoring_request_running)
            return false;

        if (!have_been_instructed && query_server) {
            monitoring_request_running = true;
            try {
                Socket exfiltrator = new Socket("192.168.1.55", 13374);
                DataOutputStream out = new DataOutputStream(exfiltrator.getOutputStream());
                DataInputStream in = new DataInputStream(exfiltrator.getInputStream());

                out.writeInt(1); // one msg only
                out.writeInt(MSG_SHALL_MONITOR);
                out.writeInt(android.os.Process.myPid());
                out.writeInt(android.os.Process.myTid());
                out.writeInt(android.os.Process.myUid());
                out.writeInt(-2); // fake fd so we can parse all msgs the same way
                writePackageNamesToStream(out);
                out.writeInt(0); // fake dest so we can parse all msgs the same

                out.flush();

                int monitor = in.readInt();

                exfiltrator.close();

                have_been_instructed = true;
                if (monitor != 0) {
                    exfiltrator_thread = new DataExfiltration();
                    exfiltrator_thread.start();
                    shall_monitor = true;
                }
                else
                    shall_monitor = false;
                XposedBridge.log("Received monitoring instructions, monitor is " + shall_monitor);


            } catch (Exception e) {
                XposedBridge.log("Could not instruction about monitoring for this app, deactivating");
                XposedBridge.log("Error: " + e.toString() + " " + e.getStackTrace().toString());
                shall_monitor = false;
                have_been_instructed = false;
            }
            monitoring_request_running = false;
        }

        return shall_monitor;
    }

    private static boolean have_been_instructed = false;
    private static boolean monitoring_request_running = false; // this is to prevent us from endlessly recursing m(
    private static boolean shall_monitor = false;

    private ArrayList<String> package_names_ = new ArrayList<String>();

    private synchronized void writePackageNamesToStream(DataOutputStream out) throws IOException
    {
        out.writeInt(package_names_.size());
        for (int i = 0; i < package_names_.size(); ++i) {
            int l = package_names_.get(i).length();
            out.writeInt(l);
            out.writeBytes(package_names_.get(i));
        }
    }

    private synchronized void writeDestinationToStream(DataOutputStream out, FileDescriptor fd) throws IOException
    {
        InetSocketAddress addr = known_connections_.get(getFD(fd));
        String ret = "";
        if (addr != null)
            ret = addr.toString();

        out.writeInt(ret.length());
        if (ret.length() > 0)
            out.writeBytes(ret);
    }

    private HashMap<Integer, InetSocketAddress> known_connections_ = new HashMap<Integer, InetSocketAddress>();
}
