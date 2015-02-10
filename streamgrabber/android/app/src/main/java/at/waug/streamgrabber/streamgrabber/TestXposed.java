/**
 * Created by philip on 12/14/14.
 */

package at.waug.streamgrabber.streamgrabber;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.callbacks.XC_LoadPackage.LoadPackageParam;

import java.io.DataOutputStream;
import java.io.FileDescriptor;
import java.net.Socket;
import java.net.SocketImpl;
import java.net.SocketAddress;
import java.net.InetSocketAddress;
import java.io.PrintWriter;
import java.io.OutputStream;
import javax.net.ssl.SSLSocket;
import static de.robv.android.xposed.XposedHelpers.findClass;
import static de.robv.android.xposed.XposedHelpers.findAndHookMethod;
import android.os.ParcelFileDescriptor;

import org.apache.http.conn.scheme.PlainSocketFactory;

import de.robv.android.xposed.XC_MethodHook;

public class TestXposed implements IXposedHookLoadPackage {


    static boolean already_hooked = false;

    public void handleLoadPackage(final LoadPackageParam lpparam) throws Throwable {

        ProcessInfo info = ProcessInfo.getInstance();
        info.addPackageName(lpparam.packageName);

        if (!already_hooked)//lpparam.packageName.equals("de.heise.android.ct.magazin"))
        {
            XposedBridge.log("Hooking " + lpparam.packageName + " already done: " + already_hooked);

            already_hooked = true;


            try {

                final Class<?> socket = findClass("java.net.Socket", lpparam.classLoader);
                XposedBridge.hookAllMethods(socket, "connect", new XC_MethodHook() {

                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {

                        ProcessInfo info = ProcessInfo.getInstance();
                        if (!info.doHijack())
                            return;

                        Object arg = param.args[0];
                        if (arg == null)
                            return;

                        InetSocketAddress addr = (InetSocketAddress) arg;

                        if (!addr.getAddress().equals("192.168.1.55"))
                        {
                            ParcelFileDescriptor pfd = ParcelFileDescriptor.fromSocket((Socket)param.thisObject);
                            FileDescriptor fd = pfd.getFileDescriptor();
                            info.handleConnectPre(fd, addr);
                        }

                    }

                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {

                        ProcessInfo info = ProcessInfo.getInstance();
                        if (!info.doHijack())
                            return;

                        Object arg = param.args[0];
                        if (arg == null)
                            return;

                        InetSocketAddress addr = (InetSocketAddress) arg;
                        if (addr == null)
                        {
                            XposedBridge.log("NOT AN SOCKET ADDR: " + arg.getClass().toString());
                            return;
                        }
                        if (!addr.getAddress().equals("192.168.1.55"))
                        {
                            ParcelFileDescriptor pfd = ParcelFileDescriptor.fromSocket((Socket)param.thisObject);
                            FileDescriptor fd = pfd.getFileDescriptor();
                            info.handleConnectPost(fd, addr);
                        }

                    }

                });
                //   XposedBridge.log("Hooked ssl_read stream");
            }
            catch (Exception e)
            {
                XposedBridge.log("failed to ssl_read output stream");
            }



            try {

                final Class<?> socket = findClass("java.net.PlainSocketImpl", lpparam.classLoader);
                XposedBridge.hookAllMethods(socket, "write", new XC_MethodHook() {

                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {

                        ProcessInfo info = ProcessInfo.getInstance();
                        if (!info.doHijack())
                            return;

                        if (param.hasThrowable())
                        {
                            return;
                        }

                        if (param.args.length <= 2)
                        {
                            return;
                        }

                        byte[] b = (byte[]) param.args[0];
                        int off = (Integer) param.args[1];
                        int len = (Integer) param.args[2];


                        info.handlePlainSocketWrite((SocketImpl)param.thisObject, b, off, len);

                    }
                });

                XposedBridge.hookAllMethods(socket, "read", new XC_MethodHook() {

                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {

                        ProcessInfo info = ProcessInfo.getInstance();
                        if (!info.doHijack())
                            return;

                        if (param.hasThrowable())
                        {
                            return;
                        }

                        if (param.args.length <= 2)
                        {
                            return;
                        }

                        Object result = param.getResult();

                        if (result == null)
                        {
                            XposedBridge.log("plain read, result is null!!");
                            return;
                        }


                        int r = (int) param.getResult();
                        byte[] b = (byte[]) param.args[0];
                        int off = (Integer) param.args[1];
                        int len = (Integer) param.args[2];


                        info.handlePlainSocketRead((SocketImpl)param.thisObject, b, off, r);

                    }
                });

                XposedBridge.hookAllMethods(socket, "close", new XC_MethodHook() {

                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {

                        ProcessInfo info = ProcessInfo.getInstance();

                        // a close will also happen from the socket that we used to figure out
                        // if we have to monitor
                        // this is really bad, since we can deadlock here if we are not REALLY careful :(
                        if (!info.doHijack(false))
                            return;

                        info.handlePlainSocketClose((SocketImpl)param.thisObject);

                    }
                });

            }
            catch (Exception e)
            {
                XposedBridge.log("failed to plain write");
            }


            try {

                final Class<?> nativecrypto = findClass("com.android.org.conscrypt.NativeCrypto", lpparam.classLoader);
                XposedBridge.hookAllMethods(nativecrypto, "SSL_read", new XC_MethodHook() {

                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {

                        ProcessInfo info = ProcessInfo.getInstance();
                        if (!info.doHijack())
                            return;

                        if (param.hasThrowable())
                        {
                           // XposedBridge.log("SSLREAD, seems that method threw!!");
                            return;
                        }

                        Object result = param.getResult();

                        if (result == null)
                        {
                            //XposedBridge.log("SSLREAD, result is null!!");
                            return;
                        }


                        int r = (int) param.getResult();

                        FileDescriptor fd = (FileDescriptor) param.args[1];
                        byte[] b = (byte[]) param.args[3];
                        int off = (Integer) param.args[4];

                        info.handleTLSRead(fd, b, off, r);
                    }



                });
             //   XposedBridge.log("Hooked ssl_read stream");





            }
            catch (Exception e)
            {
                XposedBridge.log("failed to ssl_read output stream");
            }

            try {

//                public static native void SSL_write(long sslNativePointer,
//                FileDescriptor fd,
//                SSLHandshakeCallbacks shc,
//                byte[] b, int off, int len, int writeTimeoutMillis)
//                throws IOException;



                final Class<?> nativecrypto = findClass("com.android.org.conscrypt.NativeCrypto", lpparam.classLoader);
                XposedBridge.hookAllMethods(nativecrypto, "SSL_write", new XC_MethodHook() {

                    @Override
                    protected void afterHookedMethod(MethodHookParam param) throws Throwable {

                        ProcessInfo info = ProcessInfo.getInstance();
                        if (!info.doHijack())
                            return;

                        if (param.hasThrowable())
                        {
                            return;
                        }

                        FileDescriptor fd = (FileDescriptor) param.args[1];
                        byte[] b = (byte[]) param.args[3];
                        int off = (Integer) param.args[4];
                        int len = (Integer) param.args[5];

                        info.handleTLSWrite(fd, b, off, len);

                    }



                });
           //     XposedBridge.log("Hooked ssl_write stream");


//                public static native void SSL_write(long sslNativePointer,
//                FileDescriptor fd,
//                SSLHandshakeCallbacks shc,
//                byte[] b, int off, int len, int writeTimeoutMillis)
//                throws IOException;



            }
            catch (Exception e)
            {
                XposedBridge.log("failed to ssl_write output stream");
            }







            try {

                // org.conscrypt.OpenSSLSocketImpl
                //public void setNpnProtocols(byte[] npnProtocols) {

                final Class<?> nativecrypto = findClass("com.android.org.conscrypt.OpenSSLSocketImpl", lpparam.classLoader);
                XposedBridge.hookAllMethods(nativecrypto, "setNpnProtocols", new XC_MethodHook() {
                    @Override
                    protected void beforeHookedMethod(MethodHookParam param) throws Throwable {

                        if (!ProcessInfo.getInstance().doHijack())
                            return;

                        Object protos_o = param.args[0];

                        if (protos_o == null)
                        {
                            return;
                        }

                        byte []protos = (byte[]) protos_o;

                        final byte[] PATCHED_NPN_PROTOCOLS = new byte[] {
                                8, 'h', 't', 't', 'p', '/', '1', '.', '1' };

                        param.args[0] = PATCHED_NPN_PROTOCOLS;
                    }
                });


            }
            catch (Exception e)
            {
                XposedBridge.log("failed to setnpn output stream");
            }














        }

    }
}