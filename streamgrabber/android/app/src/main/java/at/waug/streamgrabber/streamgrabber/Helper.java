package at.waug.streamgrabber.streamgrabber;

/**
 * Created by philip on 1/19/15.
 */
public class Helper {

    public static String app_name = "";

    public String instance_string = "";

    private static Helper instance_ = null;

    public static Helper getInstance(){
        if (instance_ == null)
            instance_ = new Helper();

        return instance_;
    }

}
