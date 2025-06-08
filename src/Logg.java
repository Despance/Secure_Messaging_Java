import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.logging.FileHandler;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;

public class Logg {

    private static Logger logger;

    private static FileHandler fh = null;

    public static Logger getLogger() {

        if (logger == null) {

            logger = Logger.getLogger("MyLog");
            logger.setUseParentHandlers(false);

            SimpleDateFormat format = new SimpleDateFormat("M-d_HHmmss");
            try {
                fh = new FileHandler(
                        "logs/newlog-" + format.format(Calendar.getInstance().getTime()) + ".log");
            } catch (Exception e) {
                e.printStackTrace();
            }

            fh.setFormatter(new SimpleFormatter());
            logger.addHandler(fh);
        }
        return logger;

    }
}
