package qz.common;

import com.github.zafarkhaja.semver.Version;
import qz.utils.SystemUtilities;

import java.awt.*;

/**
 * Created by robert on 7/9/2014.
 */
public class Constants {
    public static final String HEXES = "0123456789ABCDEF";
    public static final char[] HEXES_ARRAY = HEXES.toCharArray();
    public static final int BYTE_BUFFER_SIZE = 8192;
    public static final Version VERSION = Version.valueOf("2.1.1");
    public static final Version JAVA_VERSION = SystemUtilities.getJavaVersion();
    public static final String JAVA_VENDOR = System.getProperty("java.vendor");

    /* QZ-Tray Constants */
    public static final String BLOCK_FILE = "blocked";
    public static final String ALLOW_FILE = "allowed";
    public static final String TEMP_FILE = "temp";
    public static final String LOG_FILE = "debug";
    public static final String PROPS_FILE = "navedi"; // .properties extension is assumed
    public static final String PREFS_FILE = "prefs"; // .properties extension is assumed
    public static final String[] PERSIST_PROPS = { "file.whitelist" };
    public static final String AUTOSTART_FILE = ".autostart";
    public static final String DATA_DIR = "navedi";
    public static final int LOG_SIZE = 524288;
    public static final int LOG_ROTATIONS = 5;

    public static final int BORDER_PADDING = 10;

    public static final String ABOUT_TITLE = "Navedi";
    public static final String ABOUT_EMAIL = "soporte@contica.app";
    public static final String ABOUT_URL = "https://solucionesinduso.com/navedi";
    public static final String ABOUT_COMPANY = "Soluciones Induso";
    public static final String ABOUT_CITY = "San Vito";
    public static final String ABOUT_STATE = "Puntarenas";
    public static final String ABOUT_COUNTRY = "Costa Rica";

    public static final String ABOUT_LICENSING_URL = Constants.ABOUT_URL + "/licensing";
    public static final String ABOUT_SUPPORT_URL = Constants.ABOUT_URL + "/support";
    public static final String ABOUT_PRIVACY_URL = Constants.ABOUT_URL + "/privacy";
    public static final String ABOUT_DOWNLOAD_URL = Constants.ABOUT_URL + "/download";

    public static final String VERSION_CHECK_URL = "https://api.github.com/repos/Soluciones-Induso/navedi/releases";
    public static final String VERSION_DOWNLOAD_URL = "https://github.com/Soluciones-Induso/navedi/releases";
    public static final boolean ENABLE_DIAGNOSTICS = true; // Diagnostics menu (logs, etc)

    public static final String TRUSTED_CERT = String.format("Verificado por %s", Constants.ABOUT_COMPANY);
    public static final String UNTRUSTED_CERT = "Sitio web sin confianza";
    public static final String NO_TRUST = "No se puede verificar si es de confianza";

    public static final String PROBE_REQUEST = "getProgramName";
    public static final String PROBE_RESPONSE = ABOUT_TITLE;

    public static final String PREFS_NOTIFICATIONS = "tray.notifications";
    public static final String PREFS_HEADLESS = "tray.headless";
    public static final String PREFS_MONOCLE = "tray.monocle";

    public static final String WHITE_LIST = "Se le otorgó a \"%s\" acceso permanente a los recursos locales";
    public static final String BLACK_LIST = "Se le denegó permanentemente a \"%s\" el acceso a los recursos locales";

    public static final String WHITE_SITES = "Sitios con acceso permitido permanentemente";
    public static final String BLACK_SITES = "Sitios con acceso denegado permanentemente";

    public static final String ALLOWED = "Permitido";
    public static final String BLOCKED = "Denegado";

    public static final String OVERRIDE_CERT = "override.crt";
    public static final String WHITELIST_CERT_DIR = "whitelist";

    public static final long VALID_SIGNING_PERIOD = 15 * 60 * 1000; //millis
    public static final int EXPIRY_WARN = 30;   // days
    public static final Color WARNING_COLOR_LITE = Color.RED;
    public static final Color TRUSTED_COLOR_LITE = Color.BLUE;
    public static final Color WARNING_COLOR_DARK = Color.decode("#EB6261");
    public static final Color TRUSTED_COLOR_DARK = Color.decode("#589DF6");
    public static Color WARNING_COLOR = WARNING_COLOR_LITE;
    public static Color TRUSTED_COLOR = TRUSTED_COLOR_LITE;

    public static boolean MASK_TRAY_SUPPORTED = true;

    public static final long MEMORY_PER_PRINT = 512; //MB

    public static final String RAW_PRINT = ABOUT_TITLE + " Raw Print";
    public static final String IMAGE_PRINT = ABOUT_TITLE + " Pixel Print";
    public static final String PDF_PRINT = ABOUT_TITLE + " PDF Print";
    public static final String HTML_PRINT = ABOUT_TITLE + " HTML Print";

    public static final Integer[] WSS_PORTS = {8181, 8282, 8383, 8484};
    public static final Integer[] WS_PORTS = {8182, 8283, 8384, 8485};
    public static final Integer[] CUPS_RSS_PORTS = {8586, 8687, 8788, 8889};
}
