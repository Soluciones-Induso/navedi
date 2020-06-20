package qz.ui;

import com.github.zafarkhaja.semver.Version;
import org.eclipse.jetty.server.Server;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import qz.common.AboutInfo;
import qz.common.Constants;
import qz.ui.component.EmLabel;
import qz.ui.component.IconCache;
import qz.ui.component.LinkLabel;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.font.TextAttribute;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;

/**
 * Created by Tres on 2/26/2015.
 * Displays a basic about dialog
 */
public class AboutDialog extends BasicDialog implements Themeable {

    private static final Logger log = LoggerFactory.getLogger(AboutDialog.class);

    private Server server;

    private boolean limitedDisplay;

    private JLabel lblUpdate;
    private JButton updateButton;

    // Use <html> allows word wrapping on a standard JLabel
    class TextWrapLabel extends JLabel {
        TextWrapLabel(String text) {
            super("<html>" + text + "</html>");
        }
    }

    public AboutDialog(JMenuItem menuItem, IconCache iconCache) {
        super(menuItem, iconCache);

        //noinspection ConstantConditions - white label support
        limitedDisplay = Constants.VERSION_CHECK_URL.isEmpty();
    }

    public void setServer(Server server) {
        this.server = server;

        initComponents();
    }

    public void initComponents() {
        JLabel lblAbout = new EmLabel(Constants.ABOUT_TITLE, 3);

        JPanel infoPanel = new JPanel();
        infoPanel.setLayout(new BoxLayout(infoPanel, BoxLayout.Y_AXIS));

        LinkLabel linkLibrary = new LinkLabel("Información detallada sobre la librería");
        if(server.isRunning() && !server.isStopping()) {
            linkLibrary.setLinkLocation(String.format("%s://%s:%s", server.getURI().getScheme(), AboutInfo.getPreferredHostname(), server.getURI().getPort()));
        }
        Box versionBox = Box.createHorizontalBox();
        versionBox.setAlignmentX(Component.LEFT_ALIGNMENT);
        versionBox.add(new JLabel(String.format("%s (Java)", Constants.VERSION.toString())));


        JPanel aboutPanel = new JPanel(new FlowLayout(FlowLayout.CENTER));
        JLabel logo = new JLabel(getIcon(IconCache.Icon.LOGO_ICON));
        logo.setBorder(new EmptyBorder(0, 0, 0, limitedDisplay ? 0 : 20));
        aboutPanel.add(logo);

        if (!limitedDisplay) {
            LinkLabel linkNew = new LinkLabel("¿Qué hay de nuevo?");
            linkNew.setLinkLocation(Constants.VERSION_DOWNLOAD_URL);

            lblUpdate = new JLabel();
            updateButton = new JButton();
            updateButton.setVisible(false);
            updateButton.addActionListener(evt -> {
                try { Desktop.getDesktop().browse(new URL(Constants.ABOUT_DOWNLOAD_URL).toURI()); }
                catch(Exception e) { log.error("", e); }
            });
            checkForUpdate();
            versionBox.add(Box.createHorizontalStrut(12));
            versionBox.add(linkNew);

            infoPanel.add(lblAbout);
            infoPanel.add(Box.createVerticalGlue());
            infoPanel.add(versionBox);
            infoPanel.add(Box.createVerticalGlue());
            infoPanel.add(lblUpdate);
            infoPanel.add(updateButton);
            infoPanel.add(Box.createVerticalGlue());
            infoPanel.add(new TextWrapLabel(String.format("%s está escrito y soportado por %s.", Constants.ABOUT_TITLE, Constants.ABOUT_COMPANY)));
            infoPanel.add(Box.createVerticalGlue());
            infoPanel.add(new TextWrapLabel(String.format("Si está usando %s comercialmente, por favor contacte primero al publicador del sitio web para asuntos de soporte.", Constants.ABOUT_TITLE)));
            infoPanel.add(Box.createVerticalGlue());
            infoPanel.add(linkLibrary);
            infoPanel.setPreferredSize(logo.getPreferredSize());
        } else {
            LinkLabel linkLabel = new LinkLabel(Constants.ABOUT_URL);
            linkLabel.setLinkLocation(Constants.ABOUT_URL);

            infoPanel.add(Box.createVerticalGlue());
            infoPanel.add(lblAbout);
            infoPanel.add(versionBox);
            infoPanel.add(Box.createVerticalStrut(16));
            infoPanel.add(linkLabel);
            infoPanel.add(Box.createVerticalStrut(8));
            infoPanel.add(linkLibrary);
            infoPanel.add(Box.createVerticalGlue());
            infoPanel.add(Box.createHorizontalStrut(16));
        }

        aboutPanel.add(infoPanel);

        JPanel panel = new JPanel();
        panel.setLayout(new BoxLayout(panel, BoxLayout.PAGE_AXIS));
        panel.add(aboutPanel);
        panel.add(new JSeparator());

        if (!limitedDisplay) {
            LinkLabel lblLicensing = new LinkLabel("Información de la licencia", 0.9f, false);
            lblLicensing.setLinkLocation(Constants.ABOUT_LICENSING_URL);

            LinkLabel lblSupport = new LinkLabel("Información de soporte", 0.9f, false);
            lblSupport.setLinkLocation(Constants.ABOUT_SUPPORT_URL);

            LinkLabel lblPrivacy = new LinkLabel("Política de privacidad", 0.9f, false);
            lblPrivacy.setLinkLocation(Constants.ABOUT_PRIVACY_URL);

            JPanel supportPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 80, 10));
            supportPanel.add(lblLicensing);
            supportPanel.add(lblSupport);
            supportPanel.add(lblPrivacy);

            panel.add(supportPanel);
        }

        setContent(panel, true);
    }

    private void checkForUpdate() {
        Version latestVersion = AboutInfo.findLatestVersion();
        if (latestVersion.greaterThan(Constants.VERSION)) {
            lblUpdate.setText("Hay una actualización disponible:");

            updateButton.setText("Descargar " + latestVersion.toString());
            updateButton.setVisible(true);
        } else if (latestVersion.lessThan(Constants.VERSION)) {
            lblUpdate.setText("Estás en una versión beta.");

            updateButton.setText("Revertir a la versión estable " + latestVersion.toString());
            updateButton.setVisible(true);
        } else {
            lblUpdate.setText("Usted tiene la última versión.");

            updateButton.setVisible(false);
        }
    }


    @Override
    public void setVisible(boolean visible) {
        if (visible && !limitedDisplay) {
            checkForUpdate();
        }

        super.setVisible(visible);
    }


}
