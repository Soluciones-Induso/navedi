package qz.auth;

import org.apache.commons.codec.binary.StringUtils;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.ssl.Base64;
import org.apache.commons.ssl.X509CertificateChainBuilder;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.jce.PrincipalUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import qz.common.Constants;
import qz.utils.ByteUtilities;
import qz.utils.FileUtilities;
import qz.utils.SystemUtilities;
import qz.ws.PrintSocketServer;

import javax.security.cert.CertificateParsingException;
import java.io.*;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.DateTimeException;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Properties;
import java.util.Vector;

/**
 * Created by Steven on 1/27/2015. Package: qz.auth Project: qz-print
 * Wrapper to store certificate objects from
 */
public class Certificate {

    private static final Logger log = LoggerFactory.getLogger(Certificate.class);

    public enum Algorithm {
        SHA1("SHA1withRSA"),
        SHA256("SHA256withRSA"),
        SHA512("SHA512withRSA");

        String name;

        Algorithm(String name) {
            this.name = name;
        }
    }

    public static Certificate trustedRootCert = null;
    public static final String[] saveFields = new String[] {"fingerprint", "commonName", "organization", "validFrom", "validTo", "valid"};

    // Valid date range allows UI to only show "Expired" text for valid certificates
    private static final Instant UNKNOWN_MIN = LocalDateTime.MIN.toInstant(ZoneOffset.UTC);
    private static final Instant UNKNOWN_MAX = LocalDateTime.MAX.toInstant(ZoneOffset.UTC);

    private static boolean overrideTrustedRootCert = false;

    private static DateTimeFormatter dateFormat = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
    private static DateTimeFormatter dateParse = DateTimeFormatter.ofPattern("uuuu-MM-dd['T'][ ]HH:mm:ss[.n]['Z']"); //allow parsing of both ISO and custom formatted dates

    private X509Certificate theCertificate;
    private String fingerprint;
    private String commonName;
    private String organization;
    private Instant validFrom;
    private Instant validTo;

    //used by review sites UI only
    private boolean expired = false;
    private boolean valid = true;


    //Pre-set certificate for use when missing
    public static final Certificate UNKNOWN;

    static {
        HashMap<String,String> map = new HashMap<>();
        map.put("fingerprint", "UNKNOWN REQUEST");
        map.put("commonName", "An anonymous request");
        map.put("organization", "Unknown");
        map.put("validFrom", UNKNOWN_MIN.toString());
        map.put("validTo", UNKNOWN_MAX.toString());
        map.put("valid", "false");
        UNKNOWN = Certificate.loadCertificate(map);
    }

    static {
        try {
            Security.addProvider(new BouncyCastleProvider());
            // No permitir certificados alternos
            // checkOverrideCertPath();

            if (trustedRootCert == null) {
                trustedRootCert = new Certificate(
                    "-----BEGIN CERTIFICATE-----\n" +
                    "MIIGEDCCA/igAwIBAgIJAJwgopdZP668MA0GCSqGSIb3DQEBCwUAMIGUMQswCQYD\n" +
                    "VQQGEwJDUjETMBEGA1UECAwKUHVudGFyZW5hczEaMBgGA1UECgwRU29sdWNpb25l\n" +
                    "cyBJbmR1c28xMDAuBgNVBAsMJ1NvbHVjaW9uZXMgSW5kdXNvIENlcnRpZmljYXRl\n" +
                    "IEF1dGhvcml0eTEiMCAGA1UEAwwZU29sdWNpb25lcyBJbmR1c28gUm9vdCBDQTAe\n" +
                    "Fw0xOTA2MDQyMjIzNDJaFw0zOTA1MzAyMjIzNDJaMIGUMQswCQYDVQQGEwJDUjET\n" +
                    "MBEGA1UECAwKUHVudGFyZW5hczEaMBgGA1UECgwRU29sdWNpb25lcyBJbmR1c28x\n" +
                    "MDAuBgNVBAsMJ1NvbHVjaW9uZXMgSW5kdXNvIENlcnRpZmljYXRlIEF1dGhvcml0\n" +
                    "eTEiMCAGA1UEAwwZU29sdWNpb25lcyBJbmR1c28gUm9vdCBDQTCCAiIwDQYJKoZI\n" +
                    "hvcNAQEBBQADggIPADCCAgoCggIBAMxR58agL4N8/NP24iwA550ort03vXAexBxf\n" +
                    "aRkhIowIBzMc5e+v1BvQGXI6tEKQ6S6YOZ7AhpBUMB2ClxgIcd1hvtf8xMz1U+uZ\n" +
                    "DNqQU/u7iTP063j591QL2EHPxS3mTpMEhPBi5O9oby/5xfJJxv4brDud60vyBo1C\n" +
                    "SZPPWT3h59L4/GRrKuDeZJfyu2y70juHkQBkQaTNZ7n9xkcBl8kiPnyVconnnq1X\n" +
                    "cpk3JryF1OkcZh39s6NFsxPIo18k1pUjwHNl0v6eBvNYCLbVqA5O/GGl3aKMgIGE\n" +
                    "0F7OMaabWXuSLldcZfX48dDBJQCOMYbrJnOsnWC0XZqGWIE8ltKyohhJglUkOxlu\n" +
                    "2TWrEENxWVs4m4g/6OCL+x9v7pd5IXTegUbSPMaC1OaGjDX1jAukT4oPMiiIw4TW\n" +
                    "zxvgZrympg+kuu+Ut9U5HMRlIFHnuce8/PVGbxTB6YPsx2CVV3Yj46Xis1PjLVPe\n" +
                    "CternG/OrdKbYqlYkW3XjtIDMaFMLKt61+Mfryh11KTobD7Dp+Np3tN99Z1EQfb6\n" +
                    "Y+CVObC+Nzozr2fghWM8i50B7CS6OQbT8MhHV7HBfNjbaHSGVaLYOqJws5qpBTa1\n" +
                    "az3LaB0E0kMn43jJt9XwafSJCA3zy25nwy8Y+Gia5pC+zbSs4k5rWoULYDLbRmZq\n" +
                    "9rdjuj/BAgMBAAGjYzBhMB0GA1UdDgQWBBQQKRVaFa0lvH382AS/YidOYMWWhzAf\n" +
                    "BgNVHSMEGDAWgBQQKRVaFa0lvH382AS/YidOYMWWhzAPBgNVHRMBAf8EBTADAQH/\n" +
                    "MA4GA1UdDwEB/wQEAwIBhjANBgkqhkiG9w0BAQsFAAOCAgEArqc+OsHXqUUooDhU\n" +
                    "aYPtcCGGjTOOcmD5SY4/tGvbV+//gKhX9D9d3l05SYIY7RlAm58IcvAnE4reONPZ\n" +
                    "xpw1qv5RNQHLKx6QAeqPzDmn94JnaAh4PhZqVdlum61CNAaAfWK+sL0iFpOliDmY\n" +
                    "0g0ybnTsr5OUolAN5iMbas+Gy2sNAnSJ//+cC4aoAEF+AwbmwjbB2ENTlupQPHCv\n" +
                    "kSrM95XaPsFNPmjsWtY74CfH9JH4cPPV71bgfWR47hUf0FXF1S/dLA9fuzLaYS+b\n" +
                    "5VwnZqcJ2lYAgJ8J3YwnvoJqZszmJwTFROGB5n034QHs43GjV3ViYUsVfSf8SKdr\n" +
                    "5FdGkJuUoVjWmZG/OU9/aF4oH1nGpMpqVsJ6nIRlqoFsFFDdm7kamNLnNfJ/AhgQ\n" +
                    "7fAV+56q860O/nG9vfndZqMbFyjSReJPRQt/tAMyigN/dKR/gOy880OxEiAFGxL8\n" +
                    "VV4Q26J2PAjJ6Nqf/tXdZ34DMMLSqUF48/axYdtNx9yG9Lwb5wfucRFnHJdOcLsq\n" +
                    "P9Yoq6ElItezma1VsQ3XdGLrAFmkfD/i2W0l9/eBrlwJ1WcT1CaSvjzqrutLBmtH\n" +
                    "FJQdG5R6ijuBynS24zLGuw3CreTwZp3mAhB8LMBXSZIF6CaY90nEfvXD/mQqD5Kq\n" +
                    "CofHmMemvWibVJrNh+62l05R+Gg=n" +
                    "-----END CERTIFICATE-----");

                CRL.getInstance();  // Fetch the CRL
            }

            trustedRootCert.valid = true;
            log.debug("Using trusted root certificate: CN={}, O={} ({})",
                      trustedRootCert.getCommonName(), trustedRootCert.getOrganization(), trustedRootCert.getFingerprint());
        }
        catch(CertificateParsingException e) {
            e.printStackTrace();
        }
    }


    private static void checkOverrideCertPath() {
        // Priority: Check environmental variable
        String override = System.getProperty("trustedRootCert");
        String helpText = "System property \"trustedRootCert\"";
        if(setOverrideCert(override,  helpText, false)) {
            return;
        }

        // Preferred: Look for file called "override.crt" in installation directory
        override = FileUtilities.getParentDirectory(SystemUtilities.getJarPath()) + File.separator + Constants.OVERRIDE_CERT;
        helpText = String.format("Override cert \"%s\"", Constants.OVERRIDE_CERT);
        if(setOverrideCert(override, helpText, true)) {
            return;
        }

        // Fallback (deprecated): Parse "authcert.override" from qz-tray.properties
        // Entry was created by 2.0 build system, removed in newer versions in favor of the hard-coded filename
        Properties props = PrintSocketServer.getTrayProperties();
        helpText = "Properties file entry \"authcert.override\"";
        if(props != null && setOverrideCert(props.getProperty("authcert.override"), helpText, false)) {
            log.warn("Deprecation warning: \"authcert.override\" is no longer supported.\n" +
                             "{} will look for the system property \"trustedRootCert\", or look for" +
                             "a file called {} in the working path.", Constants.ABOUT_TITLE, Constants.OVERRIDE_CERT);
            return;
        }
    }

    private static boolean setOverrideCert(String path, String helpText, boolean quiet) {
        if(path != null && !path.trim().isEmpty()) {
            if (new File(path).exists()) {
                try {
                    log.error("Using override cert: {}", path);
                    trustedRootCert = new Certificate(FileUtilities.readLocalFile(path));
                    overrideTrustedRootCert = true;
                    return true;
                }
                catch(Exception e) {
                    log.error("Error loading override cert: {}", path, e);
                }
            } else if(!quiet) {
                log.warn("{} \"{}\" was provided, but could not be found, skipping.", helpText, path);
            }
        }
        return false;
    }

    /** Decodes a certificate and intermediate certificate from the given string */
    @SuppressWarnings("deprecation")
    public Certificate(String in) throws CertificateParsingException {
        try {
            //Setup X.509
            CertificateFactory cf = CertificateFactory.getInstance("X.509");

            //Strip beginning and end
            String[] split = in.split("--START INTERMEDIATE CERT--");
            byte[] serverCertificate = Base64.decodeBase64(split[0].replaceAll(X509Constants.BEGIN_CERT, "").replaceAll(X509Constants.END_CERT, ""));

            X509Certificate theIntermediateCertificate;
            if (split.length == 2) {
                byte[] intermediateCertificate = Base64.decodeBase64(split[1].replaceAll(X509Constants.BEGIN_CERT, "").replaceAll(X509Constants.END_CERT, ""));
                theIntermediateCertificate = (X509Certificate)cf.generateCertificate(new ByteArrayInputStream(intermediateCertificate));
            } else {
                theIntermediateCertificate = null; //Self-signed
            }

            //Generate cert
            theCertificate = (X509Certificate)cf.generateCertificate(new ByteArrayInputStream(serverCertificate));
            commonName = String.valueOf(PrincipalUtil.getSubjectX509Principal(theCertificate).getValues(X509Name.CN).get(0));
            fingerprint = makeThumbPrint(theCertificate);
            organization = String.valueOf(PrincipalUtil.getSubjectX509Principal(theCertificate).getValues(X509Name.O).get(0));
            validFrom = theCertificate.getNotBefore().toInstant();
            validTo = theCertificate.getNotAfter().toInstant();

            if (trustedRootCert != null) {
                HashSet<X509Certificate> chain = new HashSet<>();
                try {
                    chain.add(trustedRootCert.theCertificate);
                    if (theIntermediateCertificate != null) { chain.add(theIntermediateCertificate); }
                    X509Certificate[] x509Certificates = X509CertificateChainBuilder.buildPath(theCertificate, chain);

                    for(X509Certificate x509Certificate : x509Certificates) {
                        if (x509Certificate.equals(trustedRootCert.theCertificate)) {
                            Instant now = Instant.now();
                            expired = validFrom.isAfter(now) || validTo.isBefore(now);
                            if (expired) {
                                valid = false;
                            }
                        }
                    }
                }
                catch(Exception e) {
                    log.error("Problem building certificate chain", e);
                }
            }

            try {
                readRenewalInfo();
            }
            catch(Exception e) {
                log.error("Error reading certificate renewal info", e);
            }

            // Only do CRL checks on QZ-issued certificates
            if (trustedRootCert != null && !overrideTrustedRootCert) {
                CRL qzCrl = CRL.getInstance();
                if (qzCrl.isLoaded()) {
                    if (qzCrl.isRevoked(getFingerprint()) || theIntermediateCertificate == null || qzCrl.isRevoked(makeThumbPrint(theIntermediateCertificate))) {
                        log.warn("Problem verifying certificate with CRL");
                        valid = false;
                    }
                } else {
                    //Assume nothing is revoked, because we can't get the CRL
                    log.warn("Failed to retrieve QZ CRL, skipping CRL check");
                }
            }
        }
        catch(Exception e) {
            CertificateParsingException certificateParsingException = new CertificateParsingException();
            certificateParsingException.initCause(e);
            throw certificateParsingException;
        }
    }

    private void readRenewalInfo() throws Exception {
        // "id-at-description" = "2.5.4.13"
        Vector values = PrincipalUtil.getSubjectX509Principal(theCertificate).getValues(new ASN1ObjectIdentifier("2.5.4.13"));
        if (values.isEmpty()) {
            return;
        }
        String renewalInfo = String.valueOf(values.get(0));

        String renewalPrefix = "renewal-of-";
        if (!renewalInfo.startsWith(renewalPrefix)) {
            throw new CertificateParsingException("Malformed renewal info");
        }
        String previousFingerprint = renewalInfo.substring(renewalPrefix.length());
        if (previousFingerprint.length() != 40) {
            throw new CertificateParsingException("Malformed renewal fingerprint");
        }

        // Add this certificate to the whitelist if the previous certificate was whitelisted
        File allowed = FileUtilities.getFile(Constants.ALLOW_FILE, true);
        if (existsInAnyFile(previousFingerprint, allowed)) {
            FileUtilities.printLineToFile(Constants.ALLOW_FILE, data());
        }
    }

    private Certificate() {}


    /**
     * Used to rebuild a certificate for the 'Saved Sites' screen without having to decrypt the certificates again
     */
    public static Certificate loadCertificate(HashMap<String,String> data) {
        Certificate cert = new Certificate();

        cert.fingerprint = data.get("fingerprint");
        cert.commonName = data.get("commonName");
        cert.organization = data.get("organization");

        try {
            cert.validFrom = Instant.from(LocalDateTime.from(dateParse.parse(data.get("validFrom"))).atZone(ZoneOffset.UTC));
            cert.validTo = Instant.from(LocalDateTime.from(dateParse.parse(data.get("validTo"))).atZone(ZoneOffset.UTC));
        }
        catch(DateTimeException e) {
            cert.validFrom = UNKNOWN_MIN;
            cert.validTo = UNKNOWN_MAX;

            log.error("Unable to parse certificate date", e);
        }

        cert.valid = Boolean.parseBoolean(data.get("valid"));

        return cert;
    }

    /**
     * Checks given signature for given data against this certificate,
     * ensuring it is properly signed
     *
     * @param signature the signature appended to the data, base64 encoded
     * @param data      the data to check
     * @return true if signature valid, false if not
     */
    public boolean isSignatureValid(Algorithm algorithm, String signature, String data) {
        if (!signature.isEmpty()) {
            //On errors, assume failure.
            try {
                Signature verifier = Signature.getInstance(algorithm.name);
                verifier.initVerify(theCertificate.getPublicKey());
                verifier.update(StringUtils.getBytesUtf8(DigestUtils.sha256Hex(data)));

                return verifier.verify(Base64.decodeBase64(signature));
            }
            catch(GeneralSecurityException e) {
                log.error("Unable to verify signature", e);
            }
        }

        return false;
    }

    /** Checks if the certificate has been added to the local trusted store */
    public boolean isSaved() {
        File allowed = FileUtilities.getFile(Constants.ALLOW_FILE, true);
        File allowedShared = FileUtilities.getFile(Constants.ALLOW_FILE, false);
        return existsInAnyFile(getFingerprint(), allowedShared, allowed);
    }

    /** Checks if the certificate has been added to the local blocked store */
    public boolean isBlocked() {
        File blocks = FileUtilities.getFile(Constants.BLOCK_FILE, true);
        File blocksShared = FileUtilities.getFile(Constants.BLOCK_FILE, false);
        return existsInAnyFile(getFingerprint(), blocksShared, blocks);
    }

    private static boolean existsInAnyFile(String fingerprint, File... files) {
        for(File file : files) {
            if (file == null) { continue; }

            try(BufferedReader br = new BufferedReader(new FileReader(file))) {
                String line;
                while((line = br.readLine()) != null) {
                    if (line.contains("\t")) {
                        String print = line.substring(0, line.indexOf("\t"));
                        if (print.equals(fingerprint)) {
                            return true;
                        }
                    }
                }
            }
            catch(IOException e) {
                e.printStackTrace();
            }
        }

        return false;
    }


    public String getFingerprint() {
        return fingerprint;
    }

    public String getCommonName() {
        return commonName;
    }

    public String getOrganization() {
        return organization;
    }

    public String getValidFrom() {
        if (validFrom.isAfter(UNKNOWN_MIN)) {
            return dateFormat.format(validFrom.atZone(ZoneOffset.UTC));
        } else {
            return "Not Provided";
        }
    }

    public String getValidTo() {
        if (validTo.isBefore(UNKNOWN_MAX)) {
            return dateFormat.format(validTo.atZone(ZoneOffset.UTC));
        } else {
            return "Not Provided";
        }
    }

    public Instant getValidFromDate() {
        return validFrom;
    }

    public Instant getValidToDate() {
        return validTo;
    }

    /**
     * Validates certificate against embedded cert.
     */
    public boolean isTrusted() {
        return isValid() && !isExpired();
    }

    public boolean isValid() {
        return valid;
    }

    public boolean isExpired() {
        return expired;
    }


    public static String makeThumbPrint(X509Certificate cert) throws NoSuchAlgorithmException, CertificateEncodingException {
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        md.update(cert.getEncoded());
        return ByteUtilities.bytesToHex(md.digest(), false);
    }

    public String data() {
        return getFingerprint() + "\t" +
                getCommonName() + "\t" +
                getOrganization() + "\t" +
                getValidFrom() + "\t" +
                getValidTo() + "\t" +
                isTrusted();
    }

    @Override
    public String toString() {
        return getOrganization() + " (" + getCommonName() + ")";
    }

    @Override
    public boolean equals(Object obj) {
        if (obj instanceof Certificate) {
            return ((Certificate)obj).data().equals(data());
        }
        return super.equals(obj);
    }
}
