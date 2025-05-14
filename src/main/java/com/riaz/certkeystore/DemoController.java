package com.riaz.certkeystore;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.beans.factory.annotation.Value;

import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.net.ssl.SSLContext;

@RestController
public class DemoController {

    @Value("${server.ssl.key-store:Not configured}")
    private String keyStorePath;
    
    @Value("${server.ssl.key-store-password:changeit}")
    private String keyStorePassword;

    @GetMapping("/")
    public Map<String, Object> home() {
        Map<String, Object> response = new HashMap<>();
        response.put("message", "Hello from cert-manager CSI Driver Demo!");
        response.put("status", "Running");
        return response;
    }

    @GetMapping("/certificate-info")
    public Map<String, Object> certificateInfo() {
        Map<String, Object> certInfo = new HashMap<>();
        certInfo.put("keyStorePath", keyStorePath);
        
        try {
            // Load the keystore
            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            try (FileInputStream fis = new FileInputStream(keyStorePath)) {
                keyStore.load(fis, keyStorePassword.toCharArray());
            }
            
            // Get all aliases and certificates
            Map<String, Map<String, Object>> certificates = new HashMap<>();
            Enumeration<String> aliases = keyStore.aliases();
            
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                Certificate cert = keyStore.getCertificate(alias);
                
                if (cert instanceof X509Certificate) {
                    X509Certificate x509Cert = (X509Certificate) cert;
                    Map<String, Object> certDetails = new HashMap<>();
                    
                    // Basic information
                    certDetails.put("subject", x509Cert.getSubjectX500Principal().getName());
                    certDetails.put("issuer", x509Cert.getIssuerX500Principal().getName());
                    certDetails.put("serialNumber", x509Cert.getSerialNumber().toString(16));
                    certDetails.put("validFrom", x509Cert.getNotBefore().toString());
                    certDetails.put("validUntil", x509Cert.getNotAfter().toString());
                    certDetails.put("version", x509Cert.getVersion());
                    certDetails.put("signatureAlgorithm", x509Cert.getSigAlgName());
                    
                    // Public key info
                    PublicKey publicKey = x509Cert.getPublicKey();
                    certDetails.put("publicKeyAlgorithm", publicKey.getAlgorithm());
                    certDetails.put("publicKeyFormat", publicKey.getFormat());
                    
                    // Extensions
                    Set<String> criticalExtensions = x509Cert.getCriticalExtensionOIDs();
                    Set<String> nonCriticalExtensions = x509Cert.getNonCriticalExtensionOIDs();
                    
                    if (criticalExtensions != null) {
                        Map<String, String> criticalExts = new HashMap<>();
                        for (String oid : criticalExtensions) {
                            criticalExts.put(oid, getExtensionDescription(oid, x509Cert));
                        }
                        certDetails.put("criticalExtensions", criticalExts);
                    }
                    
                    if (nonCriticalExtensions != null) {
                        Map<String, String> nonCriticalExts = new HashMap<>();
                        for (String oid : nonCriticalExtensions) {
                            nonCriticalExts.put(oid, getExtensionDescription(oid, x509Cert));
                        }
                        certDetails.put("nonCriticalExtensions", nonCriticalExts);
                    }
                    
                    // Subject Alternative Names (SANs)
                    try {
                        Collection<List<?>> subjectAltNames = x509Cert.getSubjectAlternativeNames();
                        if (subjectAltNames != null) {
                            List<String> sans = new ArrayList<>();
                            for (List<?> san : subjectAltNames) {
                                Integer type = (Integer) san.get(0);
                                String value = (String) san.get(1);
                                sans.add(getGeneralNameTypeString(type) + ": " + value);
                            }
                            certDetails.put("subjectAlternativeNames", sans);
                        }
                    } catch (CertificateParsingException e) {
                        certDetails.put("subjectAlternativeNamesError", e.getMessage());
                    }
                    
                    // Fingerprints
                    try {
                        java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
                        byte[] der = x509Cert.getEncoded();
                        md.update(der);
                        byte[] digest = md.digest();
                        certDetails.put("sha256Fingerprint", bytesToHex(digest));
                        
                        md = java.security.MessageDigest.getInstance("SHA-1");
                        md.update(der);
                        digest = md.digest();
                        certDetails.put("sha1Fingerprint", bytesToHex(digest));
                    } catch (Exception e) {
                        certDetails.put("fingerprintError", e.getMessage());
                    }
                    
                    certificates.put(alias, certDetails);
                }
            }
            
            certInfo.put("certificates", certificates);
            
            // Get SSL context info
            SSLContext context = SSLContext.getDefault();
            certInfo.put("sslProvider", context.getProvider().getName());
            certInfo.put("sslProtocol", context.getProtocol());
            
        } catch (Exception e) {
            certInfo.put("error", e.getMessage());
            certInfo.put("stackTrace", Arrays.toString(e.getStackTrace()));
        }
        
        return certInfo;
    }

    // Helper method to get description for extensions
    private String getExtensionDescription(String oid, X509Certificate cert) {
        try {
            byte[] extensionValue = cert.getExtensionValue(oid);
            if (extensionValue == null) {
                return "No value";
            }
            
            // Common OIDs
            switch (oid) {
                case "2.5.29.14": return "Subject Key Identifier";
                case "2.5.29.15": return "Key Usage";
                case "2.5.29.17": return "Subject Alternative Name";
                case "2.5.29.19": return "Basic Constraints";
                case "2.5.29.31": return "CRL Distribution Points";
                case "2.5.29.32": return "Certificate Policies";
                case "2.5.29.35": return "Authority Key Identifier";
                case "2.5.29.37": return "Extended Key Usage";
                // Add more OIDs as needed
                default: return "OID: " + oid;
            }
        } catch (Exception e) {
            return "Error parsing extension: " + e.getMessage();
        }
    }

    // Helper method to get general name type as string
    private String getGeneralNameTypeString(Integer type) {
        switch (type) {
            case 0: return "otherName";
            case 1: return "rfc822Name";
            case 2: return "dNSName";
            case 3: return "x400Address";
            case 4: return "directoryName";
            case 5: return "ediPartyName";
            case 6: return "uniformResourceIdentifier";
            case 7: return "iPAddress";
            case 8: return "registeredID";
            default: return "unknown(" + type + ")";
        }
    }
    
    // Helper method to convert byte array to hex string
    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }
}