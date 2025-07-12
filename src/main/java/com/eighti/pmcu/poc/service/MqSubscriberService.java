package com.eighti.pmcu.poc.service;

import com.eighti.pmcu.poc.exception.DssServiceException;
import com.eighti.pmcu.poc.response.FirstLoginResponse;
import com.eighti.pmcu.poc.response.GetMqConfigResponse;
import com.eighti.pmcu.poc.response.SecondLoginResponse;
import org.apache.activemq.ActiveMQSslConnectionFactory;
import org.apache.activemq.command.ActiveMQTopic;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import jakarta.annotation.PreDestroy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import jakarta.annotation.PostConstruct;
import jakarta.jms.*;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.util.Base64;

/**
 * AGENT: See: docs/dss-api-spec.md
 */
@Service
public class MqSubscriberService {
    private static final Logger logger = LoggerFactory.getLogger(MqSubscriberService.class);
    private static final String TOPIC_NAME = "mq.common.msg.topic";
    private static final String LISTEN_MESSAGE_NAME = "vms.addVisitor";

    @Autowired
    private DssService dssService;

    private Connection connection;
    private Session session;
    private MessageConsumer consumer;

    @PostConstruct
    public void subscribeToMq() {
        try {
            GetMqConfigResponse mqConfig = dssService.getMqConfig();
            GetMqConfigResponse.DataDto data = mqConfig.getData();
            if (data != null) {
                String mqUrl = "ssl://" + data.getAddr();
                String userName = data.getUserName();
                String encryptedPassword = data.getPassword();
                // Use the plain secretKey and secretVector generated during second login (not the encrypted ones from the response)
                String secretKey = dssService.getPlainSecretKey();
                String secretVector = dssService.getPlainSecretVector();
                String password = decryptAesPassword(encryptedPassword, secretKey, secretVector);
                logger.info("MQ URL: {}", mqUrl);
                int port = extractPort(mqUrl);
                String host = extractHost(mqUrl);
                if (isPortOpen(host, port, 2000)) {
                    logger.info("✅ MQ port {} on host {} is reachable.", port, host);
                } else {
                    logger.error("❌ MQ port {} on host {} is NOT reachable! Aborting MQ connection.", port, host);
                    return;
                }
                logger.info("♻️ Preparing to connect to MQ at {} (port {})", mqUrl, port);
                listenToMq(mqUrl, userName, password, TOPIC_NAME);
            } else {
                logger.error("❌ MQ config data is null from DSS response");
            }
        } catch (Exception e) {
            logger.error("❌ Error subscribing to MQ: {}", e.getMessage(), e);
        }
    }

    private void listenToMq(String mqUrl, String userName, String password, String topicName) {
        try {
            ActiveMQSslConnectionFactory factory = new ActiveMQSslConnectionFactory(mqUrl);
            // Bypass SSL certificate validation for testing only
            factory.setTrustAllPackages(true);
            setTrustAllTrustManager(factory);
            factory.setUserName(userName);
            factory.setPassword(password);
            connection = factory.createConnection();
            connection.start();
            logger.info("MQ connection established successfully to {} as user {}", mqUrl, userName);
            session = connection.createSession(false, Session.AUTO_ACKNOWLEDGE);
            Topic topic = new ActiveMQTopic(topicName);
            consumer = session.createConsumer(topic);
            logger.info("Start listening to topic: {}", topicName);
            consumer.setMessageListener(message -> {
                if (message instanceof TextMessage) {
                    try {
                        String text = ((TextMessage) message).getText();
                        if (text != null) {
                            // Only log vms.addVisitor messages as info, others as debug
                            if (text.contains("\"method\":\"vms.addVisitor\"")) {
                                logger.info("Received vms.addVisitor message: {}", text);
                            } else {
                                logger.debug("Received message: {}", text);
                            }
                        }
                    } catch (JMSException e) {
                        logger.error("Error getting text from message: {}", e.getMessage(), e);
                    }
                } else {
                    logger.warn("Received non-text JMS message: {}", message);
                }
            });
        } catch (JMSException e) {
            logger.error("Error connecting to MQ: {}", e.getMessage(), e);
        } catch (Exception e) {
            logger.error("Unexpected error in listenToMq: {}", e.getMessage(), e);
        }
    }

    @PreDestroy
    public void cleanup() {
        logger.info("Closing MQ connection, session, and consumer.");
        try {
            if (consumer != null) {
                consumer.close();
            }
            if (session != null) {
                session.close();
            }
            if (connection != null) {
                connection.close();
            }
        } catch (JMSException e) {
            logger.error("Error closing JMS resources: {}", e.getMessage(), e);
        }
    }


    /**
     * Decrypts the MQ password using AES/CBC/PKCS7Padding and BouncyCastle
     */
    private String decryptAesPassword(String encryptedPassword, String base64SecretKey, String base64SecretVector) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        byte[] keyBytes = Base64.getDecoder().decode(base64SecretKey);
        byte[] ivBytes = Base64.getDecoder().decode(base64SecretVector);
        SecretKeySpec skeySpec = new SecretKeySpec(keyBytes, "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding");
        IvParameterSpec iv = new IvParameterSpec(ivBytes);
        cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);
        byte[] encrypted = hexStringToByteArray(encryptedPassword);
        byte[] original = cipher.doFinal(encrypted);
        return new String(original, StandardCharsets.UTF_8);
    }

    private byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

    /**
     * Extracts the port from the MQ URL (e.g., ssl://host:61616)
     */
    private int extractPort(String mqUrl) {
        try {
            String[] parts = mqUrl.split(":");
            return Integer.parseInt(parts[2]);
        } catch (Exception e) {
            logger.warn("Could not extract port from MQ URL: {}", mqUrl);
            return -1;
        }
    }

    /**
     * Extracts the host from the MQ URL (e.g., ssl://host:61616)
     */
    private String extractHost(String mqUrl) {
        try {
            String[] parts = mqUrl.split("://");
            String hostPort = parts[1];
            return hostPort.split(":")[0];
        } catch (Exception e) {
            logger.warn("Could not extract host from MQ URL: {}", mqUrl);
            return "localhost";
        }
    }

    /**
     * Checks if a TCP port is open on a given host (like telnet)
     */
    private boolean isPortOpen(String host, int port, int timeoutMillis) {
        try (java.net.Socket socket = new java.net.Socket()) {
            socket.connect(new java.net.InetSocketAddress(host, port), timeoutMillis);
            return true;
        } catch (Exception ex) {
            return false;
        }
    }

    /**
     * Sets a TrustManager that trusts all certificates (for testing only!)
     */
    private void setTrustAllTrustManager(ActiveMQSslConnectionFactory factory) {
        try {
            javax.net.ssl.TrustManager[] trustAllCerts = new javax.net.ssl.TrustManager[] {
                new javax.net.ssl.X509TrustManager() {
                    public java.security.cert.X509Certificate[] getAcceptedIssuers() { return null; }
                    public void checkClientTrusted(java.security.cert.X509Certificate[] certs, String authType) { }
                    public void checkServerTrusted(java.security.cert.X509Certificate[] certs, String authType) { }
                }
            };
            // Fix: Use setKeyAndTrustManagers instead of setTrustManagers for ActiveMQSslConnectionFactory
            factory.setKeyAndTrustManagers(null, trustAllCerts, null);
        } catch (Exception e) {
            logger.warn("Could not set TrustAll TrustManager: {}", e.getMessage(), e);
        }
    }
}
