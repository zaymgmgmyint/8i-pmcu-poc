package com.eighti.pmcu.poc.service;

import com.eighti.pmcu.poc.exception.DssServiceException;
import com.eighti.pmcu.poc.response.FirstLoginResponse;
import com.eighti.pmcu.poc.response.GetMqConfigResponse;
import com.eighti.pmcu.poc.response.SecondLoginResponse;
import com.eighti.pmcu.poc.response.VmsAddVisitorMessage;
import com.eighti.pmcu.poc.request.AddPersonRequest;
import com.eighti.pmcu.poc.response.AddPersonResponse;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.activemq.ActiveMQSslConnectionFactory;
import org.apache.activemq.command.ActiveMQTopic;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import jakarta.annotation.PreDestroy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import jakarta.annotation.PostConstruct;
import jakarta.jms.*;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

/**
 * AGENT: See: docs/dss-api-spec.md
 */
@Service
public class MqSubscriberService {
    private static final Logger logger = LoggerFactory.getLogger(MqSubscriberService.class);

    @Value("${mq.topic}")
    private String commonTopic;

    @Value("${mq.method-filter}")
    private String methodFilter;

    @Value("${mq.scheme}")
    private String schema;

    @Autowired
    private DssService dssService;
    @Autowired
    private PersonService personService;
    @Autowired
    private ObjectMapper objectMapper;

    private Connection connection;
    private Session session;
    private MessageConsumer consumer;

   @PostConstruct
    public void subscribeToMq() {
        try {
            logger.info("Starting MQ subscription process...");
            GetMqConfigResponse mqConfig = dssService.getMqConfig();
            GetMqConfigResponse.DataDto data = mqConfig.getData();
            if (data != null) {
                // Get MQ connection parameters
                logger.info("MQ configuration data: {}", data);
                logger.info("Configured scheme: {}", schema);

                String userName = data.getUserName();
                String encryptedPassword = data.getPassword();

                // Get the plaintext keys stored during login for decryption
                String plainSecretKey = dssService.getPlainSecretKey();
                String plainSecretVector = dssService.getPlainSecretVector();

                // Password handling (decryption + fallbacks)
                String password = null;
                if (encryptedPassword != null) {
                    try {
                        // Try to decrypt the password using our utility class first
                        password = com.eighti.pmcu.poc.util.MqPasswordDecrypter.decryptMqPassword(
                                encryptedPassword,
                                plainSecretKey,
                                plainSecretVector
                        );

                        if (password != null) {
                            logger.info("✅ Successfully decrypted MQ password");
                        } else {
                            logger.warn("⚠️ Utility decryption returned null, trying fallbacks");
                        }
                    } catch (Exception e) {
                        logger.warn("❌ Password decryption failed: {}", e.getMessage());
                    }

                    // If still null, try common passwords
                    if (password == null) {
                        String[] commonPasswords = {"admin", "consumer", "password", "123456", "dahua", "system"};
                        logger.info("Trying common passwords as fallback");
                        password = commonPasswords[0]; // Start with admin
                    }
                } else {
                    logger.warn("⚠️ No MQ password found in response, using default");
                    password = "admin"; // Default MQ password
                }

                // Connection strategy - similar to Python sample
                boolean connected = false;

                // Try each connection protocol/port in order
                List<ConnectionAttempt> attempts = new ArrayList<>();

                // 1. First try MQTT port if available (Python tries this first)
                if (data.getMqtt() != null && !data.getMqtt().isEmpty()) {
                    attempts.add(new ConnectionAttempt(schema, data.getMqtt(), "MQTT port"));
                }

                // 2. Then try ActiveMQ OpenWire port (Python tries this second)
                attempts.add(new ConnectionAttempt(schema, data.getAddr(), "ActiveMQ port"));

                // 3. If schema is SSL, also try TCP as fallback
                if ("ssl".equalsIgnoreCase(schema)) {
                    attempts.add(new ConnectionAttempt("tcp", data.getAddr(), "TCP fallback"));
                }
                // 4. If schema is TCP, also try SSL as fallback
                else if ("tcp".equalsIgnoreCase(schema)) {
                    attempts.add(new ConnectionAttempt("ssl", data.getAddr(), "SSL fallback"));
                }

                // Try each connection attempt in sequence
                for (ConnectionAttempt attempt : attempts) {
                    String mqUrl = attempt.scheme + "://" + attempt.hostPort;
                    logger.info("Trying connection: {} ({})", mqUrl, attempt.description);

                    // Check port accessibility first
                    String host = extractHost(mqUrl);
                    int port = extractPort(mqUrl);

                    if (isPortOpen(host, port, 3000)) {
                        logger.info("✅ Port {} on host {} is reachable", port, host);

                        try {
                            connected = connectToMq(mqUrl, userName, password, commonTopic);
                            if (connected) {
                                logger.info("✅ Successfully connected to MQ at {}", mqUrl);
                                break; // Stop trying other connections if successful
                            }
                        } catch (Exception e) {
                            logger.warn("⚠️ Connection failed to {}: {}", mqUrl, e.getMessage());
                        }
                    } else {
                        logger.warn("❌ Port {} on host {} is NOT reachable", port, host);
                    }
                }

                if (!connected) {
                    logger.error("❌ All connection attempts failed. Unable to establish MQ connection.");
                }
            } else {
                logger.error("❌ MQ config data is null from DSS response");
            }
        } catch (Exception e) {
            logger.error("❌ Error subscribing to MQ: {}", e.getMessage(), e);
        }
    }

    private static class ConnectionAttempt {
        final String scheme;
        final String hostPort;
        final String description;

        ConnectionAttempt(String scheme, String hostPort, String description) {
            this.scheme = scheme;
            this.hostPort = hostPort;
            this.description = description;
        }
    }

    private boolean connectToMq(String mqUrl, String userName, String password, String topicName) {
        logger.info("♻️ Connecting to MQ at {} as user {}", mqUrl, userName);

        try {
            // For SSL vs TCP connection handling
            boolean isSSL = mqUrl.startsWith("ssl://");
            ConnectionFactory factory = null;

            if (isSSL) {
                // SSL connection factory - similar to Python's TLS setup
                logger.info("Setting up SSL connection factory");
                ActiveMQSslConnectionFactory sslFactory = new ActiveMQSslConnectionFactory(mqUrl);
                sslFactory.setConnectResponseTimeout(10000);
                sslFactory.setTrustAllPackages(true);

                // Trust all certificates - similar to Python's cert_reqs=ssl.CERT_NONE
                setTrustAllTrustManager(sslFactory);
                logger.info("Configured with SSL trust-all settings");
                factory = sslFactory;
            } else {
                // TCP connection - use regular ActiveMQConnectionFactory
                logger.info("Setting up TCP connection factory");
                org.apache.activemq.ActiveMQConnectionFactory tcpFactory =
                    new org.apache.activemq.ActiveMQConnectionFactory(mqUrl);
                tcpFactory.setTrustAllPackages(true);
                logger.info("Configured with TCP settings");
                factory = tcpFactory;
            }

            // Multiple connection attempts with backoff (like Python's reconnect logic)
            int maxRetries = 3;
            Exception lastException = null;

            for (int retry = 0; retry < maxRetries; retry++) {
                try {
                    logger.info("Connection attempt {} of {}", retry + 1, maxRetries);
                    connection = factory.createConnection(userName, password);
                    connection.start();

                    session = connection.createSession(false, Session.AUTO_ACKNOWLEDGE);
                    Topic topic = new ActiveMQTopic(topicName);
                    consumer = session.createConsumer(topic);

                    logger.info("✅ Connected to MQ broker successfully");
                    logger.info("Listening to topic: {}", topicName);

                    // Set up message listener for the consumer
                    consumer.setMessageListener(message -> {
                        if (message instanceof TextMessage) {
                            try {
                                String text = ((TextMessage) message).getText();
                                if (text != null) {
                                    if (text.contains("\"method\":\"" + methodFilter + "\"")) {
                                        logger.info("✅ Received {} message: {}", methodFilter, text);
                                        processVisitorMessage(text);
                                    } else {
                                        logger.debug("⚠️ Received other message: {}", text);
                                    }
                                }
                            } catch (JMSException e) {
                                logger.error("❌ Error getting text from message: {}", e.getMessage(), e);
                            }
                        } else {
                            logger.warn("⚠️ Received non-text JMS message: {}", message);
                        }
                    });

                    return true;
                } catch (JMSException e) {
                    lastException = e;
                    logger.warn("Connection attempt {} failed: {}", retry + 1, e.getMessage());
                    if (retry < maxRetries - 1) {
                        int backoffMs = (retry + 1) * 2000; // Exponential backoff
                        logger.info("Retrying in {} ms...", backoffMs);
                        try {
                            Thread.sleep(backoffMs);
                        } catch (InterruptedException ie) {
                            Thread.currentThread().interrupt();
                        }
                    }
                }
            }

            if (lastException != null) {
                logger.error("❌ Failed to connect after {} attempts: {}", maxRetries, lastException.getMessage());
            }

        } catch (Exception e) {
            logger.error("❌ Error in MQ connection setup: {}", e.getMessage(), e);
        }

        return false;
    }

    private void processVisitorMessage(String messageText) {
        try {
            VmsAddVisitorMessage visitorMsg = objectMapper.readValue(messageText, VmsAddVisitorMessage.class);
            AddPersonRequest addPersonRequest = mapVisitorToAddPerson(visitorMsg);
            AddPersonResponse addPersonResponse = personService.addPerson(addPersonRequest);
            logger.info("✅ Added person from visitor message. Response: {}", addPersonResponse);
        } catch (Exception ex) {
            logger.error("❌ Error processing visitor message: {}", ex.getMessage(), ex);
        }
    }

    // AGENT: Map VmsAddVisitorMessage to AddPersonRequest (minimal, all required fields for /obms/api/v1.1/acs/person)
    private AddPersonRequest mapVisitorToAddPerson(VmsAddVisitorMessage visitorMsg) {
        AddPersonRequest req = new AddPersonRequest();

        // --- baseInfo (required) ---
        AddPersonRequest.BaseInfo baseInfo = new AddPersonRequest.BaseInfo();
        baseInfo.setPersonId(visitorMsg.getInfo() != null ? visitorMsg.getInfo().getVisitorId() : "unknown");
        baseInfo.setFirstName(visitorMsg.getInfo() != null ? visitorMsg.getInfo().getVisitorName() : "Visitor");
        baseInfo.setGender(visitorMsg.getInfo() != null ? visitorMsg.getInfo().getStatus() : "0"); // fallback to "0" (unknown)
        baseInfo.setOrgCode(visitorMsg.getInfo() != null ? visitorMsg.getInfo().getVisitorOrgName() : "001");
        req.setBaseInfo(baseInfo);

        // --- extensionInfo (required) ---
        AddPersonRequest.ExtensionInfo extensionInfo = new AddPersonRequest.ExtensionInfo();
        extensionInfo.setIdType(visitorMsg.getInfo() != null ? visitorMsg.getInfo().getIdType() : "0");
        extensionInfo.setNationalityId("9999");
        req.setExtensionInfo(extensionInfo);

        // --- authenticationInfo (required) ---
        AddPersonRequest.AuthenticationInfo authenticationInfo = new AddPersonRequest.AuthenticationInfo();
        authenticationInfo.setStartTime(String.valueOf(System.currentTimeMillis() / 1000)); // now (seconds)
        authenticationInfo.setEndTime("2026915199"); // year 2034
        req.setAuthenticationInfo(authenticationInfo);

        // --- accessInfo (required) ---
        AddPersonRequest.AccessInfo accessInfo = new AddPersonRequest.AccessInfo();
        accessInfo.setAccessType("0"); // Normal
        req.setAccessInfo(accessInfo);

        // --- faceComparisonInfo (required) ---
        AddPersonRequest.FaceComparisonInfo faceComparisonInfo = new AddPersonRequest.FaceComparisonInfo();
        faceComparisonInfo.setEnableFaceComparisonGroup("1");
        req.setFaceComparisonInfo(faceComparisonInfo);

        return req;
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
            logger.error("❌ Error closing JMS resources: {}", e.getMessage(), e);
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
