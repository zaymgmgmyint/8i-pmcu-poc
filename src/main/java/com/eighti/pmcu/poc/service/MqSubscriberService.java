package com.eighti.pmcu.poc.service;

import com.eighti.pmcu.poc.request.AddPersonRequest;
import com.eighti.pmcu.poc.response.AddPersonResponse;
import com.eighti.pmcu.poc.response.GetMqConfigResponse;
import com.eighti.pmcu.poc.response.VmsAddVisitorMessage;
import com.eighti.pmcu.poc.util.MqPasswordDecrypter;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import jakarta.jms.*;
import org.apache.activemq.ActiveMQSslConnectionFactory;
import org.apache.activemq.command.ActiveMQTopic;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

/**
 * MQ Subscriber Service - matches Python implementation for DSS MQ integration
 * See: docs/dss-api-spec.md, dss_api_sample.py, dss_mq_sample.py
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
                logger.info("MQ configuration data: {}", data);
                logger.info("Configured scheme: {}", schema);

                String userName = data.getUserName();
                String encryptedPassword = data.getPassword();
                String plainSecretKey = dssService.getPlainSecretKey();
                String plainSecretVector = dssService.getPlainSecretVector();

                // Password handling - try decryption first, then fallback to common passwords
                String password = null;
                if (encryptedPassword != null) {
                    try {
                        password = MqPasswordDecrypter.decryptMqPassword(
                                encryptedPassword, plainSecretKey, plainSecretVector);
                        if (password != null) {
                            logger.info("✅ Successfully decrypted MQ password");
                        } else {
                            logger.warn("⚠️ Password decryption failed, using common passwords");
                            password = "admin"; // Common default
                        }
                    } catch (Exception e) {
                        logger.warn("❌ Password decryption error: {}", e.getMessage());
                        password = "admin";
                    }
                } else {
                    logger.warn("⚠️ No MQ password found, using default");
                    password = "admin";
                }

                // Connection strategy - try multiple approaches like Python sample
                boolean connected = false;
                List<ConnectionAttempt> attempts = new ArrayList<>();

                // Try plain TCP first since SSL is failing
                attempts.add(new ConnectionAttempt("tcp", data.getAddr(), "ActiveMQ TCP"));
                attempts.add(new ConnectionAttempt("tcp", data.getMqtt(), "MQTT TCP"));
                if (data.getAmqp() != null && !data.getAmqp().isEmpty()) {
                    attempts.add(new ConnectionAttempt("tcp", data.getAmqp(), "AMQP TCP"));
                }

                // Only try SSL if TLS is enabled
                if ("1".equals(data.getEnableTls())) {
                    attempts.add(new ConnectionAttempt("ssl", data.getAddr(), "ActiveMQ SSL"));
                    if (data.getWss() != null && !data.getWss().isEmpty()) {
                        attempts.add(new ConnectionAttempt("ssl", data.getWss(), "WebSocket SSL"));
                    }
                }

                // Try each connection
                for (ConnectionAttempt attempt : attempts) {
                    String mqUrl = attempt.scheme + "://" + attempt.hostPort;
                    logger.info("Trying connection: {} ({})", mqUrl, attempt.description);

                    String host = extractHost(mqUrl);
                    int port = extractPort(mqUrl);

                    if (isPortOpen(host, port, 3000)) {
                        logger.info("✅ Port {} on host {} is reachable", port, host);
                        try {
                            connected = connectToMq(mqUrl, userName, password, commonTopic);
                            if (connected) {
                                logger.info("✅ Successfully connected to MQ at {}", mqUrl);
                                break;
                            }
                        } catch (Exception e) {
                            logger.warn("⚠️ Connection failed to {}: {}", mqUrl, e.getMessage());
                        }
                    } else {
                        logger.warn("❌ Port {} on host {} is NOT reachable", port, host);
                    }
                }

                if (!connected) {
                    logger.error("❌ All connection attempts failed");
                }
            } else {
                logger.error("❌ MQ config data is null");
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
            boolean isSSL = mqUrl.startsWith("ssl://");
            ConnectionFactory factory;

            if (isSSL) {
                logger.info("Setting up SSL connection factory");
                ActiveMQSslConnectionFactory sslFactory = new ActiveMQSslConnectionFactory(mqUrl);
                sslFactory.setConnectResponseTimeout(10000);
                sslFactory.setTrustAllPackages(true);
                setTrustAllTrustManager(sslFactory);
                logger.info("Configured SSL connection");
                factory = sslFactory;
            } else {
                logger.info("Setting up TCP connection factory");
                org.apache.activemq.ActiveMQConnectionFactory tcpFactory =
                    new org.apache.activemq.ActiveMQConnectionFactory(mqUrl);
                tcpFactory.setTrustAllPackages(true);
                factory = tcpFactory;
            }

            // Connection attempts with retry
            int maxRetries = 3;
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

                    // Set up message listener
                    consumer.setMessageListener(message -> {
                        if (message instanceof TextMessage) {
                            try {
                                String text = ((TextMessage) message).getText();
                                if (text != null && text.contains("\"method\":\"" + methodFilter + "\"")) {
                                    logger.info("✅ Received {} message: {}", methodFilter, text);
                                    processVisitorMessage(text);
                                } else {
                                    logger.debug("⚠️ Received other message: {}", text);
                                }
                            } catch (JMSException e) {
                                logger.error("❌ Error processing message: {}", e.getMessage(), e);
                            }
                        }
                    });

                    return true;
                } catch (JMSException e) {
                    logger.warn("Connection attempt {} failed: {}", retry + 1, e.getMessage());
                    if (retry < maxRetries - 1) {
                        try {
                            Thread.sleep((retry + 1) * 2000);
                        } catch (InterruptedException ie) {
                            Thread.currentThread().interrupt();
                        }
                    }
                }
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

    private AddPersonRequest mapVisitorToAddPerson(VmsAddVisitorMessage visitorMsg) {
        AddPersonRequest req = new AddPersonRequest();

        // baseInfo (required)
        AddPersonRequest.BaseInfo baseInfo = new AddPersonRequest.BaseInfo();
        baseInfo.setPersonId(visitorMsg.getInfo() != null ? visitorMsg.getInfo().getVisitorId() : "unknown");
        baseInfo.setFirstName(visitorMsg.getInfo() != null ? visitorMsg.getInfo().getVisitorName() : "Visitor");
        baseInfo.setGender(visitorMsg.getInfo() != null ? visitorMsg.getInfo().getStatus() : "0");
        baseInfo.setOrgCode(visitorMsg.getInfo() != null ? visitorMsg.getInfo().getVisitorOrgName() : "001");
        req.setBaseInfo(baseInfo);

        // extensionInfo (required)
        AddPersonRequest.ExtensionInfo extensionInfo = new AddPersonRequest.ExtensionInfo();
        extensionInfo.setIdType(visitorMsg.getInfo() != null ? visitorMsg.getInfo().getIdType() : "0");
        extensionInfo.setNationalityId("9999");
        req.setExtensionInfo(extensionInfo);

        // authenticationInfo (required)
        AddPersonRequest.AuthenticationInfo authenticationInfo = new AddPersonRequest.AuthenticationInfo();
        authenticationInfo.setStartTime(String.valueOf(System.currentTimeMillis() / 1000));
        authenticationInfo.setEndTime("2026915199");
        req.setAuthenticationInfo(authenticationInfo);

        // accessInfo (required)
        AddPersonRequest.AccessInfo accessInfo = new AddPersonRequest.AccessInfo();
        accessInfo.setAccessType("0");
        req.setAccessInfo(accessInfo);

        // faceComparisonInfo (required)
        AddPersonRequest.FaceComparisonInfo faceComparisonInfo = new AddPersonRequest.FaceComparisonInfo();
        faceComparisonInfo.setEnableFaceComparisonGroup("1");
        req.setFaceComparisonInfo(faceComparisonInfo);

        return req;
    }

    @PreDestroy
    public void cleanup() {
        logger.info("Closing MQ connection, session, and consumer");
        try {
            if (consumer != null) consumer.close();
            if (session != null) session.close();
            if (connection != null) connection.close();
        } catch (JMSException e) {
            logger.error("❌ Error closing JMS resources: {}", e.getMessage(), e);
        }
    }

    private int extractPort(String mqUrl) {
        try {
            String[] parts = mqUrl.split(":");
            return Integer.parseInt(parts[2]);
        } catch (Exception e) {
            logger.warn("Could not extract port from MQ URL: {}", mqUrl);
            return -1;
        }
    }

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

    private boolean isPortOpen(String host, int port, int timeoutMillis) {
        try (java.net.Socket socket = new java.net.Socket()) {
            socket.connect(new java.net.InetSocketAddress(host, port), timeoutMillis);
            return true;
        } catch (Exception ex) {
            return false;
        }
    }

    private void setTrustAllTrustManager(ActiveMQSslConnectionFactory factory) {
        try {
            javax.net.ssl.TrustManager[] trustAllCerts = new javax.net.ssl.TrustManager[] {
                new javax.net.ssl.X509TrustManager() {
                    public java.security.cert.X509Certificate[] getAcceptedIssuers() { return null; }
                    public void checkClientTrusted(java.security.cert.X509Certificate[] certs, String authType) { }
                    public void checkServerTrusted(java.security.cert.X509Certificate[] certs, String authType) { }
                }
            };
            factory.setKeyAndTrustManagers(null, trustAllCerts, null);
        } catch (Exception e) {
            logger.warn("Could not set TrustAll TrustManager: {}", e.getMessage(), e);
        }
    }
}
