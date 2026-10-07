package com.insiderthreat.audit;

import com.insiderthreat.model.SecurityEvent;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.time.LocalDateTime;

public class AuditLogger {

    private static final String LOG_DIRECTORY = "logs";
    private static final String LOG_FILE = LOG_DIRECTORY + "/security-audit.log";

    // Initialize audit logging
    public static void initialize() {

        File directory = new File(LOG_DIRECTORY);

        if (!directory.exists()) {
            directory.mkdirs();
        }

        try {
            File file = new File(LOG_FILE);

            if (!file.exists()) {
                file.createNewFile();
            }

        } catch (IOException e) {
            System.out.println("[AUDIT] Failed to initialize audit log.");
            e.printStackTrace();
        }
    }

    // Record a security event
    public static void logEvent(SecurityEvent event, int riskScore, String riskLevel) {

        initialize();

        try (FileWriter writer = new FileWriter(LOG_FILE, true)) {

            writer.write("========================================\n");
            writer.write("SECURITY EVENT AUDIT\n");
            writer.write("========================================\n");
            writer.write("Logged At   : " + LocalDateTime.now() + "\n");
            writer.write("User ID     : " + event.getUserId() + "\n");
            writer.write("Event       : " + event.getEventType() + "\n");
            writer.write("Resource    : " + event.getResource() + "\n");
            writer.write("Source      : " + event.getSource() + "\n");
            writer.write("Event Time  : " + event.getTimestamp() + "\n");
            writer.write("Risk Score  : " + riskScore + "/100\n");
            writer.write("Risk Level  : " + riskLevel + "\n");
            writer.write("========================================\n\n");

        } catch (IOException e) {

            System.out.println("[AUDIT] Failed to write security event.");
            e.printStackTrace();
        }
    }

    // Record a major insider-threat detection
    public static void logThreat(
            String userId,
            int behaviorScore,
            String threatResult,
            String priority,
            String action) {

        initialize();

        try (FileWriter writer = new FileWriter(LOG_FILE, true)) {

            writer.write("########################################\n");
            writer.write("INSIDER THREAT DETECTION\n");
            writer.write("########################################\n");
            writer.write("Detected At      : " + LocalDateTime.now() + "\n");
            writer.write("User ID          : " + userId + "\n");
            writer.write("Behavior Score   : " + behaviorScore + "/100\n");
            writer.write("Threat Result    : " + threatResult + "\n");
            writer.write("Priority         : " + priority + "\n");
            writer.write("Action           : " + action + "\n");
            writer.write("########################################\n\n");

        } catch (IOException e) {

            System.out.println("[AUDIT] Failed to write threat record.");
            e.printStackTrace();
        }
    }
}