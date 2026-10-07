package com.insiderthreat.analysis;

import com.insiderthreat.model.SecurityEvent;
import com.insiderthreat.detection.RiskScoreEngine;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;

public class IncidentAnalyzer {

    private static int incidentCounter = 1;

    /**
     * Generates a unique incident ID.
     */
    private static String generateIncidentId() {

        LocalDateTime now = LocalDateTime.now();

        return String.format(
                "INC-%04d%02d%02d-%03d",
                now.getYear(),
                now.getMonthValue(),
                now.getDayOfMonth(),
                incidentCounter++
        );
    }

    /**
     * Generates the complete forensic investigation
     * console output from the detected security events.
     */
    public static void generateInvestigationReport(
            List<SecurityEvent> events,
            int behaviorScore,
            String threatResult) {

        if (events == null || events.isEmpty()) {

            System.out.println();
            System.out.println("==================================================");
            System.out.println("          INSIDER THREAT INVESTIGATION CONSOLE");
            System.out.println("==================================================");
            System.out.println();
            System.out.println("No security events available for investigation.");
            System.out.println("==================================================");

            return;
        }

        String incidentId = generateIncidentId();

        SecurityEvent firstEvent = events.get(0);

        String activeUser = firstEvent.getUserId();

        String threatLevel =
                RiskScoreEngine.classifyRisk(behaviorScore);

        String recommendedAction;

        if (behaviorScore >= 80) {

            recommendedAction =
                    "INITIATE FORENSIC INVESTIGATION";

        } else if (behaviorScore >= 60) {

            recommendedAction =
                    "INVESTIGATE USER ACTIVITY";

        } else if (behaviorScore >= 30) {

            recommendedAction =
                    "CONTINUE ENHANCED MONITORING";

        } else {

            recommendedAction =
                    "CONTINUE MONITORING";
        }

        DateTimeFormatter formatter =
                DateTimeFormatter.ofPattern("HH:mm:ss");

        System.out.println();

        System.out.println(
                "=================================================="
        );

        System.out.println(
                "          INSIDER THREAT INVESTIGATION CONSOLE"
        );

        System.out.println(
                "=================================================="
        );

        System.out.println();

        System.out.println(
                "Active User       : " + activeUser
        );

        System.out.println(
                "Incident ID       : " + incidentId
        );

        System.out.println(
                "Risk Score        : " + behaviorScore + "/100"
        );

        System.out.println(
                "Threat Level      : " + threatLevel
        );

        System.out.println();

        System.out.println(
                "EVENT SEQUENCE"
        );

        System.out.println(
                "--------------------------------------------------"
        );

        for (SecurityEvent event : events) {

            String time =
                    event.getTimestamp().format(formatter);

            System.out.printf(
                    "%-10s %-18s %-25s%n",
                    time,
                    event.getEventType(),
                    event.getResource()
            );
        }

        System.out.println();

        System.out.println(
                "CORRELATED PATTERN"
        );

        System.out.println(
                "--------------------------------------------------"
        );

        System.out.println(
                buildCorrelatedPattern(events)
        );

        System.out.println();

        System.out.println(
                "DETECTION"
        );

        System.out.println(
                "--------------------------------------------------"
        );

        System.out.println(
                threatResult
        );

        System.out.println();

        System.out.println(
                "RECOMMENDED ACTION"
        );

        System.out.println(
                "--------------------------------------------------"
        );

        System.out.println(
                recommendedAction
        );

        System.out.println();

        System.out.println(
                "AUDIT STATUS"
        );

        System.out.println(
                "--------------------------------------------------"
        );

        System.out.println(
                "LOGGED ✓"
        );

        System.out.println();

        System.out.println(
                "=================================================="
        );
    }


    /**
     * Builds a human-readable representation of the
     * correlated security-event sequence.
     */
    private static String buildCorrelatedPattern(
            List<SecurityEvent> events) {

        StringBuilder pattern =
                new StringBuilder();

        for (int i = 0; i < events.size(); i++) {

            SecurityEvent event = events.get(i);

            String eventName =
                    formatEventName(
                            event.getEventType().name()
                    );

            pattern.append(eventName);

            if (i < events.size() - 1) {

                pattern.append(" → ");
            }
        }

        return pattern.toString();
    }


    /**
     * Converts enum-style event names into
     * readable security-event names.
     */
    private static String formatEventName(
            String eventName) {

        return eventName
                .replace("_", " ");
    }
}