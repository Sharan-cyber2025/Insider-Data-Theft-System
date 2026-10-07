package com.insiderthreat;

import com.insiderthreat.analysis.IncidentAnalyzer;
import com.insiderthreat.audit.AuditLogger;
import com.insiderthreat.detection.RiskScoreEngine;
import com.insiderthreat.detection.ThreatDetectionEngine;
import com.insiderthreat.model.SecurityEvent;
import com.insiderthreat.model.SecurityEvent.EventType;
import com.insiderthreat.monitoring.EventMonitor;
import java.util.List;

public class Main {

    private static void line() {
        System.out.println("==============================================");
    }

    public static void main(String[] args) {

        line();
        System.out.println("       INSIDER DATA THEFT DETECTION SYSTEM");
        line();

        System.out.println("System starting...\n");

        // -------------------------------------------------
        // 1. Initialize Event Monitor
        // -------------------------------------------------

        EventMonitor monitor = new EventMonitor();

        System.out.println("[SYSTEM] Event monitoring initialized.");
        System.out.println("[SYSTEM] Security event collection started.\n");

        // -------------------------------------------------
        // 2. Generate security events
        // -------------------------------------------------

        monitor.recordEvent(
                new SecurityEvent(
                        "USR-001",
                        EventType.LOGIN,
                        "Corporate System",
                        "WORKSTATION"
                )
        );

        monitor.recordEvent(
                new SecurityEvent(
                        "USR-001",
                        EventType.FILE_ACCESS,
                        "employee_records.xlsx",
                        "WORKSTATION"
                )
        );

        monitor.recordEvent(
                new SecurityEvent(
                        "USR-001",
                        EventType.USB_INSERT,
                        "USB-001",
                        "USB_DEVICE"
                )
        );

        monitor.recordEvent(
                new SecurityEvent(
                        "USR-001",
                        EventType.FILE_COPY,
                        "confidential.pdf",
                        "USB_DEVICE"
                )
        );

        // -------------------------------------------------
        // 3. Display collected events
        // -------------------------------------------------

        line();
        System.out.println("              EVENT MONITOR");
        line();

        List<SecurityEvent> events = monitor.getEvents();

        for (SecurityEvent event : events) {
            System.out.println(event);
        }

        System.out.println("----------------------------------------------");
        System.out.println("Total Events: " + events.size());

        // -------------------------------------------------
        // 4. Individual Risk Analysis
        // -------------------------------------------------

        line();
        System.out.println("             INDIVIDUAL RISK ANALYSIS");
        line();

        for (SecurityEvent event : events) {

            int riskScore =
                    RiskScoreEngine.calculateRiskScore(event);

            String riskLevel =
                    RiskScoreEngine.classifyRisk(riskScore);

            System.out.println();

            System.out.println("User       : " + event.getUserId());
            System.out.println("Event      : " + event.getEventType());
            System.out.println("Resource   : " + event.getResource());
            System.out.println("Source     : " + event.getSource());
            System.out.println("Timestamp  : " + event.getTimestamp());
            System.out.println("Risk Score : " + riskScore + "/100");
            System.out.println("Risk Level : " + riskLevel);

            if (riskScore >= 80) {

                System.out.println(
                        "ALERT      : CRITICAL THREAT DETECTED!"
                );

                System.out.println(
                        "Action     : IMMEDIATE SECURITY RESPONSE"
                );

            } else if (riskScore >= 60) {

                System.out.println(
                        "ALERT      : HIGH-RISK ACTIVITY DETECTED!"
                );

                System.out.println(
                        "Action     : INVESTIGATE USER ACTIVITY"
                );

            } else if (riskScore >= 30) {

                System.out.println(
                        "WARNING    : SUSPICIOUS ACTIVITY DETECTED."
                );

                System.out.println(
                        "Action     : CONTINUE MONITORING"
                );

            } else {

                System.out.println(
                        "STATUS     : NORMAL ACTIVITY."
                );

                System.out.println(
                        "Action     : CONTINUE MONITORING"
                );
            }
        }

        // -------------------------------------------------
        // 5. Behavioral Threat Analysis
        // -------------------------------------------------

        line();
        System.out.println("          BEHAVIORAL THREAT ANALYSIS");
        line();

        int behaviorScore =
                ThreatDetectionEngine.calculateBehaviorScore(events);

        String threatResult =
                ThreatDetectionEngine.classifyThreat(behaviorScore);

        System.out.println(
                "Events Analyzed : " + events.size()
        );

        System.out.println(
                "Behavior Score  : " + behaviorScore + "/100"
        );

        System.out.println(
                "Threat Result   : " + threatResult
        );

        // -------------------------------------------------
        // 6. Security Decision
        // -------------------------------------------------

        line();
        System.out.println("           FORENSIC SECURITY DECISION");
        line();

        String priority;
        String action;

        if (behaviorScore >= 80) {

            priority = "CRITICAL";
            action = "INITIATE FORENSIC INVESTIGATION";

            System.out.println(
                    "🚨 ALERT: POSSIBLE INSIDER DATA THEFT!"
            );

        } else if (behaviorScore >= 60) {

            priority = "HIGH";
            action = "INVESTIGATE USER ACTIVITY";

            System.out.println(
                    "⚠ ALERT: SUSPICIOUS INSIDER ACTIVITY!"
            );

        } else if (behaviorScore >= 30) {

            priority = "MEDIUM";
            action = "CONTINUE MONITORING";

            System.out.println(
                    "WARNING: SUSPICIOUS ACTIVITY DETECTED."
            );

        } else {

            priority = "LOW";
            action = "CONTINUE MONITORING";

            System.out.println(
                    "STATUS: NORMAL ACTIVITY."
            );
        }

        System.out.println("Action   : " + action);
        System.out.println("Priority : " + priority);

        // -------------------------------------------------
        // 7. Audit Logging
        // -------------------------------------------------

        AuditLogger.logThreat(
                "USR-001",
                behaviorScore,
                threatResult,
                priority,
                action
        );

        // -------------------------------------------------
        // 8. Detection Summary
        // -------------------------------------------------

        line();
        System.out.println("              DETECTION SUMMARY");
        line();

        System.out.println(
                "Total Events Processed : " + events.size()
        );

        System.out.println(
                "Behavior Score          : "
                        + behaviorScore + "/100"
        );

        System.out.println(
                "Threat Classification   : " + threatResult
        );

        line();

        // -------------------------------------------------
        // 9. Forensic Investigation Console
        // -------------------------------------------------

        IncidentAnalyzer.generateInvestigationReport(
                events,
                behaviorScore,
                threatResult
        );

        // -------------------------------------------------
        // 10. System Status
        // -------------------------------------------------

        line();
        System.out.println("Monitoring Status : ACTIVE");
        System.out.println("Detection Engine  : ACTIVE");
        System.out.println("Risk Analysis     : ACTIVE");
        System.out.println("Behavior Analysis : ACTIVE");
        System.out.println("Audit Logging     : ACTIVE");
        System.out.println("Incident Analysis : ACTIVE");
        line();

        System.out.println(
                "Insider Data Theft Detection System"
        );

        System.out.println(
                "System execution completed successfully."
        );

        line();
    }
}