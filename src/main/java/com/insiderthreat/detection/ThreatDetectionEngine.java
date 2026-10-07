package com.insiderthreat.detection;

import com.insiderthreat.model.SecurityEvent;
import java.util.List;

public class ThreatDetectionEngine {

    /**
     * Analyzes a sequence of security events and identifies
     * suspicious insider activity patterns.
     *
     * @param events list of security events
     * @return threat description
     */
    public static String analyzeUserActivity(List<SecurityEvent> events) {

        boolean loginDetected = false;
        boolean sensitiveFileAccess = false;
        boolean usbDetected = false;
        boolean fileCopyDetected = false;

        for (SecurityEvent event : events) {

            switch (event.getEventType()) {

                case LOGIN:
                    loginDetected = true;
                    break;

                case FILE_ACCESS:
                    sensitiveFileAccess = true;
                    break;

                case USB_INSERT:
                    usbDetected = true;
                    break;

                case FILE_COPY:
                    fileCopyDetected = true;
                    break;

                default:
                    break;
            }
        }

        /*
         * Strong behavioral pattern:
         *
         * LOGIN
         *     ↓
         * FILE_ACCESS
         *     ↓
         * USB_INSERT
         *     ↓
         * FILE_COPY
         *
         * This pattern indicates potential insider
         * data exfiltration and requires investigation.
         */
        if (loginDetected
                && sensitiveFileAccess
                && usbDetected
                && fileCopyDetected) {

            return "POSSIBLE INSIDER DATA THEFT";
        }

        /*
         * USB activity followed by file copying
         * indicates suspicious data transfer.
         */
        if (usbDetected && fileCopyDetected) {

            return "SUSPICIOUS DATA TRANSFER ACTIVITY";
        }

        /*
         * File access followed by copying may indicate
         * unauthorized or suspicious file handling.
         */
        if (sensitiveFileAccess && fileCopyDetected) {

            return "SUSPICIOUS FILE COPYING ACTIVITY";
        }

        return "NO SIGNIFICANT THREAT DETECTED";
    }


    /**
     * Calculates an overall behavioral risk score
     * based on the combination of security events.
     *
     * Maximum score = 100.
     *
     * @param events list of security events
     * @return behavioral score from 0 to 100
     */
    public static int calculateBehaviorScore(
            List<SecurityEvent> events) {

        int score = 0;

        boolean fileAccess = false;
        boolean usbActivity = false;
        boolean fileCopy = false;

        for (SecurityEvent event : events) {

            switch (event.getEventType()) {

                case FILE_ACCESS:
                    fileAccess = true;
                    break;

                case USB_INSERT:
                    usbActivity = true;
                    break;

                case FILE_COPY:
                    fileCopy = true;
                    break;

                default:
                    break;
            }
        }

        /*
         * Base behavioral scores.
         */
        if (fileAccess) {
            score += 20;
        }

        if (usbActivity) {
            score += 30;
        }

        if (fileCopy) {
            score += 30;
        }

        /*
         * Additional correlation score when
         * USB activity and file copying occur together.
         */
        if (usbActivity && fileCopy) {
            score += 20;
        }

        /*
         * Prevent the score from exceeding 100.
         */
        return Math.min(score, 100);
    }


    /**
     * Converts the behavioral score into a threat classification.
     *
     * @param score behavioral risk score
     * @return threat classification
     */
    public static String classifyThreat(int score) {

        if (score >= 80) {

            return "POSSIBLE INSIDER DATA THEFT";
        }

        if (score >= 60) {

            return "HIGH-RISK INSIDER ACTIVITY";
        }

        if (score >= 30) {

            return "SUSPICIOUS ACTIVITY";
        }

        return "NO SIGNIFICANT THREAT DETECTED";
    }
}