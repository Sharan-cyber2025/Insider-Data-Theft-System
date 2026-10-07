package com.insiderthreat.detection;

import com.insiderthreat.model.SecurityEvent;

public class RiskScoreEngine {

    public static int calculateRiskScore(SecurityEvent event) {

        int score = 0;

        switch (event.getEventType()) {

            case FILE_COPY:
                score += 30;
                break;

            case FILE_DELETE:
                score += 40;
                break;

            case USB_INSERT:
                score += 20;
                break;

            case USB_REMOVE:
                score += 10;
                break;

            case FILE_ACCESS:
                score += 10;
                break;

            case LOGIN:
                score += 5;
                break;
        }

        // External USB device increases risk
        if ("USB_DEVICE".equalsIgnoreCase(event.getSource())) {
            score += 30;
        }

        return Math.min(score, 100);
    }

    public static String classifyRisk(int score) {

        if (score >= 80) {
            return "CRITICAL";
        }

        if (score >= 60) {
            return "HIGH";
        }

        if (score >= 30) {
            return "MEDIUM";
        }

        return "LOW";
    }
}