package com.insiderthreat.model;

import java.time.LocalDateTime;

public class SecurityEvent {

    public enum EventType {
        FILE_COPY,
        FILE_DELETE,
        USB_INSERT,
        USB_REMOVE,
        LOGIN,
        FILE_ACCESS
    }

    private final String userId;
    private final EventType eventType;
    private final String resource;
    private final String source;
    private final LocalDateTime timestamp;

    public SecurityEvent(
            String userId,
            EventType eventType,
            String resource,
            String source) {

        this.userId = userId;
        this.eventType = eventType;
        this.resource = resource;
        this.source = source;
        this.timestamp = LocalDateTime.now();
    }

    public String getUserId() {
        return userId;
    }

    public EventType getEventType() {
        return eventType;
    }

    public String getResource() {
        return resource;
    }

    public String getSource() {
        return source;
    }

    public LocalDateTime getTimestamp() {
        return timestamp;
    }

    @Override
    public String toString() {
        return timestamp +
                " | USER=" + userId +
                " | EVENT=" + eventType +
                " | RESOURCE=" + resource +
                " | SOURCE=" + source;
    }
}