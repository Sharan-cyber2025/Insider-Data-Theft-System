package com.insiderthreat.monitoring;

import com.insiderthreat.model.SecurityEvent;
import com.insiderthreat.model.SecurityEvent.EventType;

import java.util.ArrayList;
import java.util.List;

public class EventMonitor {

    private final List<SecurityEvent> events;

    public EventMonitor() {
        events = new ArrayList<>();
    }

    /**
     * Records a security event.
     */
    public void recordEvent(SecurityEvent event) {

        events.add(event);

        System.out.println("\n[EVENT MONITOR] Security event recorded:");
        System.out.println(event);
    }

    /**
     * Returns all recorded events.
     */
    public List<SecurityEvent> getEvents() {
        return new ArrayList<>(events);
    }

    /**
     * Returns the number of recorded events.
     */
    public int getEventCount() {
        return events.size();
    }

    /**
     * Displays all events currently stored in memory.
     */
    public void displayEvents() {

        System.out.println("\n==============================================");
        System.out.println("              EVENT MONITOR");
        System.out.println("==============================================");

        if (events.isEmpty()) {
            System.out.println("No security events recorded.");
            return;
        }

        for (SecurityEvent event : events) {
            System.out.println(event);
        }

        System.out.println("----------------------------------------------");
        System.out.println("Total Events: " + events.size());
    }

    /**
     * Creates sample security events for system testing.
     */
    public void generateTestEvents() {

        recordEvent(new SecurityEvent(
                "USR-001",
                EventType.LOGIN,
                "Corporate System",
                "WORKSTATION"
        ));

        recordEvent(new SecurityEvent(
                "USR-001",
                EventType.FILE_ACCESS,
                "employee_records.xlsx",
                "WORKSTATION"
        ));

        recordEvent(new SecurityEvent(
                "USR-001",
                EventType.USB_INSERT,
                "USB-001",
                "USB_DEVICE"
        ));

        recordEvent(new SecurityEvent(
                "USR-001",
                EventType.FILE_COPY,
                "confidential.pdf",
                "USB_DEVICE"
        ));
    }
}