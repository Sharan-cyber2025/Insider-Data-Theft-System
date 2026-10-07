# INSIDER DATA THEFT INVESTIGATION SYSTEM (DIGITAL FORENSICS) USING JAVA

## Project Overview

The **Insider Data Theft Investigation System (Digital Forensics) Using Java** is a Java-based cybersecurity and digital forensics prototype developed to identify and analyze potentially suspicious insider activities.

The system monitors security events such as user login, sensitive file access, USB device insertion, and file copying. Individual events are assigned risk scores, while behavioral analysis correlates multiple events to identify suspicious data-exfiltration patterns.

When a high-risk behavioral pattern is detected, the system generates a forensic security decision containing the risk score, threat classification, incident information, correlated event sequence, priority, and recommended investigation action.

> **Note:** The system identifies potential insider-threat activity based on predefined rules and event correlation. It does not automatically prove that actual data theft has occurred.

---

##  Objectives

- Monitor and record security-related events.
- Represent security activities using Java objects.
- Assign risk scores to individual security events.
- Analyze combinations of events using behavioral correlation.
- Identify potentially suspicious insider activity.
- Classify detected activity based on risk level.
- Generate structured forensic investigation information.
- Generate incident identifiers and recommended actions.
- Maintain security audit logs.
- Demonstrate Java-based cybersecurity and digital-forensics concepts.

---

##  Key Features

### 1. Security Event Monitoring

The system records security events including:

- User Login
- File Access
- USB Device Insertion
- File Copy
- File Delete
- USB Device Removal

Each event contains:

- User ID
- Event Type
- Resource
- Source
- Timestamp

---

### 2. Individual Risk Scoring

Each security event is evaluated using a rule-based risk scoring mechanism.

| Security Event | Base Risk |
|---|---:|
| LOGIN | 5 |
| FILE_ACCESS | 10 |
| USB_INSERT | 20 |
| USB_REMOVE | 10 |
| FILE_COPY | 30 |
| FILE_DELETE | 40 |

An additional risk score is applied when the event source is identified as an external USB device.

The final individual event score is limited to a maximum of **100**.

---

### 3. Behavioral Threat Analysis

The system correlates multiple security events rather than analyzing each event independently.

The main demonstrated behavioral pattern is:

```text
LOGIN → FILE ACCESS → USB INSERT → FILE COPY
'''

4. Threat Classification
The behavioral risk score is classified using predefined thresholds:
Score	Classification
0–29	NO SIGNIFICANT THREAT DETECTED
30–59	SUSPICIOUS ACTIVITY
60–79	HIGH-RISK INSIDER ACTIVITY
80–100	POSSIBLE INSIDER DATA THEFT


5. Digital Forensic Investigation
When suspicious behavior is detected, the system generates structured investigation information including:
- Active User
- Incident ID
- Risk Score
- Threat Level
- Event Sequence
- Correlated Pattern
- Detection Result
- Recommended Action
- Investigation Priority
6. Audit Logging
The system records important security decisions in an audit log for later reference.
The audit record contains information such as:
- Detection time
- User ID
- Behavioral score
- Threat result
- Priority
- Recommended action

 System Architecture
                 SECURITY EVENTS
                       │
                       ▼
                EVENT MONITORING
                       │
                       ▼
             INDIVIDUAL RISK SCORING
                       │
                       ▼
             BEHAVIORAL CORRELATION
                       │
                       ▼
              THREAT CLASSIFICATION
                       │
                       ▼
            FORENSIC SECURITY DECISION
                       │
                       ▼
                 INCIDENT ANALYSIS
                       │
                       ▼
             EVIDENCE & AUDIT LOGGING

System Workflow
User/System Activity
        ↓
Security Event Creation
        ↓
Event Monitoring
        ↓
Individual Risk Analysis
        ↓
Behavioral Event Correlation
        ↓
Behavioral Risk Score
        ↓
Threat Classification
        ↓
Forensic Security Decision
        ↓
Incident Analysis
        ↓
Audit Logging

 Technologies Used
- Programming Language: Java
- Development Environment: Visual Studio Code
- Operating System: macOS
- Java APIs: Java Collections API and Java Time API
- Data Structure: List<SecurityEvent>
- Logging: File-based audit logging
- Version Control: Git and GitHub

 Project Structure
Insider-Data-Theft-System/
│
├── data/
│
├── logs/
│   └── security-audit.log
│
├── reports/
│
├── src/
│   ├── main/
│   │   └── java/
│   │       └── com/
│   │           └── insiderthreat/
│   │               ├── analysis/
│   │               │   └── IncidentAnalyzer.java
│   │               │
│   │               ├── audit/
│   │               │   └── AuditLogger.java
│   │               │
│   │               ├── detection/
│   │               │   ├── RiskScoreEngine.java
│   │               │   └── ThreatDetectionEngine.java
│   │               │
│   │               ├── model/
│   │               │   └── SecurityEvent.java
│   │               │
│   │               └── monitoring/
│   │                   └── EventMonitor.java
│   │
│   └── test/
│
├── .gitignore
└── README.md

 How to Run
Prerequisites
Make sure Java is installed on your system.
Check the Java version:
java -version

Check the Java compiler:
javac -version

Clone the Repository
git clone https://github.com/Sharan-cyber2025/Insider-Data-Theft-System.git

Navigate to the project:
cd Insider-Data-Theft-System

Compile the Project
rm -rf out
mkdir -p out
javac -d out $(find src/main/java -name "*.java")

Run the Application
java -cp out com.insiderthreat.Main

 Demonstration Scenario
The current prototype demonstrates a controlled sequence of security events associated with user USR-001.
Event Sequence
1. LOGIN
2. FILE ACCESS
3. USB INSERT
4. FILE COPY

The events are processed by the event monitoring, individual risk analysis, and behavioral threat detection components.
Demonstrated Result
Events Analyzed : 4
Behavior Score  : 100/100
Threat Result   : POSSIBLE INSIDER DATA THEFT
Priority        : CRITICAL
Action          : INITIATE FORENSIC INVESTIGATION

Correlated Pattern
LOGIN → FILE ACCESS → USB INSERT → FILE COPY

Important: The 100/100 value is a behavioral risk score and is not an accuracy percentage.

 Main Java Modules
SecurityEvent
The SecurityEvent class represents an individual security event.
It stores:
- User ID
- Event Type
- Resource
- Source
- Timestamp

EventMonitor
The EventMonitor class records and manages security events during system execution.
It maintains a collection of SecurityEvent objects and provides access to the recorded events.
RiskScoreEngine
The RiskScoreEngine calculates the risk associated with individual security events.
It also classifies individual risk scores into:
- LOW
- MEDIUM
- HIGH
- CRITICAL
ThreatDetectionEngine
The ThreatDetectionEngine performs behavioral analysis by examining combinations of security events.
It identifies suspicious combinations such as:
USB INSERT + FILE COPY

and the complete demonstrated sequence:
LOGIN + FILE ACCESS + USB INSERT + FILE COPY

IncidentAnalyzer
The IncidentAnalyzer generates a structured investigation console containing:
- Incident ID
- Active User
- Risk Score
- Threat Level
- Event Sequence
- Correlated Pattern
- Detection Result
- Recommended Action
AuditLogger
The AuditLogger records important threat-detection decisions in the security audit log for later reference.

 Risk Analysis
The demonstrated scenario produces the following individual event risk scores:
Event	Source	Risk Score	Risk Level
LOGIN	WORKSTATION	5/100	LOW
FILE_ACCESS	WORKSTATION	10/100	LOW
USB_INSERT	USB_DEVICE	50/100	MEDIUM
FILE_COPY	USB_DEVICE	60/100	HIGH


The behavioral analysis combines the relevant activities and produces:
Behavior Score : 100/100
Threat Level   : CRITICAL

The system therefore recommends:
INITIATE FORENSIC INVESTIGATION

 Audit Logging
The system maintains an audit log at:
logs/security-audit.log

A recorded security decision contains information such as:
INSIDER THREAT DETECTION

Detected At    : <timestamp>
User ID        : USR-001
Behavior Score : 100/100
Threat Result  : POSSIBLE INSIDER DATA THEFT
Priority       : CRITICAL
Action         : INITIATE FORENSIC INVESTIGATION

 Limitations
The current implementation is a controlled Java cybersecurity and digital-forensics prototype.
The main limitations are:
- Security events are currently generated in a controlled demonstration scenario.
- Complete real-time operating-system activity monitoring is not implemented.
- Physical USB-device monitoring is not implemented as an operating-system-level detection mechanism.
- Detection is based on predefined rules rather than machine-learning models.
- The number of monitored event types is limited.
- The system identifies potential suspicious activity but cannot independently prove actual data theft.
- Forensic evidence is primarily represented through security-event records and audit logs.
- The current implementation is intended for academic demonstration rather than direct enterprise deployment.

 Future Scope
The system can be extended with:
Real-Time File-System Monitoring
Integration with operating-system file monitoring mechanisms can allow automatic detection of file creation, modification, deletion, and other file activities.
Automated USB Detection
Future versions can integrate operating-system device events to automatically detect USB insertion and removal.
Advanced Behavioral Analysis
More advanced behavioral techniques can be introduced to establish normal user activity patterns and identify deviations.
Persistent Evidence Management
A structured evidence-management mechanism can be developed for storing and retrieving forensic investigation records.
Network and Cloud Activity Monitoring
Future versions can correlate endpoint activities with network transfers and cloud-storage operations.

Security Dashboard
A graphical dashboard can be developed to display:
- Active incidents
- Risk scores
- Event timelines
- Threat classifications
- Investigation status
Enterprise Deployment
The prototype can be further developed into a scalable security monitoring solution suitable for organizational environments.

 Academic Information

Project Title:
INSIDER DATA THEFT INVESTIGATION SYSTEM (DIGITAL FORENSICS) USING JAVA
Course:
Java Programming
Institution:
Chennai Institute of Technology (Autonomous)
Department:
Computer Science and Business Systems
Academic Year:
2026–2027

 Team Members
Name	Register Number
Sharan Prathyusha K.	210425149056
Lekha D.	210425149009


 Project Status
Status: Completed Java PBL Prototype
The current implementation demonstrates:
-  Security Event Monitoring
-  Individual Risk Scoring
-  Behavioral Threat Analysis
-  Event Correlation
-  Threat Classification
-  Forensic Security Decision
-  Incident Analysis
-  Audit Logging

 Disclaimer
This project is an academic cybersecurity and digital-forensics prototype developed for educational and demonstration purposes.
A result such as "POSSIBLE INSIDER DATA THEFT" indicates that the observed event sequence matches the predefined suspicious-behavior rules. It should be treated as an investigation trigger and not as definitive proof of malicious activity.


Developed By
Sharan Prathyusha K.
Lekha D.
Chennai Institute of Technology
Computer Science and Business Systems
