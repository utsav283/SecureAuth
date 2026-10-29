# SecureAuth — Secure Authentication and Network Security Monitoring System

## 1. Project Overview

SecureAuth is a web-based cybersecurity application that combines secure user authentication with basic network security monitoring.

The system is designed to demonstrate practical cybersecurity concepts including password security, multi-factor authentication, session management, login monitoring, audit logging, network scanning, and packet capture.

The project was developed as part of a cybersecurity course project.

---

## 2. Features

### User Authentication
- User registration
- Secure password hashing
- Secure login
- Email-based OTP authentication
- Session management
- Password reset
- Password strength checker

### Security Monitoring
- Login history
- Login attempt monitoring
- Audit logs
- Security dashboard

### Network Security
- Custom Python-based network scanner
- IP and port scanning
- Network packet capture
- Packet protocol information
- Packet capture statistics
- Basic network traffic analysis

---

## 3. Technologies Used

| Technology | Purpose |
|---|---|
| HTML | Web page structure |
| CSS | User interface styling |
| JavaScript | Client-side functionality |
| PHP | Backend application |
| MySQL | Database management |
| Python | Network security tools |
| Scapy | Packet capture and analysis |
| PHPMailer | Email OTP delivery |
| Composer | PHP dependency management |
| XAMPP | Local Apache and MySQL environment |
| Npcap | Network packet capture support |
| Visual Studio Code | Development environment |

---

## 4. Project Structure

```text
Cybersecurity-Project/
│
├── dashboard.php
├── login.php
├── register.php
├── 2fa-verify.php
├── forgot-password.php
├── reset-password.php
├── password-checker.php
├── network-scanner.php
├── packet-capture.php
├── logout.php
├── db.php
├── email-config.php
│
├── network_scanner.py
├── packet_capture.py
│
├── scan_results.json
├── packet_results.json
├── packet_capture.pcap
│
├── composer.json
├── composer.lock
├── vendor/
│
└── CSS files
```

> Note: JSON and PCAP files may be generated or updated when the network security features are used.

---

## 5. System Requirements

### Hardware

- Processor: Intel Core i3 or equivalent
- RAM: 4 GB or higher
- Storage: At least 10 GB of available space
- Network connection

### Software

- Windows
- XAMPP
- PHP
- MySQL
- Python 3
- Composer
- Npcap
- Visual Studio Code
- Modern web browser

---

## 6. Installation

### Step 1 — Install XAMPP

Install XAMPP and make sure Apache and MySQL are available.

Place the project inside the XAMPP `htdocs` directory:

```text
C:\xampp\htdocs\Cybersecurity-Project
```

### Step 2 — Start XAMPP

Open the XAMPP Control Panel and start:

```text
Apache
MySQL
```

### Step 3 — Create the Database

Open phpMyAdmin through XAMPP and create the required MySQL database.

Import or create the database tables required by SecureAuth:

- `users`
- `audit_logs`
- `login_attempts`
- `password_resets`

### Step 4 — Configure Database Connection

Update the database connection details in:

```text
db.php
```

Configure the database name, username, password, and host according to the local MySQL installation.

### Step 5 — Install PHP Dependencies

Open a terminal inside the project directory and run:

```bash
composer install
```

This installs the required PHP dependencies, including PHPMailer.

### Step 6 — Configure Email

Update:

```text
email-config.php
```

with the required SMTP configuration.

The system uses Gmail SMTP to send email-based OTP verification codes.

### Step 7 — Configure Python

Make sure Python is installed and available on the system.

Install the required Python package:

```bash
pip install scapy
```

Npcap should also be installed to support packet capture.

---

## 7. Running the Application

After starting Apache and MySQL in XAMPP, open the application in a web browser:

```text
http://localhost/Cybersecurity-Project/
```

The user can then:

1. Create a SecureAuth account.
2. Log in using the registered email and password.
3. Verify the email OTP.
4. Access the security dashboard.
5. View login and audit information.
6. Perform network scanning.
7. Capture network packets.

---

## 8. Network Scanner

The network scanner is implemented using Python.

Users can provide:

- Target IP address
- Starting port
- Ending port

The Python scanner checks the specified target and port range and returns the scan results to the SecureAuth interface.

The scanner is intended for authorized networks and systems only.

---

## 9. Packet Capture

SecureAuth includes a packet capture feature implemented using Python and Scapy.

The capture function collects network packets for a defined period and provides information such as:

- Total packets captured
- Protocol information
- Packet details
- Capture duration
- Capture start time
- Capture end time

The captured packet information can also be stored in a PCAP file for further analysis.

**Important:** Packet capture should only be performed on networks and systems where you have authorization to monitor the traffic.

---

## 10. Security Features

SecureAuth implements several cybersecurity controls:

- Password hashing
- Password strength validation
- Email-based multi-factor authentication
- Session management
- Password reset
- Login attempt monitoring
- Login history
- Audit logging
- Network scanning
- Packet capture and analysis

These features demonstrate how multiple security mechanisms can be combined into a single web-based cybersecurity system.

---

## 11. Database

SecureAuth uses MySQL for storing application and security-related information.

### Users

Stores registered user account information.

### Audit Logs

Stores important security-related activities, including the user, action, description, IP address, and timestamp.

### Login Attempts

Stores login attempt information including the user, email, IP address, attempt time, and whether the attempt was successful.

### Password Resets

Stores password reset information such as the user, email, reset code, expiration time, usage status, and creation time.

---

## 12. Project Objectives

The main objectives of SecureAuth are to:

- Develop a secure web authentication system.
- Protect stored user passwords.
- Implement additional authentication using email OTP.
- Monitor authentication activities.
- Maintain security audit logs.
- Provide a security dashboard.
- Implement a custom network scanner.
- Capture and analyze network packets.
- Demonstrate practical cybersecurity concepts through an integrated application.

---

## 13. Limitations

SecureAuth is an educational cybersecurity project and has some limitations.

- The network monitoring functionality is designed for basic analysis rather than enterprise-level monitoring.
- The packet capture functionality is not intended to replace professional network analysis tools.
- The application is primarily designed for a local development environment.
- Advanced intrusion detection and automated threat response are not included.
- The system does not provide enterprise-level SIEM functionality.

---

## 14. Future Improvements

Possible future improvements include:

- Real-time network monitoring
- Intrusion detection capabilities
- Automated suspicious activity alerts
- More advanced network traffic analysis
- Role-based access control
- Improved rate limiting
- Security notifications
- Graphical network traffic visualization
- Integration with professional security monitoring tools
- Deployment on a production server

---

## 15. Security Notice

This project is intended for **educational and authorized security testing purposes only**.

Network scanning and packet capture should only be performed against systems and networks where permission has been granted.

The developer is not responsible for unauthorized use of the tools included in this project.

---

## 16. Project Status

**Status:** Completed

**Project:** SecureAuth — Secure Authentication and Network Security Monitoring System

**Purpose:** Cybersecurity course project

**Development Environment:** Windows + XAMPP

**Primary Technologies:** PHP, MySQL, Python, HTML, CSS, JavaScript