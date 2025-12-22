# Network Traffic Analysis using Tcpdump

## Overview
This project demonstrates how network traffic can be captured and analyzed using tcpdump, highlighting the security risks of HTTP and the protection offered by HTTPS.

## Objectives
- Capture live network traffic
- Analyze HTTP packets for exposed credentials
- Compare HTTP and HTTPS data confidentiality
- Understand protocol-level security risks

## Tools Used
- Kali Linux
- Tcpdump
- Linux terminal utilities (grep)

## Methodology
1. Identified active network interface using `ip a`
2. Captured HTTP traffic during a login attempt
3. Extracted plaintext credentials from HTTP packets
4. Captured HTTPS traffic during login
5. Verified encryption by searching for credentials

## Results
- HTTP traffic exposed usernames and passwords in plaintext
- HTTPS traffic encrypted all sensitive data
- Demonstrates the importance of encrypted communication

## Conclusion
Unencrypted protocols such as HTTP are vulnerable to packet sniffing attacks. HTTPS effectively protects user data through encryption and should always be used for sensitive communications.

## Disclaimer
This project was conducted in a controlled environment for educational purposes only.
