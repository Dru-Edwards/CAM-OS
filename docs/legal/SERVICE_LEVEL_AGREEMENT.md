# Service Level Agreement (SLA)

*Last Updated: May 27, 2025*

## 1. Introduction

This Service Level Agreement ("SLA") forms part of the Terms of Service between Complete Arbitration Mesh ("CAM Protocol", "we", "our", or "us") and the Customer ("you", "your") for the provision of the CAM Protocol services (the "Service").

This SLA describes the levels of service you will receive from us and defines the metrics by which the Service is measured, as well as remedies available to you if we fail to meet these standards.

## 2. Service Commitment

CAM Protocol is committed to providing a reliable, secure, and high-performance service. We aim to deliver:

- **High Availability**: Ensuring the Service is accessible when you need it
- **Low Latency**: Providing rapid response times for API requests
- **Data Durability**: Protecting your data against loss or corruption
- **Timely Support**: Responding to and resolving issues promptly

## 3. Definitions

For the purposes of this SLA, the following definitions apply:

- **Service Credit**: The percentage of the monthly service fees credited to you for a validated claim.
- **Monthly Uptime Percentage**: The total number of minutes in a month, minus the number of minutes of Downtime experienced in a month, divided by the total number of minutes in a month.
- **Downtime**: Any period of time when the Service is unavailable or operating at less than 10% of normal performance.
- **Scheduled Downtime**: Planned maintenance periods announced at least 48 hours in advance.
- **Emergency Maintenance**: Unplanned maintenance necessary to address critical security or performance issues.
- **Response Time**: The time between receipt of a support request and the initial response from our support team.
- **Resolution Time**: The time between receipt of a support request and the implementation of a solution or workaround.

## 4. Service Level Objectives

### 4.1 Service Availability

| Service Tier | Monthly Uptime Commitment | Measurement Period |
|--------------|---------------------------|-------------------|
| Enterprise | 99.99% | Monthly |
| Business | 99.9% | Monthly |
| Developer | 99.5% | Monthly |

Calculation: (Total Minutes in Month - Downtime Minutes) / Total Minutes in Month × 100

Exclusions:
- Scheduled Downtime
- Emergency Maintenance (limited to 4 hours per month)
- Force Majeure events
- Issues resulting from Customer's applications, equipment, or actions

### 4.2 API Response Time

| Service Tier | Average Response Time | 95th Percentile Response Time |
|--------------|------------------------|-------------------------------|
| Enterprise | < 200ms | < 500ms |
| Business | < 300ms | < 750ms |
| Developer | < 500ms | < 1000ms |

Measurement: Response time is measured from when the API gateway receives a request until it begins sending the response.

### 4.3 Error Rate

| Service Tier | Maximum Error Rate |
|--------------|-------------------|
| Enterprise | < 0.1% |
| Business | < 0.5% |
| Developer | < 1.0% |

Calculation: (Number of Failed Requests / Total Requests) × 100

A failed request is defined as any request that returns a 5xx HTTP status code, except when caused by:
- Customer's inputs or configurations
- Exceeding rate limits
- Third-party service failures

### 4.4 Support Response Times

| Severity Level | Description | Enterprise Response | Business Response | Developer Response |
|----------------|-------------|---------------------|-------------------|-------------------|
| Critical | Service unavailable or severely impacted | 30 minutes (24/7) | 1 hour (24/7) | 4 hours (business hours) |
| High | Service degraded or major feature unavailable | 2 hours (24/7) | 4 hours (24/7) | 8 hours (business hours) |
| Medium | Non-critical feature unavailable or not functioning correctly | 4 hours (business hours) | 8 hours (business hours) | 1 business day |
| Low | General questions, feature requests, minor bugs | 1 business day | 2 business days | 3 business days |

Business hours: Monday-Friday, 9:00 AM to 6:00 PM Pacific Time, excluding holidays.

## 5. Monitoring and Reporting

### 5.1 Service Status Page

We maintain a public status page at status.cam-protocol.com that provides:
- Current service status
- Historical uptime
- Scheduled maintenance notifications
- Incident history and post-mortems

### 5.2 Service Metrics Dashboard

Enterprise and Business customers have access to a real-time metrics dashboard showing:
- API response times
- Error rates
- Request volumes
- Service availability

### 5.3 Monthly Service Reports

Enterprise customers receive monthly service reports detailing:
- Service performance against SLAs
- Incident summaries
- Upcoming maintenance
- Capacity planning recommendations

## 6. Service Credits

### 6.1 Credit Schedule for Availability

| Monthly Uptime Percentage | Enterprise Credit | Business Credit | Developer Credit |
|---------------------------|-------------------|-----------------|------------------|
| < 99.99% but ≥ 99.9% | 10% | 0% | 0% |
| < 99.9% but ≥ 99.5% | 25% | 10% | 0% |
| < 99.5% but ≥ 99.0% | 50% | 25% | 10% |
| < 99.0% | 100% | 50% | 25% |

### 6.2 Credit Schedule for API Response Time

If the monthly 95th percentile response time exceeds the committed level:

| Service Tier | Credit |
|--------------|--------|
| Enterprise | 10% |
| Business | 5% |
| Developer | 0% |

### 6.3 Credit Schedule for Error Rate

If the monthly error rate exceeds the committed level:

| Service Tier | Credit |
|--------------|--------|
| Enterprise | 10% |
| Business | 5% |
| Developer | 0% |

### 6.4 Credit Schedule for Support Response Time

If we fail to meet the support response time for Critical or High severity issues:

| Service Tier | Credit |
|--------------|--------|
| Enterprise | 5% per incident |
| Business | 2% per incident |
| Developer | 0% |

### 6.5 Maximum Monthly Credit

The maximum Service Credit for any monthly billing period is:
- Enterprise: 100% of monthly fees
- Business: 50% of monthly fees
- Developer: 25% of monthly fees

## 7. Credit Request and Payment Process

### 7.1 Credit Request Process

To receive a Service Credit, you must submit a claim by:
- Emailing support@cam-protocol.com with "SLA Credit Request" in the subject line
- Including dates and times of the incident
- Including logs or other evidence of the service disruption

### 7.2 Credit Request Deadline

Credit requests must be submitted within 30 days of the end of the month in which the SLA violation occurred.

### 7.3 Credit Evaluation

We will evaluate all properly submitted claims and respond within 30 days.

### 7.4 Credit Application

Approved credits will be applied to your next billing cycle.

## 8. Limitations and Exclusions

### 8.1 SLA Exclusions

This SLA does not apply to:
- Free or trial services
- Preview, beta, or early access features
- Issues resulting from Customer's equipment, software, or network connections
- Force Majeure events
- Suspensions or terminations in accordance with the Terms of Service
- Scheduled Downtime or Emergency Maintenance

### 8.2 Sole Remedy

Service Credits are your sole and exclusive remedy for any failure to meet the SLAs outlined in this document.

## 9. Changes to SLA

We may update this SLA from time to time. We will provide at least 30 days' notice for any changes that reduce service levels or remedies. The current version of this SLA will always be available at cam-protocol.com/legal/sla.

## 10. Disaster Recovery and Business Continuity

### 10.1 Disaster Recovery

Our disaster recovery capabilities include:
- Multi-region data replication
- Regular backups with 30-day retention
- Recovery Time Objective (RTO) of 4 hours for Enterprise customers
- Recovery Point Objective (RPO) of 15 minutes for Enterprise customers

### 10.2 Business Continuity

Our business continuity measures include:
- Redundant infrastructure across multiple availability zones
- Automated failover capabilities
- Regular disaster recovery testing
- 24/7 operations team

## 11. Technical Support

### 11.1 Support Channels

We provide technical support through the following channels:
- Email: support@cam-protocol.com
- Support portal: support.cam-protocol.com
- Phone support (Enterprise customers only): +1-800-CAM-SUPP

### 11.2 Support Hours

| Service Tier | Support Hours |
|--------------|---------------|
| Enterprise | 24/7/365 |
| Business | 24/7 for Critical and High severity issues; Business hours for Medium and Low |
| Developer | Business hours only |

### 11.3 Escalation Process

For Enterprise customers, we provide an escalation path for critical issues:
- Level 1: Support Engineer (initial response)
- Level 2: Senior Support Engineer (technical escalation)
- Level 3: Engineering Team (product escalation)
- Level 4: Executive Escalation (management attention)

## 12. Service Maintenance

### 12.1 Scheduled Maintenance

We perform scheduled maintenance during the following windows:
- Primary: Sundays, 2:00 AM to 6:00 AM Pacific Time
- Secondary: Wednesdays, 10:00 PM to 2:00 AM Pacific Time

Notification will be provided at least 48 hours in advance through:
- Email notification
- Status page updates
- In-app notifications

### 12.2 Emergency Maintenance

Emergency maintenance may be performed as needed to address critical security or performance issues. We will make reasonable efforts to notify customers in advance.

## 13. Security and Compliance

### 13.1 Security Measures

We implement and maintain industry-standard security measures, including:
- Encryption of data in transit and at rest
- Regular security assessments and penetration testing
- Access controls and authentication
- Security monitoring and incident response

### 13.2 Compliance Certifications

We maintain the following compliance certifications:
- SOC 2 Type II
- ISO 27001
- GDPR compliance

### 13.3 Security Incident Notification

We will notify you of security incidents affecting your data within:
- Enterprise: 24 hours
- Business: 48 hours
- Developer: 72 hours

## 14. Data Management

### 14.1 Data Backup

We perform regular backups of customer data with the following retention:
- Enterprise: Daily backups with 30-day retention
- Business: Daily backups with 14-day retention
- Developer: Weekly backups with 7-day retention

### 14.2 Data Portability

Upon request, we will provide exports of your data in a machine-readable format within:
- Enterprise: 3 business days
- Business: 5 business days
- Developer: 10 business days

## 15. Service Termination

### 15.1 Data Retention After Termination

Following termination of the Service:
- Enterprise: Data retained for 30 days
- Business: Data retained for 14 days
- Developer: Data retained for 7 days

### 15.2 Data Deletion

After the retention period, all customer data will be permanently deleted from our systems.

## 16. Contact Information

For questions about this SLA, please contact:
- Email: legal@cam-protocol.com
- Address: 123 Tech Plaza, Suite 400, San Francisco, CA 94103, USA

---

**Signed for and on behalf of CAM Protocol:**

Name: ________________________
Position: ______________________
Date: _________________________
Signature: _____________________

**Signed for and on behalf of the Customer:**

Name: ________________________
Position: ______________________
Date: _________________________
Signature: _____________________
