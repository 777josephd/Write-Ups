# Introduction to Phishing

THM SOC Simulator

Scenario objectives
- Monitor and analyze real-time alerts.
- Identify and document critical events such as suspicious emails and attachments.
- Create detailed case reports based on your observations to help your team understand the full scope of alerts and malicious activity.

## First Alert

Diving into the alert queue, we'll select the highest priority alert.

<img width="1703" height="731" alt="ss1" src="https://github.com/user-attachments/assets/c89149ba-300e-4cef-8c80-1336795206ac" />

With context provided by the description of the rule that triggered the alert, we can take the DestinationIP, 67[.]199[.]248[.]11 and plug it into our OSINT tool on the VM.

<img width="747" height="590" alt="ss15" src="https://github.com/user-attachments/assets/10776f7b-1a1e-41c9-808e-0381fe97d0dc" />

With the OSINT tool flagging the IP as malicious, we can confidently assign this alert a True Positive status and submit a formal report.

<img width="1648" height="625" alt="ss2" src="https://github.com/user-attachments/assets/29b0753d-de5d-4b6c-a0d2-457abe84a2b8" />

<img width="1610" height="445" alt="ss16" src="https://github.com/user-attachments/assets/4cf0730a-43d7-46ff-930b-a71359d0c217" />

## Second Alert

Our next alert is Medium severity.

<img width="1656" height="336" alt="ss5" src="https://github.com/user-attachments/assets/60d7a44d-c27b-4b51-a965-9ab78914dd85" />

With context provided by the alert description, we can verify the reputation of the URL embedded in the body of the email with our OSINT tool.

<img width="740" height="597" alt="ss7" src="https://github.com/user-attachments/assets/49c97308-20f5-46b8-b9fe-345373b6456e" />

With no other signs of malicious activity present in the alert, we can move forward with labeling it as a False Positive and submitting a report.

<img width="1615" height="376" alt="ss8" src="https://github.com/user-attachments/assets/628c87df-613c-4b5c-b416-3e127c8b8c4b" />

## Third Alert

Our third alert is another Medium severity.

<img width="1654" height="464" alt="ss9" src="https://github.com/user-attachments/assets/c96447e9-1706-45e0-804e-b2c6bf8fb671" />

From the alert details, we can see obvious signs of an attempted phishing campaign.
The subject contains a notice from Amazon, with a call to action - "Action Required" - and sender urgents@amazon[.]biz.
In the content, we see more common signs of phishing, with an obfuscated bit[.]ly URL and a manufactured sense of urgency.

With this information, we can mark the alert as a True Positive and complete a report.

<img width="1619" height="502" alt="ss10" src="https://github.com/user-attachments/assets/7b561733-f1b1-4e26-80c0-017a92248f32" />

## Fourth Alert

Our final alert, another Medium severity.

<img width="1647" height="505" alt="ss11" src="https://github.com/user-attachments/assets/f14554f8-d9b8-4b9f-84a4-9cd04291b004" />

Again, we can see obvious signs of an attempted phishing campaign.
The sender field contains an address from no-reply@m1crosoftsuppoert[.]co, clear use of the typosquatting technique.
In the content field, we see a call to action regarding an unusual sign-in attempt on a Microsoft account. The embedded address contains the same typosquatted domain, hxxps://m1crosoftsupport[.]co/login.

With this information, we can move forward with a True Positive assignment and report.

<img width="1621" height="472" alt="ss12" src="https://github.com/user-attachments/assets/a6de1a0b-6112-4823-a5e8-63f044cab83f" />










