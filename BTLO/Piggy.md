# Piggy Write-Up

Q1: What remote IP address was used to transfer data over SSH?

<img width="1888" height="586" alt="ss1 q1" src="https://github.com/user-attachments/assets/4db1a79b-191d-47d9-b753-ebd2a2d0cb64" />


Q2: How much data was transferred in total?

35[.]211[.]33[.]16 corresponds to the IP used in SSH data transfer, `1131 M`.

<img width="1484" height="684" alt="ss2 q2" src="https://github.com/user-attachments/assets/46c1e1d5-217a-44c7-b9c2-9e0d74f11a0b" />


Q3: Review the IPs the infected system has communicated with. Perform OSINT searches to identify the malware family tied to this infrastructure

Each IP was plugged into VirusTotal respectively and briefly investigated. The corresponding malware family was then identified as `Trickbot`.

<img width="1483" height="686" alt="ss3 q3" src="https://github.com/user-attachments/assets/dae1b240-40fc-466f-86b9-1b8af5d0b46b" />

<img width="685" height="863" alt="ss4 q3" src="https://github.com/user-attachments/assets/da290616-5090-488f-8e60-d9cb93d10510" />


Q4: Review the two IPs that are communicating on an unusual port. What are the two ASN numbers these IPs belong to?

Once again, each IP was investigated, and the ASN providers of highest interest were documented.

<img width="1481" height="684" alt="ss5 q4" src="https://github.com/user-attachments/assets/8b7c9773-3ddc-430b-83e7-8644cdfce891" />

<img width="529" height="168" alt="ss6 q4" src="https://github.com/user-attachments/assets/2f1e1176-4877-49cd-b02f-34fdd8b8a3bf" />

<img width="456" height="166" alt="ss7 q4" src="https://github.com/user-attachments/assets/62136147-7012-48b0-a3f5-e162dff6d637" />


Q5: Perform OSINT checks. What malware category have these IPs been attributed to historically?

AlphaSOC has the malicious IP(s) categorized as `miner`, and with brief investigation, this is corroborated by other submissions.

<img width="1760" height="864" alt="ss8 q5" src="https://github.com/user-attachments/assets/8b296051-9de8-4072-9c59-09a2c7c0608a" />


Q6: What ATT&CK technique is most closely related to this activity?

MITRE ATT&CK ID: `T1496` is the closest match to this activity.

<img width="1440" height="941" alt="ss9 q6" src="https://github.com/user-attachments/assets/0b410e34-0efb-4197-8bba-a570ea80fdb5" />


Q7: Go to View > Time Display Format > Seconds Since Beginning of Capture. How long into the capture was the first TXT record query made? (Use the default time, which is seconds since the packet capture started)



<img width="1918" height="95" alt="ss10 q7" src="https://github.com/user-attachments/assets/f7187d22-3329-4203-ad89-d9e2f2aca719" />


Q8: Go to View > Time Display Format > UTC Date and Time of Day. What is the date and timestamp?

<img width="1916" height="507" alt="ss11 q8" src="https://github.com/user-attachments/assets/4298707d-d255-4bae-ae5f-3f09b0be1018" />


Q9: What is the ATT&CK subtechnique relating to this activity?

MITRE ATT&CK ID: `T1071.004` is the closest match to this activity.

<img width="1411" height="642" alt="ss12 q9" src="https://github.com/user-attachments/assets/a08aa1b6-6b83-4fc5-99ef-02c84f7a3991" />
