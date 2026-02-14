# Hunting an APT with Splunk

```
Notes taken in Obsidian, formatting may be inconsistent.
```

A hands-on workshop designed to provide a deeper dive into a (fictional) nation-state APT.
This workshop leverages #Splunk and Enterprise Security and uses the #Lockheed_Martin_Kill_Chain and #MITRE_ATTACK to contextualize a hunt.

Initial access of the victim's system is the primary focus in this workshop.
All hunts in this workshop series leverage the popular Boss of the SOC (BOTS) dataset.

## Navigating the Data

A common question: what kind of data do we have?

A few techniques to determine what kind of events exist:
 - Data summary
 Most well known method

 - `metadata` command can search within an index. One caveat, time values are returned in EPOCH. To formalize for reporting, utilize `eval` to change formatting to desired layout.

*Implementation*

Under Statistics, the following query can show us the most relevant sourcetypes in this investigation.

<img width="1907" height="982" alt="screenshot1" src="https://github.com/user-attachments/assets/5ae92493-85ca-47c4-807a-29d1afc7f249" />


Adding the time string formatting, the query and output looks like this:

<img width="1907" height="974" alt="screenshot2" src="https://github.com/user-attachments/assets/3a86d257-91c5-4d2c-9a1b-811165167556" />


Adjusting our context, we move to Enterprise Security to see enumerated assets and identities.

`Apps>Enterprise Security`
`Security Domains>Identity>Asset Center`

The Asset Center shows us all systems part of the asset and identity framework.

<img width="1905" height="954" alt="screenshot3" src="https://github.com/user-attachments/assets/7abdbbbe-65fa-4175-ab52-0c593ae193bf" />


We can also observe the identity center using the same method.

`Security Domains>Identity>Identity Center`

<img width="1904" height="1121" alt="screenshot4" src="https://github.com/user-attachments/assets/dc4dded3-f3eb-4187-931b-f50bfa368ff1" />


The Network Diagram can show us connections and associations between systems.
We have a link to the Frothly environment's Network Diagram from the Enterprise Security navigation bar.

<img width="1484" height="847" alt="frothly-environment-image" src="https://github.com/user-attachments/assets/bc1d802c-6624-48fb-9c2d-373d9e28819d" />


This information, along with the information in the Asset and Identity Center dashboards will be critical to the investigation.

## Setting the Scene

We are responsible for defending an organization, Frothly.
The FBI has notified our CEO of an East Asian APT which targeted their organization.

We are tasked with investigating the adversary's actions.

# APT Scenario

## Spearphishing

### Hypothesis

We will be hunting for the following MITRE ATT&CK technique and sub-technique: `T1566.001`
#Phishing_Spearphishing_Attachment

How might we confirm or refute our hypothesis?

#QUESTIONS_TO_ASK

 - What data sources (sourcetypes) should we look for mail traffic in?
 - If we are hypothesizing about email attachments, do we have visibility into what email attachments are being received?
 - Are there specific kinds of attachments that we should be hunting for?
 - If we find attachments of interest, what attributes are associated with it? (Sender, recipient, subject, message, etc.)
 - Do we see those attributes in other emails?
 - Are there prior spearphishing attempts that were unsuccessful that can be leveraged?
 - Focus on a relevant time frame and tighten from there.

### Mail Attachments
#### Attack Vector

Delivery of a specific file is unlikely to be caught unless the attacker is sloppy, we have optimal threat intel, or we've worked back through other parts of the Kill Chain.

If we have captured other indicators, or if we know the victims and targets, we can use this acquired knowledge to hunt.

We begin by looking at mail attachments delivered via SMTP.

*Brief troubleshooting notes:*
Field filter `attach_filename{}` was not available as a selection.
This was solved by first verifying the field existed.
First, I checked `Apps>Manage Apps>Splunk Stream` and confirmed its existence.
Next, in the Search bar, I entered the following query to confirm existence of relevant output.

>index=botsv2 sourcetype=stream:smtp
>| stats count by attach_filename{}

This query provided output relevant to the investigation, so with another manual entry query, I am able to pull the field from the fields filter.

>index=botsv2 sourcetype=stream:smtp attach_filename{}=*

*ALSO NOTE:*
This can be troubleshot more easily via `more fields` and selecting `Coverage>All fields`

Continuing...

We can now reference email attachments as a starting point.

<img width="1184" height="846" alt="screenshot5" src="https://github.com/user-attachments/assets/01b28d5d-ab1c-4590-ad9e-9c57e942b4f9" />


#### Narrowing Time

We also know adversary activity began around August 23rd.
Therefore, if a phishing technique was used, it would have had to been delivered *before* August 23rd.
We can now hypothesize further, judging the filetypes found in `attach_filename{}` and deciding which are most interesting.
We begin with the .zip extension.

<img width="980" height="693" alt="screenshot6" src="https://github.com/user-attachments/assets/5bb45eee-65d4-42f7-8aaf-4b2d598c225c" />


#### Focus on a Specific File

Now, we have 4 events within the relevant time frame and pertaining to our file of interest.
We can investigate further and validate or invalidate our hypothesis.

### Mail Attributes

With our refined search, we can begin to identify additional attributes and contextual clues to improve our context.
We want to know *WHO* the sender is, not the name, but the #Originator .
*WHO* the email was destined for.
Attachment name and size.
The time it was received.
The subject and the body.

#### Reviewing Contextual Clues

Looking at `src_ip`, we can see multiple different servers, but all within the same /16 subnet block.

<img width="600" height="330" alt="screenshot7" src="https://github.com/user-attachments/assets/dd1a6e6e-6329-4f76-b1f9-fccb6a5aec97" />


Investigating further, we see all 4 instances that share the same file, `Invoice.zip`, also share the same `sender` and `subject` fields.

<img width="600" height="249" alt="screenshot8" src="https://github.com/user-attachments/assets/291a8366-7315-4c94-ae9c-7e6bde8ac7ab" />
<img width="600" height="249" alt="screenshot9" src="https://github.com/user-attachments/assets/1ca5ada4-cc3c-41ce-952f-72ee2cae58df" />


This file was sent to 4 different recipients.

<img width="600" height="330" alt="screenshot10" src="https://github.com/user-attachments/assets/4eeaef73-d3c5-49b9-88ce-e2023a1b32bd" />


From our overall context, we know at least 2 of these recipients have been impacted by the adversarial activity.
This gives us confidence that this is the malicious file we are searching for.

Looking at `file_size`, `attach_content_md5_hash{}`, `attach_content_decoded_md5_hash{}`, we can verify that the size of the attachment and its associated hashes are all identical.

<img width="600" height="301" alt="screenshot11" src="https://github.com/user-attachments/assets/b44aaf2b-130e-44bb-b9bb-9ae7d22f9bd2" />
<img width="600" height="249" alt="screenshot12" src="https://github.com/user-attachments/assets/8a392cc2-3582-4ab6-820c-3ee059caabdc" />
<img width="600" height="249" alt="screenshot13" src="https://github.com/user-attachments/assets/c34c4e6f-595b-4760-8ffc-3f6c98dfc8c9" />


We are confident all 4 recipients received the same file by name, size, and hash.

Observing the `attach_type{}` field, we see `application/octet-stream`.

<img width="600" height="249" alt="screenshot14" src="https://github.com/user-attachments/assets/71f36b3f-809a-43c9-8bc0-cbadb930a034" />


Researching #application/octet-stream, we arrive at StackOverflow (https://stackoverflow.com/questions/20508788/do-i-need-content-type-application-octet-stream-for-file-download) and are pointed in the direction of RFC 2046, section 4.5.1 (https://www.ietf.org/rfc/rfc2046#section-4.5.1)
Both of these resources confirm `application/octet-stream` is defined as *"arbitrary binary data"*.

Looking at other filter fields, we investigate the content field. Here, we are met with encoded output. Utilizing #CyberChef and the `magic` operation, the first portion of encoded content is decoded and displays #PK followed by raw binary data, indicative of a ZIP archive.

<img width="1836" height="910" alt="screenshot15" src="https://github.com/user-attachments/assets/c047e908-6d45-43cb-809b-e9381b0b0d87" />
<img width="1534" height="614" alt="screenshot16" src="https://github.com/user-attachments/assets/f1222cdd-2160-4829-98c6-4bebbdd40b7a" />


*Note: I realize after attempting to decode another portion of content, I am hitting a dead-end. I revert back to the main page and manually open the `content` field, and am met with readable output.

<img width="1627" height="868" alt="screenshot17" src="https://github.com/user-attachments/assets/60aef7fe-09d9-45ab-b2e5-fd0d833936e7" />


Within this block, we can now observe the sender's IP address.

<img width="570" height="185" alt="screenshot18" src="https://github.com/user-attachments/assets/99b5f6a7-a95c-4d7b-86a9-747d3a10b0d4" />


Using the following query and regex pattern, we can confirm this field exists for all 4 events of interest.

<img width="885" height="719" alt="screenshot19" src="https://github.com/user-attachments/assets/d30cbbe4-0ea1-4370-9be6-6d9adb77c902" />


We can also inspect the `content_body` and reveal that the body of the email is identical across all 4 instances.

<img width="567" height="285" alt="screenshot20" src="https://github.com/user-attachments/assets/7a4257b1-c524-4b9f-b71c-be7f4d48af65" />


### OSINT

Brief OSINT is conducted and we discover the attacker leveraged a non-malicious email distribution site in order to target the victims.

Sites used for OSINT:
	- www.whois.com
	- www.iplocation.net/ip-lookup

`MITRE T1583.006` sub-technique details adversarial acquisition of infrastructure, specifically web services.

Unfortunately, OSINT does not reveal any information valuable to the investigation.

### Mail Sender

We can investigate our known sender and see if they have any separate interactions with our organization.
With the following query, we specify our sender by name and email address used, organizing the output by `table` and fields of interest.

<img width="1848" height="496" alt="screenshot21" src="https://github.com/user-attachments/assets/10be67b0-eeba-4770-97f3-ed75a8ca4ed3" />


Here we can see our recipients receiving the same 4 subjects.
Investigating one of the logs containing the `Malware Alert Text.txt` file, we can inspect the `content` field and find an encoded string, which we can then plug into #CyberChef 

<img width="603" height="368" alt="screenshot23" src="https://github.com/user-attachments/assets/00e46302-f16d-4905-9598-295ffcb1e5e9" />
<img width="1274" height="614" alt="screenshot22" src="https://github.com/user-attachments/assets/9471589f-d3d0-4727-93a7-738efe07d209" />


This output reveals that the file was removed due to its detection as a #Trojan.

Comparing the successful and unsuccessful attempts, we confirm our suspicions about the sender.

<img width="1619" height="952" alt="screenshot24" src="https://github.com/user-attachments/assets/39abf4ef-9bea-4ccc-9af2-74dc933171d0" />


Plugging the MD5 hash into #VirusTotal, we see that the file has no detections, but was recently submitted for analysis.
This can mean that the file was tested until passed as clean before being deployed to our victims.

<img width="1908" height="489" alt="screenshot25" src="https://github.com/user-attachments/assets/38f91de1-e7a3-4aeb-8a7b-84e1b478f28c" />


### Lessons Learned

We now say Frothly was likely the victim of a phishing campaign.
We can see the same 4 recipients received emails from the same sender within close time proximity on two different occasions.

- First time resulted in malware detection of #Trojan 
- Second time did not trigger any detection alerts

Both attacks shared identical metadata and were sent from a commercial service.
OSINT did not provide additional corroboration.

To confirm this, we must continue the hunt.

##### What do we know now:
- Phishing was attempted twice
		First attempt was unsuccessful
		Second attempt was successful
- Sender IP is 185[.]83[.]51[.]21
- Sender name is Jim Smith <jsmith @ urinalysis[.]com>
- Phishing targeted the same 4 recipients both times
- Subject in the phishing email was `Invoice`
- Body was identical across all 4 emails
- Emails sent in close proximity but individually
- Attachment was the same size for each recipient

#### How do we operationalize?
- Apply watchlisting of domain to monitor future phishing attempts
- Apply alerting to sender IP
		We must consider if this will inhibit any business processes
- Automate analysis of hash values to look at threat intel to gain insight into crowdsourcing threat intel for attachments
- Develop analytics to alert on attachments that come in externally to multiple recipients that have the same filename/size.

## User Execution

With the discovery of a spearphishing attachment, the logical next step is to hunt for the execution of that file.
We have confidence and context to serve as a starting point to work with.

`MITRE T1204.002` sub-technique, user execution of a malicious file, claims that with the confirmation of the spearphishing hypothesis, it makes sense to investigate for file execution.

How might we confirm or refute our hypothesis?

#QUESTIONS_TO_ASK 

- What data sources (sourcetypes) should execution of files include?
- Should we be looking for file executions before or after spearphishing attachments may have been received?
- What kind of supporting information is found in events when a file execution occurs?
- What other indicators do we have to start looking for user execution?
		In this case, we know the attachment, `invoice.zip` was received.
- What system did the execution occur on?
- What was the username that executed the file?
- What happened upon execution of a file?

### File Execution

From our previous investigation progress, we know that invoice.zip was present in SMTP traffic.
We can filter to look outside of SMTP traffic with the following query:

`index=botsv2 sourcetype!=stream:smtp invoice.zip`

Now, we can see it referenced in `Sysmon`, `WinHostMon`, `WinRegistry`, and `wineventlog`.

<img width="600" height="330" alt="screenshot26" src="https://github.com/user-attachments/assets/23f39bf7-3b8d-4c08-8175-3370de30d301" />


We can also see there is 1 host filtered for, `wrk-btun`

<img width="600" height="249" alt="screenshot27" src="https://github.com/user-attachments/assets/2a3fdfd9-6f56-4840-a13f-5fb9bf42e795" />


Focusing on Windows Registry and Event Logs, we can see `WINWORD.EXE` and opening `invoice.doc` from within `\Temp1_invoice.zip\`

<img width="1729" height="814" alt="screenshot28" src="https://github.com/user-attachments/assets/9c105fa2-c805-4659-b7e3-33a3824c702f" />


Sysmon shows 2 logs that include the `invoice.zip` file.

<img width="1902" height="662" alt="screenshot29" src="https://github.com/user-attachments/assets/1fc81702-4e8c-417f-ba66-2ba2be10e30c" />


Given that Sysmon shows the same output seen in the other logs:

<img width="1600" height="441" alt="screenshot30" src="https://github.com/user-attachments/assets/00f46570-5405-4f59-870c-f58a855ed146" />


Along with the absence of a #VirusTotal hit, we can assume there is an embedded macro within the doc file.

### Additional Events After Execution

We can pinpoint a time frame by utilizing the Sysmon log time and using that as input in the range filter.
Our adjusted time filter is now:
`08/23/17 20:28:55.000 -- 08/23/17 20:30:00.000`

Our new query string is as follows:
`index=botsv2 host=wrk-btun sourcetype="xmlwineventlog:microsoft-windows-sysmon/operational" | reverse`

After brief observation, we can see a suspicious PowerShell execution command along with encoded input.

<img width="1563" height="990" alt="screenshot31" src="https://github.com/user-attachments/assets/87d22ce4-f4f5-48de-b085-e64bb9cd4606" />


Both of these events map to:

	-`MITRE T1059.001` Command and Scripting Interpreter: PowerShell
	-`MITRE T1132.001` Data Encoding: Standard Encoding

Decoding the PowerShell command in #CyberChef reveals the following output:

<img width="1743" height="896" alt="screenshot32" src="https://github.com/user-attachments/assets/85c6fbb5-e1c6-4e62-b39e-ccd5fd1969b3" />


This is highly suspicious activity, and warrants further investigation.

After further cleaning:

<img width="957" height="283" alt="screenshot33" src="https://github.com/user-attachments/assets/629807ee-2932-4d49-b530-94b03cc02812" />


### Lessons Learned

We were able to trace execution of `invoice.zip` to a specific user.

That user did have encoded PowerShell running on their system immediately after Windows opened `invoice.doc` (extracted from `invoice.zip).

Billy Tun appears to have executed the attachment in `invoice.doc.

`invoice.doc` was extracted from `invoice.zip` that was found in the spearphishing email.

PowerShell was executed after the document was opened.

#### How do we operationalize?

- Monitor for macro execution
- Apply EDR solutions that analyze, log, and potentially block their execution
- Alert when Sysmon or Windows Events code 4688 appears with PowerShell running encoded
		It should be noted, some admins may encode their PowerShell. Use discretion.

