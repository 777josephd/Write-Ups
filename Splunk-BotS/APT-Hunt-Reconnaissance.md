# Hunting an APT with Splunk - Reconnaissance

"Threat hunters focus their search on adversaries.. and who are already within the networks and systems of the threat hunters' organization.." - SANS - The Who, What, Where, When, Why and How of Effective Threat Hunting

The assumption we start with when threat hunting, the adversary is already within the organization. We are looking for things that are occurring, but the SIEM, IDS, etc. have not identified.
We are working in a manner that ASSUMES BREACH and to identify signs of this.

MITRE ATT&CK framework builds on Lockheed Martin's Kill Chain, but focuses on tactics and techniques that occur during exploit and activity occurring post-exploit.
# APT Scenario

## User Agents

### Hypothesis

We are going to be looking for an adversary who has gotten sloppy with their tradecraft, and using that sloppiness to learn more about how they are targeting us.

User Agent Strings may provide insight into an adversary that they may not have intended to show.

How might we confirm or refute our hypothesis?

#QUESTIONS_TO_ASK 

- What data sources (sourcetypes) are needed to view user agent strings?
- When were specific user agent strings seen?
- What IP addresses were user agent strings seen from?
- Are any of the user agent strings anomalous? Are there any that are excessively short/long or from systems that would be unexpected?

Focusing on August 2017 and tightening from there.

### User Agents in Splunk

We can begin by searching the `stream:http` sourcetype, which is our web data capture off the wire.
We can look at all web traffic where the site referenced is our corporate site, `www.froth.ly`.
Then we use the stats command to generate a count and group by `http_user_agent`.
Sort the count by largest to smallest.

<img width="1913" height="893" alt="ss1" src="https://github.com/user-attachments/assets/1d611633-925f-40a8-911a-5980043272c7" />


### User Agent OSINT

Investigating our user agent strings, we can use sites like `whatismybrowser.com` and paste the user agent string in.

The largest volume of data comes from the following user agent:
`Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.90 Safari/537.36`
..which #whatismybrowser identifies as Chrome 60 on Mac OS X 10 (Sierra)

We got the OS, browser type, and version all with the user agent string.

We can rinse and repeat through the list.

Eventually, we find a suspicious user agent.

<img width="1106" height="912" alt="ss2" src="https://github.com/user-attachments/assets/142e3faa-e469-4052-9a86-0b9e4e1ad69c" />


The word "Naenara" stands out.
Investigating the software of Naenara 3, we see "ko-KP" and Korean characters.
Depending on who is expected to visit the site, this may or may not be a point of interest.

<img width="1098" height="486" alt="ss3" src="https://github.com/user-attachments/assets/c5463055-b75b-4395-abc5-5f7663153b34" />


A brief Google search reveals Naenara as originating from North Korea.

<img width="660" height="365" alt="ss4" src="https://github.com/user-attachments/assets/fcb4968a-eede-4a88-a4d6-64c92afd3f4d" />


It is also noted that the "ko-KP" code refers specifically to North Korea.

<img width="660" height="315" alt="ss6" src="https://github.com/user-attachments/assets/ea39b105-b674-494e-95d5-68dda5bbee77" />


### Suspicious UA

Now that we've identified a highly-suspicious UA, we can pivot back to Splunk and investigate in depth.
Our query will look like this:
```
index=botsv2 sourcetype=stream:http http_user_agent="Mozilla/5.0 (X11; U; Linux i686; ko-KP; rv: 19.1br) Gecko/20130508 Fedora/1.9.1-2.5.rs3.0 NaenaraBrowser/3.5b4"
| stats count by src dest
```
Utilizing the Statistics tab:

<img width="1909" height="332" alt="ss7" src="https://github.com/user-attachments/assets/d69c328c-5318-4608-929d-82f66511995e" />


We see 3 external IPs using this UA targeting 3 distinct systems at our organization.
After contextualizing assets, we can pivot to `Asset Center` to see our internal IPs in more detail.

<img width="1786" height="855" alt="ss8" src="https://github.com/user-attachments/assets/3135b460-bf71-4652-ab3d-548038f68691" />


Here, we see 172[.]31[.]4[.]249 to be one of our servers, host/DNS name `gacrux`, hosting services like `brewertalk`, `mysql`, etc.
This context will allow us to search for relevant communication paths.

### ASN OSINT

Performing a #whois query, we receive the following information:

<img width="768" height="758" alt="ss9" src="https://github.com/user-attachments/assets/41e3ffdb-f4e7-41f2-9167-130e422abdda" />


Each ISP has one or many ASNs that provide a way to identify networks and their ownership.

Identifying an ASN could help with attribution (*could*).

ASNs can also serve as a method to filter traffic coming to the network.
	If we don't do business in certain regions of the world, why do we want these networks and IPs communicating with our systems?

We can look at RIPE's whois information to ensure it aligns with the information was discovered.

<img width="1158" height="1101" alt="ss10" src="https://github.com/user-attachments/assets/3e3da18d-b490-46d0-bd2a-9fe3ceb75347" />


(*Note, after extensive research, it seems that since 2017, this domain and other ASN-related information, have been passed to different owners than what is expected, given the North Korean UA)

Sites referenced:

```
whois.domaintools.com
apps.db.ripe.net
stat.ripe.net
wq.apnic.net
iana.org/whois
asn.cymru.com/cgi-bin/whois.cgi
```

### Lessons Learned

We can confirm our hypothesis by using UA information.
Reconnaissance was performed ahead of the attack our organization experienced.
User Agent Strings provided a clue as to who might be behind the attack.
Infrastructure used was also identified.

### What Have We Learned

- User Agent String of North Korean origin visited `froth.ly`
	- Mozilla/5.0 (X11; U; Linux i686; ko-KP; rv: 19.1br) Gecko/20130508 Fedora/1.9.1-2.5.rs3.0 NaenaraBrowser/3.5b4
	- This does *not* establish attribution
- IP address the browser came from was 85[.]203[.]47[.]86
- ASN 133752 *owned* that IP address
- Visitor used ExpressVPN in Hong Kong to connect to `froth.ly`
- Two additional IPs, 136[.]0[.]0[.]125 and 136[.]0[.]2[.]138, used this same UA String connecting to `www.brewertalk.com`

### What Can We Operationalize?

Monitor for subsequent User Agent String activity

 - This is a random UA String to be found on a U.S. website
	-Monitoring for this string in certain parts of the world may result in false positives
 - This could have been sloppy tradecraft by an adversary
 - Could yield interesting intelligence regardless

Monitor for IP address / netblock

 - Low effectiveness, adversary can easily change IP
 - Blocking broader #netblock may be a better strategy

Monitor for traffic from certain ASNs

 - This covers a broader set of traffic beyond a single netblock
 - Filter at border or ISP portions of the world that the organization doesn't work or associate with.

## Public Web Visibility

Adversaries will often gather information about their targets ahead of time and attempt to learn as much as possible.

`MITRE T1593`: Search Open Websites/Domains

We can hunt our own websites as "adversaries" to see what publicly available information can be leveraged by possible adversaries.

How might we confirm or refute our hypothesis?

#QUESTIONS_TO_ASK 

 - From an adversary perspective, where can we find information about our target?
	 -SEC Filings
	 -Social Media -- LinkedIn/X/Facebook/etc.
	 -Corporate Websites
	 -Other?

 - Did specific User Agent Strings access company content?
	 -We may find that User Agent String in other hunts

 - What IP addresses accessed company content?
 - What kinds of company information is available from our website and other places to understand more about us?


### File Execution

If we explore our HTTP data,  we can pivot to any interesting fields extracted at search.
`http_content_type` is used to indicate MIME type in the event.

<img width="600" height="431" alt="ss11" src="https://github.com/user-attachments/assets/8a03f43e-c0f1-451e-8533-6dda4d6da302" />
<img width="1041" height="511" alt="ss12" src="https://github.com/user-attachments/assets/718170a2-b53c-4737-b374-c91202f94ddd" />


Focusing on the outlier, we see that `company_contacts.xlsx` was served to `src_ip`: 85[.]203[.]47[.]86 and the NaenaraBrowser UA on 08/05.

<img width="1743" height="924" alt="ss13" src="https://github.com/user-attachments/assets/271d66b6-77e9-4d3b-993f-fcafa4b5b30a" />


We can modify our query further to isolate the suspicious instance.

<img width="1760" height="283" alt="ss14" src="https://github.com/user-attachments/assets/2908dcba-79fd-43b8-936f-be1cf53376a3" />


### Lessons Learned

A browser with a North Korean UA String downloaded a company contacts spreadsheet from the website ahead of the attack.
This information does not mean North Korea is attributed to the attack. Only that the browser originates from there.

`company_contacts.xlsx` was downloaded.
Based on the timestamp, we know this occurred on 08/05.

Depending on file contents, we may be able to monitor potential targets and take a proactive approach.

Since we have the date of the incident, we can scope our investigations to after that date of compromise.

### What Can We Operationalize?

Understand the organization's footprint and visibility to the rest of the world
 - Monitor for key execs who are well-known and visible

Determine if all employees need to have that same level of visibility and if not, monitor for if their information appears out there

Pay special attention to the website and other company assets and minimize OSINT information around employees and computing assets where possible

Seed objects in the organization, including websites, with erroneous information that can then be monitored for
 - Anytime we can deny or deceive the adversary, we are causing them to invest more effort into their attacks
 - This approach has mixed reception
