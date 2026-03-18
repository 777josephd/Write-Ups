# Deep Blue Write-up

Scenario:
A Windows workstation was recently compromised, and evidence suggests it was an attack against internet-facing RDP, then Meterpreter was deployed to conduct 'Actions on Objectives'.
Verify these findings.

You are provided with Security.evtx and System.evtx log exports from the compromised system - analyze these, NOT the Windows logs (when using DeepBlueCLI ensure you're providing the path to these files, stored inside `\Desktop\Investigation\`).

Read: `https://github.com/sans-blue-team/DeepBlueCLI`

From the directory: `C:\Users\BTLOTest\Desktop\Investigation\DeepBlueCLI-master`

Run:
```
.\DeepBlue.ps1 C:\Users\BTLOTest\Desktop\Investigation\Security.evtx
```

Q1: Using DeepBlueCLI, investigate the recovered Security log (Security.evtx). Which user account ran GoogleUpdate.exe?

The user's name is clearly visible from the command path, `Mike Smith`.

<img width="728" height="398" alt="ss1 q1" src="https://github.com/user-attachments/assets/28575099-c135-46fe-bf4d-a331af771d0f" />


Q2: Using DeepBlueCLI investigate the recovered Security.evtx log. At what time is there likely evidence of Meterpreter activity?


<img width="576" height="331" alt="ss2 q2" src="https://github.com/user-attachments/assets/c7f46deb-703c-4f45-879e-772b41098adf" />


Q3: Using DeepBlueCLI investigate the recovered System.evtx log. What is the name of the suspicious service created?

Run:
```
.\DeepBlue.ps1 C:\Users\BTLOTest\Desktop\Investigation\System.evtx
```

<img width="515" height="129" alt="ss3 q3" src="https://github.com/user-attachments/assets/d27d30ac-6709-4216-ba4d-1bea14379080" />


Q4: Investigate the Security.evtx log in Event Viewer. Process creation is being audited (event ID 4688). Identify the malicious executable downloaded that was used to gain a Meterpreter reverse shell, between 10:30 and 10:50 AM on the 10th of April 2021.

Within the `Investigation` folder, open the `Security.evtx` file.

Set `Filter Current Log` to the relevant time frame: 4/10/2021 10:30:00 AM - 4/10/2021 10:50:00 AM with the Event ID field to 4688.

<img width="844" height="812" alt="ss4 q4" src="https://github.com/user-attachments/assets/d5376fd3-a552-403b-9051-3c82ea92846b" />


Q5: It's also believed that an additional account was created to ensure persistence between 11:25 AM and 11:40 AM on the 10th April 2021. What was the command line used to create this account? (Make sure you've found the right account!)

Adjust `Filter Current Log` to the relevant time frame once again: 4/10/2021 11:25:00 AM - 4/10/2021 11:40:00 AM.

<img width="850" height="806" alt="ss5 q5" src="https://github.com/user-attachments/assets/beb97823-a061-4ab6-aa56-89850ee8f168" />


Q6: What two local groups was this new account added to?

<img width="843" height="809" alt="ss6 q6" src="https://github.com/user-attachments/assets/1f4c5e52-0269-4c51-b641-76bf73c1ce4b" />


<img width="847" height="806" alt="ss7 q6" src="https://github.com/user-attachments/assets/5a4769ee-5ac0-43b8-b75e-2477fdb493de" />


