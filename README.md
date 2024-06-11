# Incident Response in Azure Sentinel Using NIST 800-61
## Introduction
In this project, the aim was to emulate the work of a SOC Analyst. Incident tickets were opened and investigated, and I tried to determine whether the incidents were legitimate. If so, I would either close out the incidents or escalate them as necessary. This process was carried out using the NIST 800-61 as a framework for the incident response process.

Although there was a large volume of brute force attempts generated through the creation of the honeypots, it was rare for them to have a successful login attempt. These higher severity tickets were generated through the use of PowerShell scripts, except for the one Linux brute force success, which was a true positive.

## NIST 800-61 Incident Response Framework
![Screenshot 2023-09-14 222035](https://github.com/Lachiecodes/Azure-Incident-Response/assets/138475757/0c2e01e8-eca0-4630-b737-445c79baaf06)<br>
**Preparation:** This is the foundational stage where we set the stage for incident response success. We create a well-defined incident response plan tailored to our organization's needs. We identify and designate incident response team members with specific roles and responsibilities. We establish communication protocols, both within the team and with external parties like law enforcement or vendors. Additionally, we ensure we have the right tools, technologies, and resources at our disposal, such as forensic software and incident tracking systems.<br>

**Detection and Analysis:** In this phase, we're like digital detectives. We constantly monitor our networks and systems for any unusual or suspicious activities. We use intrusion detection systems, log analysis tools, and security information and event management (SIEM) systems to spot signs of potential incidents. When something looks amiss, we investigate further to understand the nature and scope of the incident. We gather evidence, analyze malware, and determine how the attacker gained access.<br>

**Containment, Eradication, and Recovery:** Once we confirm an incident, our immediate goal is to stop it from spreading and causing more harm. We isolate compromised systems from the network, shut down unauthorized access points, and lock down affected accounts. Simultaneously, we work to eradicate the root cause by removing malware, closing vulnerabilities, and patching systems. Our ultimate aim is to get back to business as usual, so we focus on recovery—restoring data, services, and systems to their pre-incident state.<br>

**Post-Incident Activity and Lessons Learned:** After the dust settles, we don't just move on. We conduct a thorough post-incident analysis. We assess our incident response performance, identifying what we did well and where we can improve. We document lessons learned, update our incident response plan and procedures based on these insights, and ensure that any legal or compliance requirements are met. This phase is all about continuous improvement, so we're better prepared for the next incident.<br>

## Incident 1: Brute Force Success (Windows)
**Step 2: Detection and Analysis**

![Screenshot 2023-09-05 193524](https://github.com/asad6833/Azure-Incident-Response/blob/main/Github.png)

- Incident was triggered on 11/06/2024 at 09:09 pm
- Affected Machine: windows-vm
- Attacker IP: 76.31.73.57 (Richmond, Texas)
- Attacker entity failed 5 previous brute attempts earlier in the day before the final successful attempt.<br>

![Screenshot 2023-09-05 195042](https://github.com/asad6833/Azure-Incident-Response/blob/main/Brute%20Force%20Success.png)<br>

 
- Potentially compromised system ‘windows-vm’ involved in several other incidents/alerts. Possible overexposure to the public internet
- Inspected actions from 76.31.73.57, there were 12 “successes” from the MOVS/Anonymous account but upon further investigation it was found that the alert raised was a false positive created by a service account.<br>

![Screenshot 2023-09-05 201937](https://github.com/Lachiecodes/Azure-Incident-Response/assets/138475757/50661698-24f2-46c3-8a6f-5dc2c2e9c2b3)<br>

  
- After the “successes” the attacker continued brute force attempts at the system, which suggests that they had not gained any significant access to user/admin accounts on the system, such as the “labuser”.<br>

![Screenshot 2023-09-05 201759](https://github.com/Lachiecodes/Azure-Incident-Response/assets/138475757/9d4a604a-4d54-4259-9b4a-b3d92b02c84e)<br>


- Although a false positive was generated, we still have a medium-level issue to resolve since this type of traffic should not be reaching the windows-vm in the first place.
- Closing out the incident as a false positive but will start the process for hardening network security groups.<br>


![Screenshot 2023-09-05 203815](https://github.com/asad6833/Azure-Incident-Response/blob/main/Brute%20Force%20SUCCESS%201.png)


**Step 3: Containment, Eradication, and Recovery**

- I locked down the network security group assigned to the windows-vm and subnet by only allowing traffic from known IP Addresses that I will be accessing the VNet from.
- I enabled MFA for all user accounts on the virtual machine and in Azure AD.
  
## Incident 2: Possible Privilege Escalation (Azure Active Directory)
**Step 2: Detection and Analysis**

![Screenshot 2023-09-05 222944](https://github.com/asad6833/Azure-Incident-Response/blob/main/1.png)<br>

- Incident was triggered on 11/06/2024 at 09:09 pm
- Same user viewed critical credentials several times:

Name - Asad Khan

User Principal Name - asad6833@outlook.com <br>

![Screenshot 2023-09-05 224003](https://github.com/asad6833/Azure-Incident-Response/blob/main/2.png)<br>

- Not only did this user view the critical credentials multiple times, they also are involved in several other incidents, including excessive password resets and global admin role assignment.
- After calling the above user, they confirmed that they were just doing their normal duties, corroborated this with their manager. Closing out for a benign positive.<br>

![Screenshot 2023-09-05 224048](https://github.com/asad6833/Azure-Incident-Response/blob/main/3.png)


  
## Incident 4: Malware Detected
**Step 2: Detection and Analysis**

![Screenshot 2023-09-06 124254](https://github.com/asad6833/Azure-Incident-Response/blob/main/Malware%20Detected.png)<br>


- Incident was triggered on 11/06/2024 at 09:09 pm
- The host machine affected was windows-vm
- Several other security alerts have been associated with this VM.<br>

![Screenshot 2023-09-06 124946](https://github.com/asad6833/Azure-Incident-Response/blob/main/Malware%20Detected%202.png)<br>


- As far as malware goes, this alert was a false positive because it looks like the user was testing with EICAR files.
- Here is the KQL query we used:<br>

![Screenshot 2023-09-06 130223](https://github.com/Lachiecodes/Azure-Incident-Response/assets/138475757/da594683-7305-423c-865c-f257523eddeb)<br>

- Corroborated with the user and user manager to determine if this false positive checks out with them. They confirmed that they were testing the anti-malware software on the machine.
- Closed out the ticket as a false positive.<br>

![Screenshot 2023-09-06 130915](https://github.com/asad6833/Azure-Incident-Response/blob/main/Malware%20Detected%203.png)
