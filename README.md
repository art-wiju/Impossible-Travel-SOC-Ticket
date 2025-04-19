# Incident Response: Impossible Travel and Account Compromise Investigation

## 🔍 Detection and Analysis

To detect signs of impossible travel, I used the following KQL query. It identifies accounts with logins from more than two different geographic locations within the past seven days:

```kql
let TimePeriodThreshold = timespan(7d);
let NumberOfDifferentLocationsAllowed = 2;
SigninLogs
| where TimeGenerated > ago(TimePeriodThreshold)
| summarize Count = count() by UserPrincipalName, UserId, City = tostring(parse_json(LocationDetails).city), State = tostring(parse_json(LocationDetails).state), Country = tostring(parse_json(LocationDetails).countryOrRegion)
| project UserPrincipalName, UserId, City, State, Country
| summarize PotentialImpossibleTravelInstances = count() by UserPrincipalName, UserId
| where PotentialImpossibleTravelInstances > NumberOfDifferentLocationsAllowed
```

At least ten accounts were flagged for potential impossible travel. One of them belonged to a high-privilege admin account, which required deeper investigation.

![image](https://github.com/user-attachments/assets/0fe68167-d33f-4f32-9783-ec9be0f358c7)


### 👩‍💼 Admin Account Investigation

Using the following query, I verified the admin account’s login activity:

```kql
SigninLogs
| where TimeGenerated > ago(7d)
| where UserPrincipalName == "arisa_admin@company.com"
| project TimeGenerated, City = tostring(LocationDetails.city), State = tostring(LocationDetails.state), Country = tostring(LocationDetails.countryOrRegion)
| order by TimeGenerated desc
```

All login activity for this account came from Japan. After cross-referencing timestamps and city data, the travel patterns appeared normal—likely facilitated by the high-speed bullet train system. No concerns were noted for this account.

![image](https://github.com/user-attachments/assets/34fcae3e-002a-4655-9c6a-2150596bdad6)


### 📋 Other Account Review

I then verified the other flagged accounts:

```kql
let UserList = dynamic([
    "5d3abe0e@company.com",
    "61427a@company.com",
    "b1a10@company.com",
    "a9d97@company.com",
    "224bd@company.com",
    "9918a@company.com",
    "8a8d6@company.com",
    "e29bb@company.com",
    "ba027@company.com"
]);
SigninLogs
| where UserPrincipalName in (UserList)
| where TimeGenerated > ago(7d)
| project TimeGenerated, City = tostring(LocationDetails.city), State = tostring(LocationDetails.state), Country = tostring(LocationDetails.countryOrRegion)
| order by TimeGenerated desc
```

All accounts showed normal login activity, except `a9d97@company.com`. This account typically logs in from New York, but also showed a successful login from Lagos, Nigeria, within one minute of the New York login—an example of impossible travel.

To investigate further:

```kql
SigninLogs
| where UserPrincipalName == 'a9d97@company.com'
| where LocationDetails.city == "Lagos"
```

A successful login was identified from IP `197.210.227.113` on `2025-04-11T21:20:23Z`. This IP has been flagged multiple times for port scanning, brute-force attacks, and other malicious behavior. Cisco Talos classified it as a spam source, and VirusTotal confirmed known IoCs associated with it.

AbuseIPDB:

![image](https://github.com/user-attachments/assets/160ee0cc-d7dc-48c6-839f-4953ec22db26)


![image](https://github.com/user-attachments/assets/8986c8e8-bade-4e8d-97ea-db0a053ba176)

Cisco Talos:

![image](https://github.com/user-attachments/assets/75303f9d-1455-4ded-8ed8-7d404b38536e)

VirusTotal:

![image](https://github.com/user-attachments/assets/984616a9-3cf3-425b-b831-9668a69150ce)



### 🔎 Root Cause Investigation

To understand how the attacker may have gained access, I examined activity tied to this account around the time of the breach. An earlier login came from another malicious IP address (`102.90.98.56`), suggesting a prior compromise via a VM:

```kql
let Timespan = datetime('2025-04-11T21:20:23.317017Z');
AzureActivity
| where TimeGenerated >= Timespan - 7d and TimeGenerated <= Timespan + 7d
| where tostring(parse_json(Claims)["http://schemas.microsoft.com/identity/claims/objectidentifier"]) == "306889"
| where parse_json(HTTPRequest).clientIpAddress == "102.90.98.56"
```

![image](https://github.com/user-attachments/assets/07b9fbad-3da4-44ae-a676-fabf20c271dd)

This query revealed that the attacker started an existing VM associated with this user.

## 🧯 Containment, Eradication, and Recovery

- Disabled the compromised account in Microsoft Entra ID (formerly Azure AD).
- Forced a password reset and notified the user.
- Verified account activity originating from the compromised account to check for unusual or unauthorized activity.
- User admitted the password may have been reused from another website—strongly suggesting credential stuffing.
- The user’s assigned workstation was isolated and re-imaged.
- A forensic image was collected for further analysis to rule out persistence mechanisms (e.g., scheduled tasks, registry modifications).
- 🚫 Added a firewall rule to block known malicious IPs (`197.210.227.113` and `102.90.98.56`) across the entire environment.


![image](https://github.com/user-attachments/assets/68d45e11-e094-4689-93ff-64854fb1af58)

![image](https://github.com/user-attachments/assets/6b50b3e3-b1cb-4174-856b-a624e345877a)


## 🧠 Post-Incident Recommendations

To prevent future incidents:

- Implement geo-fencing for expected login regions; block or alert on access attempts from countries without employee presence.
- Create exceptions for known travel scenarios by employees.
- Continue to monitor sign-in activity across high-privilege accounts.

This case highlights how even a single credential compromise can potentially escalate into network-wide risks if not detected and mitigated promptly.

