# Splunk Logs and Investigations

In this project I explore a large dataset of over 500,000 events containing many different attacker TTPs using the powerful SIEM tool, [Splunk Enterprise](https://www.splunk.com/en_us/products/splunk-enterprise.html). The goals of this project are to: 

1. Use many of the available Search Processing Language (SPL) tools to craft efficient and complex searches: [Splunk and SPL](#splunk-and-spl)
2. Create effective intrusion detection searches and alerts based on: 
	1. Attacker TTPs and known behavior: [Detecting Attacker TTPs](#detecting-attacker-ttps)
	2. Anomaly detection: [Detecting Attacker Behavior with Anomaly Detection](#detecting-attacker-behavior-with-anomaly-detection)
3. Discover many of the detected elements, methods, processes, etc. of an attack and develop a timeline of how the attacker gained initial access: [Intrusion Detection With Splunk](#intrusion-detection-with-splunk) -> [Finding the Source of the Intrusion](#finding-the-source-of-the-intrusion)

Through this project I have gained a comprehensive understanding of Splunk's architecture, written many detection-related SPL searches, and applied attacker TTPs and analytics for defensive cybersecurity tasks. I am now well prepared to leverage Splunk in real-world log analysis, detection, and incident response scenarios. 
## Table of Contents

- [Splunk and SPL](#splunk-and-spl)
	- [Splunk as a SIEM](#splunk-as-a-siem)
	- [Identify Available Data](#identify-available-data)
	- [Practice Queries](#practice-queries)
- [Splunk Applications - Sysmon](#splunk-applications---sysmon)
- [Intrusion Detection With Splunk](#intrusion-detection-with-splunk)
	- [Search Performance Optimization](#search-performance-optimization)
	- [Using Attacker Mindset](#using-attacker-mindset)
	- [Meaningful Alerts](#meaningful-alerts)
	- [Further Detection Practice](#further-detection-practice)
- [Detecting Attacker TTPs](#detecting-attacker-ttps)
	- [Crafting SPL Searches Based on Known TTPs](#crafting-spl-searches-based-on-known-ttps)
	- [Practice Investigation](#practice-investigation)
- [Detecting Attacker Behavior with Anomaly Detection](#detecting-attacker-behavior-with-anomaly-detection)
	- [SPL Searches Based on Analytics](#spl-searches-based-on-analytics)
	- [Practice Scenario](#practice-scenario)
- [Finding the Source of the Intrusion](#finding-the-source-of-the-intrusion)
	- [Find the process that created remote threads in rundll32.exe](#find-the-process-that-created-remote-threads-in-rundll32exe)
	- [Find the process that started the infection](#find-the-process-that-started-the-infection)

## Splunk and SPL

In this section I will focus on the SIEM capabilities of Splunk and go through its many data analysis tools. I will also use Splunk Processing Language (SPL) to conduct various searches, filters, transformations, and visualizations. 

### Splunk as a SIEM 

To begin creating basic SPL commands, I will use a VM host setup with a Splunk Index named **main** containing Windows Security, Sysmon, and other logs. 

For some starter searches I first query the index for the term "UNKNOWN" using `index=main "UNKNOWN"`:

![](Images/Pasted%20image%2020231114151034.png)

Then I can modify that same query with wildcards to find all occurrences of "UNKNOWN" with any amount of characters before and after it:

![](Images/Pasted%20image%2020231114151417.png)

The wildcards return more results as the search criteria becomes less strict. 

Splunk automatically identifies data fields from the events like source, souretype, host, and EventCode. For example, from the previous search I can see some of the hosts that were found: 

![](Images/Pasted%20image%2020231114153328.png)

Then I can create queries using these data fields combined with comparison operators to filter based on the values found for each data field. With this information, I do a search for all records where the host is "waldo-virtual-machine" using `index="main" host="waldo-virtual-machine"`:

![](Images/Pasted%20image%2020231114153627.png)

Using a pipe "|" I can direct the output of a search into a command, similar to Linux. For the data fields, SPL offers a **fields** command that I can use to remove and add filters from the results. 

With the fields command I conduct a search on all Sysmon events with EventCode 1 but remove the "User" field from the results. This will output all the usual results except the ones where the user initiated the process:

![](Images/Pasted%20image%2020231114155715.png)

Another useful command is **table** which can be used to change the display of the results into a table with the desired columns. 

With the Sysmon EventCode 1 results I create a table that only displays the time, host, and image fields:

![](Images/Pasted%20image%2020231114160243.png)

If I wanted to use a different name for a field then I can use the command **rename** to change it in the results. For example, I can change the Image field to be "Process":

![](Images/Pasted%20image%2020231114160616.png)

![](Images/Pasted%20image%2020231114161104.png)

Another handy command is **dedup** which deletes all duplicate events based on a specified field:

In the last results where I renamed Image to be Process, each value had many counts, but with dedup many of them are filtered out:

![](Images/Pasted%20image%2020231114161411.png)

With the **sort** command I can sort the results in ascending or descending order based on a specified field. Here I sort the results by the time they occurred and in descending order so I can see the most recent results:

![](Images/Pasted%20image%2020231114161715.png)

The **stats** command allows me to compute statistical operations on the results to better organize/visualize it. Using the **count** operation I compile the results to show the number of times that each Image created an event at a certain time:

![](Images/Pasted%20image%2020231114162739.png)

To further expand on the data visualization aspect of SPL, there is the **chart** command that is very similar to **stats** but outputs the results into a table-like data visualization.

I can create a chart with the previous example of taking the count of events that and Image created at a specific time:

![](Images/Pasted%20image%2020231114163336.png)

If I needed to further redefine or create a new field from an existing field I can use **eval**. For example, if I wanted the output of the Image field but in all lower case I could create a new field and set its results to the lower case version of Image. 

`eval Process_Path=lower(Image)` will create a new field called "Process_Path" and uses the lower case function with the Image field as input to set the new field equal to the lower case results of the Image field:

![](Images/Pasted%20image%2020231114164225.png)

I can also extract new fields from existing ones using regular expressions through the **rex** command. 

`[^%](?<guid>{.*})` is a regular expression that: 
- Excludes anything that starts with %
- Creates a named capture group called "guid" that assigns the name to anything in between curly braces and isn't a new line character

This will create a new field called "guid" that I can then use in further commands. Using the new field I will create a table that shows all the extracted data: 

![](Images/Pasted%20image%2020231114171735.png)

Splunk **Lookups** can add to the results of a query by matching fields in the results to fields in lookup files. 

I have created a file called malware_lookup.csv that holds fields matching files to whether or not they are malware. This will act as a lookup table file that I can use with the data to do a lookup on known malicious files. 

![](Images/Pasted%20image%2020231114172240.png)

After adding malware_lookup.csv to the Lookup files in Splunk's settings, I am now ready to use it with the **lookup** command. 

First, I do some results manipulation by extracting all the names of the files listed in the Image field, converting them to lower case, and then storing the results into a new field called "filename":

`| rex field=Image "(?P<filename>[^\\\]+)$"` = extract new filename field 
`| eval filename=lower(filename)` = converts all of the results for the filename field to lower case

Now I can compare the values of the new filename field to the malware_lookup.csv (which has a matching filename column) to see if any of the found files are known malware. 

`| lookup malware_lookup.csv filename OUTPUTNEW is_malware` = uses the newly created filename Splunk field as a key to lookup the column filename in malware_lookup.csv and then outputs the corresponding "is_malware" value into a new Splunk field with the same name 

With these commands I have now extracted all the file names found in the Splunk Image field and compared them against a list of known malicious files to see which ones were found in my data:

![](Images/Pasted%20image%2020231114173800.png)

There is an alternate way I could do this command which replaces the rex with **mvdedup** and **mvindex** to split the full file paths by backslashes and take the last index, which is the filename. 

`eval filename=mvdedup(split(Image, "\\"))` = split up the file names from the Image field using the backslashes and remove any duplicates

`eval filename=mvindex(filename, -1)` = select the last index which will be the filename 

The rest is similar to the rex version minus the duplicates and the results are the same:

![](Images/Pasted%20image%2020231114182336.png)

Transactions in Splunk are used to group events that share common characteristics. With the **transaction** command I can group events based on certain fields like Image. 

`| transaction Image startswith=eval(EventCode=1) endswith=eval(EventCode=3) maxspan=1m` = creates a transaction of events within 1 minute of each other that start with an event with EventCode 1 and ends with an event with EventCode 3

After removing the duplicate values I can identify programs that all created certain types of events within 1 minute of each other: 

![](Images/Pasted%20image%2020231114201941.png)

Finally, I use SPL's capability to do subsearches to filter out large sets of data. I start by creating a very simple search to get all Sysmon events with EventCode 1. 

Using the logical NOT keyword I can filter out all the results of a subsearch from the results of this main search:

```
NOT
	[ search index="main" sourcetype="WinEventLog:Sysmon" EventCode=1
	| top limit=100 Image
	| fields Image ]
```

The subsearch will find all Sysmon events with Event Code 1 and returns only the 100 most common values of the Image field. Therefore, all of these results will be removed from the main search:

![](Images/Pasted%20image%2020231114202755.png)

Filtering out these events will result in a search that provides a look into some of the Event Code 1 events that feature more rare and unique instances of programs being used. 

### Identify Available Data

To first get an idea of all the indexes I have in my data set I use **eventcount** with `summarize=false` to create a table of each one: 

![](Images/Pasted%20image%2020231115122829.png)

Then I can use **metadata** to view all of the different sourcetype objects (ex: Sysmon) that have created events in my data:

![](Images/Pasted%20image%2020231115123122.png)

I can use similar commands to view all the hosts and get info about the sources: 

![](Images/Pasted%20image%2020231115123308.png)

![](Images/Pasted%20image%2020231115123453.png)

Once I know the different sourcetypes, I can view their raw event data in a table with `table _raw`:

![](Images/Pasted%20image%2020231115125429.png)

For information on the types of fields a sourcetype has I can use the **fieldsummary** command:

![](Images/Pasted%20image%2020231115130408.png)

I can further filter the results based on some of the returned stats from fieldsummary:

![](Images/Pasted%20image%2020231115133511.png)

For time based queries, the **bucket** command can group together events and then computing stats on them makes it easy to view summaries of defined time periods. 

In this query I bucket all events into singular days and compute the counts of each sourcetype in each index:

![](Images/Pasted%20image%2020231115131904.png)

Another way to find uncommon events is with the **rare** command. Here I get the top 10 least common combinations of index and sourcetype:

![](Images/Pasted%20image%2020231115132715.png)

The command **sistats** can also be used to explore event diversity and extract info about common/uncommon events. 

With this command I count the number events based on index, sourcetype, source, and host to get a big picture analysis of the events:

![](Images/Pasted%20image%2020231115133904.png)

### Practice Queries

#### Find the account name with the highest amount of Kerberos authentication ticket requests

Since I don't know which Event Code the Kerberos authentication ticket request is, I do a simple search for "kerberos authentication" to see that it is 4768:

![](Images/Pasted%20image%2020231115145057.png)

Then I can do a search on Event Code 4768 that counts all the Account_Name field values, puts them into a table, and sorts to see the highest count account:

![](Images/Pasted%20image%2020231115145321.png)

The account named "waldo" submitted the highest number of Kerberos authentication requests. 
#### Find the number of distinct computers accessed by the account name SYSTEM in all Event Code 4624 events

Since this query is much more specific I can instantly grab this info by getting all events with Event Code 4624 and that have the Account_Name SYSTEM, then using dedup to get all of the unique ComputerName values:

![](Images/Pasted%20image%2020231115151727.png)

This returns 10 results which means that the SYSTEM account accessed 10 unique computers in the 4624 events. 

## Splunk Applications - Sysmon

To get an idea for the usefulness and functionality that Splunk applications provide, I will be using the [Sysmon App for Splunk](https://splunkbase.splunk.com/app/3544). 

Once I've downloaded it into my instance of Splunk Enterprise, I can see that the app is functioning and I can view all of its tools with the toolbar:

![](Images/Pasted%20image%2020231115191033.png)

In the **File Activity** section I can view all the files that have been created in my dataset:

![](Images/Pasted%20image%2020231115191015.png)

However, there is no data in the "Top Systems" section because the search that the app is using isn't compatible with my data:

![](Images/Pasted%20image%2020231115191114.png)

Using the UI I can edit the search manually and manually make it compatible as a normal Splunk search would function. 

The issue in this example was that the search was originally `sysmon EventCode=11 | top Computer` but there isn't a field named "Computer" so I changed it to "ComputerName" to be accurate for my data:

![](Images/Pasted%20image%2020231115191220.png)

Now the "Top Systems" section displays accurate data because the underlying search will actually return results:

![](Images/Pasted%20image%2020231115191240.png)

There are many instances like the above example where the downloaded app won't always be perfectly aligned with your data in terms of keywords and fields. I went ahead and made a few more changes to some of the searches that **Sysmon App for Splunk** was using. 

In this example, there was a report that the app wanted to make to show the amount of network connections being made by an application. Many of the fields and search terms that it was using were incompatible with my data:

![](Images/Pasted%20image%2020231115195749.png)

To make this search more functional I wanted to fix it so that I could see the number of network connections made by the app **SharpHound.exe**. 

There were many fields to edit such as protocol, dest_port, dest_host, and dest_ip, but after converting them to the most relevant alternative in my data I successfully found that the SharpHound app had made 6 network connections:

![](Images/Pasted%20image%2020231115195725.png)

## Intrusion Detection With Splunk

This section will cover real-world intrusion detection scenarios and mimic the techniques that blue teams would use when hunting for attacks in an organization. I will use common techniques to identify different types of attacks that are present in the over 500,000 events that the data holds. 
### Search Performance Optimization

First I will start by looking for attacks in the Sysmon data, and to get a broad look of it I do a simple command to see how many events exist for Sysmon:

![](Images/Pasted%20image%2020231116132024.png)

I want to compare the performance differences between SPL searches, so I do the same search for the system name "uniwaldo.local" but with and without wildcards:

![](Images/Pasted%20image%2020231116132833.png)
![](Images/Pasted%20image%2020231116132845.png)

I get the same amount of events found but the time it took to get the results with wildcards was significantly longer than without because it was matching to many more events. 

Another example with the same search to improve performance and get more accurate results is to specify the field, assuming I know what field I expect the keyword to be in: 

![](Images/Pasted%20image%2020231116133936.png)

### Using Attacker Mindset

Event codes in the Sysmon data can give me an idea of the attacks that attackers use against a system or network because they each signal specific processes being performed on a host. 

I start by taking a look at the number of events related to each of the Sysmon event codes existing in the data:

![](Images/Pasted%20image%2020231116135140.png)

Event code 1 for process creation can be related to unusual parent-child trees and I begin looking for attacks with it:

![](Images/Pasted%20image%2020231116170507.png)

Some problematic child processes are **cmd.exe** and **powershell.exe** so I look for them in a search with the Image field:

![](Images/Pasted%20image%2020231116171557.png)

The original search has now been narrowed down to 628 events compared to 5,472. 

Some of the more questionable results of these events are the ones where the problematic child processes are spawned from a **notepad.exe** parent process:

![](Images/Pasted%20image%2020231116171739.png)

I narrow down the search to focus on these 21 occurrences: 

![](Images/Pasted%20image%2020231116171942.png)

Looking at even the first event I can see that it involved a command line prompt where powershell is used to download a file from a server:

![](Images/Pasted%20image%2020231116172134.png)

Investigating the IP address that the file was downloaded from shows only two sourcetypes:

![](Images/Pasted%20image%2020231116172323.png)

Looking specifically at the syslog sourcetype I can see that the IP belongs to the host "waldo-virtual-machine" and it is using its ens160 interface:

![](Images/Pasted%20image%2020231116172548.png)

One of the events shows that a new address record has been created on the interface to form some form of communication with a Linux system:

![](Images/Pasted%20image%2020231116174732.png)

I also check the Sysmon related logs with the CommandLine field to investigate further:

![](Images/Pasted%20image%2020231116174712.png)

In these results we can see many commands being used to download files that are likely malicious, and it it also likely to be confirmed that the Linux system being connected to previously is infected. 

If I add the count for the host field I can see that there were two hosts that were victims of the attack: 

![](Images/Pasted%20image%2020231116175131.png)

Based on the file name, it appears that one of the hosts was targeted with a DCSync attack using a powershell file:

![](Images/Pasted%20image%2020231116175248.png)

This type of attack is related to Active Directory and I can focus on this by looking at events with event code 4662. I also use a couple of specifiers that will show a couple of procedures that a DCSync attack uses: 

`AccessMask=0x100` = this will appear when Control Access is requested which is needed for a DCSync attack because it requires high-level permissions

`AccountName!=*$` = removes all results where the account being used is a service, so I only see instances where a user account was used for DCSync which is normally not allowed

![](Images/Pasted%20image%2020231116180142.png)

Looking into the two returned events I can see two GUIDs: 

![](Images/Pasted%20image%2020231116180316.png)

The first is for "DS-replication-Get-Changes-All":

![](Images/Pasted%20image%2020231116180438.png)

From the documentation I can see that the purpose of this is to "replicate changes from a given NC" which is essentially the definition of a DCSync attack as it attempts to ask other domain controllers to replicate information and gain user credentials. 

This information concludes that the attacker has infiltrated a system, gained domain admin rights, moved laterally across the network, and exfiltrated the domain credentials for the network. 

I know now that the waldo user was used to execute this attack and that the account likely has domain admin rights itself, but I am not yet aware of how the attacker gained these rights initially. 

Knowing that lsass dumping is a prevalent credential harvesting technique, I conduct a search to see the types of programs related with event code 10 and keyword "lsass":

![](Images/Pasted%20image%2020231116190124.png)

I use an assumption that lower event counts can be considered out of the ordinary, or not typical behavior, and find that some of the lowest event counts are related to **notepad.exe** and **rundll32**:

![](Images/Pasted%20image%2020231116190334.png)

Looking further at notepad reveals only one event that Sysmon thinks is related to lsass and credential dumping:

![](Images/Pasted%20image%2020231116192204.png)

![](Images/Pasted%20image%2020231116192351.png)

### Meaningful Alerts

In the previous section I found that APIs were called from UNKNOWN memory regions and that this eventually lead to the DSSync attack that I investigated. I can now create an alert that detects this to hopefully be able to prevent similar attacks in the future. 

First I want to know more about the UNKNOWN memory location usage so I search to see the related event codes:

![](Images/Pasted%20image%2020231116192929.png)

The results show that the only related event code is 10 which is for process access, so I know now that I am looking for events that attempt to open handles to other processes that don't have a memory location mapped to the disk. 

Getting an idea of the types of programs related to this behavior results in a lot of unproblematic results:

![](Images/Pasted%20image%2020231116193217.png)

I want to filter out a lot of these normal instances so I begin by removing any events where the source program tries to access itself, which the attack I investigated did not do:

![](Images/Pasted%20image%2020231116193718.png)

To further filter the programs I exclude anything C# related by excluding any .net, ni.dll, or clr.dll references: 

![](Images/Pasted%20image%2020231116194355.png)

Another instance to remove is anything related to WOW64 because it has a non-harmful phenomenon that comprises regions of memory that are unknown:

![](Images/Pasted%20image%2020231116194549.png)

Anything related to explorer will be much harder to find because, as seen by the high event count, there are many non-malicious events that it produces so it would result in a lot of noise for my alert. I choose to remove this explicitly through the SourceImage field:

![](Images/Pasted%20image%2020231116194826.png)

Now I have a list of only 4 programs that exhibit the behavior I'm trying to target with my alert. I could then analyze and possibly filter out more non-threatening programs but for now this is an alert that could work to prevent the domain admin credential harvesting I identified earlier. 

There are some issues with this alert since the dataset includes very few false positives and is tailored specifically for this exercise. For example, my alert could be bypassed by simply using an arbitrary load of one of the DLLs that I excluded. However, for the purposes of this exercise I was able to identify an attack pattern and create a targeted alert that would detect it. 

### Further Detection Practice

#### Find the other process that dumped credentials with lsass

This is simple as I can go back to my finalized alert for the attack and look at some of the TargetImages:

![](Images/Pasted%20image%2020231116201157.png)

From there I can see that, in addition to notepad.exe, rundll32.exe was also using lsass for credential dumping:

![](Images/Pasted%20image%2020231116201105.png)

#### Find the method rundll32.exe dumped lsass

I start by creating a target search to see all the events that have the source program as rundll32.exe and target program as lsass:

![](Images/Pasted%20image%2020231116202928.png)

From the search I extracted the unique call traces and found many DLLs being used. After a little research I found that one of the DLLs, comsvcs.dll, is actually a common dumping DLL. 

#### Find any suspicious loads of clr.dll that could be C sharp injection/execute-assembly attacks, then find the suspicious process that was used to temporarily execute code

First I will get an idea of all the types of events that include the phrase **clr.dll**. After a bit of searching I found that an important field I wanted to pay attention to was what processes were loading the clr.dll image:

![](Images/Pasted%20image%2020231116211931.png)

One way that I began to filter the results was to just see which images Sysmon correlated with process injection attacks:

![](Images/Pasted%20image%2020231116212101.png)

I got a lot of seemingly harmless results from Microsoft processes like Visual Studio, so I filtered some more: 

![](Images/Pasted%20image%2020231116215321.png)

Unsurprisingly I found that both notepad.exe and rundll32.exe, from my original DCSync alert, were also used to execute code. 

#### Find the two IP addresses of the C2 callback server

This was as simple as looking for any IPs that rundll32.exe or notepad.exe were connection to:

![](Images/Pasted%20image%2020231116222606.png)

![](Images/Pasted%20image%2020231116222618.png)

10.0.0.186 and 10.0.0.91 appear to be the command and control servers. 

#### Find the port that one of the two C2 server IPs used to connect to one of the compromised machines

I started with a broad search to see any mention of the two IP addresses:

![](Images/Pasted%20image%2020231116223752.png)

Since in this case I only care about network connections, I filter to see all events with event code 3:

![](Images/Pasted%20image%2020231116223913.png)

Digging into one of the events gives me an idea of some of the key fields that I want to investigate further:

![](Images/Pasted%20image%2020231116224035.png)

Since I don't know which of the IPs connected to the compromised machine, I simply extract all of the source IPs and their correlating destination ports:

![](Images/Pasted%20image%2020231116223648.png)

From these results I can conclude that the C2 IP 10.0.0.186 used the Remote Desktop Protocol port 3389 to connect to the compromised machines. 

## Detecting Attacker TTPs

Using attacker TTPs to create searches and alerts involves both searching for known behavior and searching for abnormal behavior. This section will cover creating searches based on attacker behavior. 

### Crafting SPL Searches Based on Known TTPs

Attackers often use Windows binaries like net.exe for reconnaissance activities to find privilege escalation and lateral movement opportunities. To target this behavior I use Sysmon event code 1 and look for command line usage that can give info on a host or network:

![](Images/Pasted%20image%2020231117145212.png)

Searching for malicious payload requests can be done by looking at requests for common whitelisted sites that attackers use to host their payloads, like **githubusercontent.com**. Sysmon event 22 for DNS queries can help me identify these occurences. 

There is a QueryName field that I can use to search for githubusercontent.com requests:

![](Images/Pasted%20image%2020231117145612.png)

![](Images/Pasted%20image%2020231117145727.png)

Several MITRE ATT&CK techniques use PsExec and its high-level permissions to conduct attacks. Some common Sysmon event codes that relate to these attacks are 13, 11, 17, and 18. 

Leveraging event code 13, which is for registry value sets, takes a lot of involvement. However, using some resources like [Splunking with Sysmon](https://hurricanelabs.com/splunk-tutorials/splunking-with-sysmon-part-3-detecting-psexec-in-your-environment/) can provide some well crafted searches:

![](Images/Pasted%20image%2020231117153244.png)

`index="main" sourcetype="WinEventLog:Sysmon" EventCode=13 Image="C:\\Windows\\system32\\services.exe" TargetObject="HKLM\\System\\CurrentControlSet\\Services\\*\\ImagePath"` = this will isolate to event code 13, select the services.exe image which handles service creation, and grabs the TargetObject which are the registry keys that will be affected 

`rex field=Details "(?<reg_file_name>[^\\\]+)$"` = grabs the file name from the Details field and stores it in a new field reg_file_name

`eval reg_file_name = lower(reg_file_name), file_name = if(isnull(file_name), reg_file_name, lower(file_name))` = this converts reg_file_name to lower case, then modifies the file_name field so that if it is null it will be filled with reg_file_name and if not it keeps its original value and sets it to lower case as well

`stats values(Image) AS Image, values(Details) AS RegistryDetails, values(\_time) AS EventTimes, count by file_name, ComputerName` = for each unique combination of file_name and Computer name,  this will extract all the unique values of Image, Details, TargetObject, and time

This query will be able to tell me all the instances where **services.exe** modified the ImagePath value of a service. In the search results I have extracted the details of these modifications. 

Using Sysmon event code 11 for file creation shows that there have been execution resembling PsExec:

![](Images/Pasted%20image%2020231117154044.png)

Sysmon event code 18 for pipe connections can also show a PsExec execution pattern:

![](Images/Pasted%20image%2020231117154223.png)

Archive or zipped files are typically used for data exfiltration, so using event code 11 I can filter for these types of file creations and see some concerning results:

![](Images/Pasted%20image%2020231117161312.png)

A common way to actually download the payloads that attackers are hosting is through powershell or MS Edge while also targeting **Zone.Identifier** which signals files downloaded from the internet or untrustworthy sources:

![](Images/Pasted%20image%2020231117161638.png)

![](Images/Pasted%20image%2020231117161841.png)

There are also ways to detect execution from unusual places, for example in this search I look for process creations in the downloads folder using event code 1:

![](Images/Pasted%20image%2020231117163246.png)

Another sign of malicious activity is the creation of DLL and executable files outside of the Windows directory:

![](Images/Pasted%20image%2020231117163625.png)

Even though it takes a bit of manual involvement, another attribute to look for is the misspelling of common programs. In this case I look for a misspelling of the PsExec files:

![](Images/Pasted%20image%2020231117164757.png)

Finally, one of the most common tactics is using non-standard ports for communications and data transfers. Searching for this can be as simple as looking for all network connections, event code 3, that aren't using typical ports:

![](Images/Pasted%20image%2020231117165520.png)

### Practice Investigation

#### Find the password utilized during the PsExec activity

This was very simple to find as the attacker often used command line arguments to enter in the password. I simply looked for any reference to the phrase "password" in Sysmon events and found a PsExec related event with the password stated in the CommandLine field:

![](Images/Pasted%20image%2020231117170249.png)

## Detecting Attacker Behavior with Anomaly Detection

Rather than focusing on specific attacker TTPs and crafting searches to target them, another method of detection is by using statistics/analytics to capture abnormal behavior compared to a baseline of "normal" behavior. 

Splunk provides many options to do this, including the **streamstats** command:

![](Images/Pasted%20image%2020231118144946.png)

Streamstats lets me capture real-time analytics on the data to better identify anomalies that may exist. In the above example:

`bin time span=1h` = groups the event code 3 events into hourly intervals

`streamstats time_window=24h avg(NetworkConnections) as avg stdev(NetworkConnections) as stdev by Image` = creates rolling 24-hour averages and standard deviations of the number of network connections for each unique process image

These statistics create the baseline of normal behavior to which I can then extract any events that are outside of the range that I specify with: `eval isOutlier=if(NetworkConnections > (avg + (0.5 * stdev)), 1, 0)`

### SPL Searches Based on Analytics

One of the simpler ways to search for anomalies is by looking for really long commands. Attackers often need to execute complex commands to do their tasks so searching based on the length of the CommandLine field can be effective:

![](Images/Pasted%20image%2020231118151907.png)

I can also use the same technique of looking for a baseline and apply it to unusual cmd.exe activity:

![](Images/Pasted%20image%2020231118152653.png)

The above baseline is relatively simple as it looks for average/stdev of the number of commands being run with cmd.exe. 

Another anomaly that is often exhibited by malware is a high amount of DLLs being loaded within a short amount of time. This can often be done by non-malicious activity as well, but it is still something to check. 

Here I try to filter out as many benign processes that could exhibit this behavior and then extract all of the events where more than 3 unique DLLs are loaded within an hour:

![](Images/Pasted%20image%2020231118154658.png)

When the same process is executed on the same computer it can often signal malicious or at least abnormal behavior. With Sysmon event code 1 I can see all the events where the same programs are started more than once. 

To do this I look for instances where a process, the Image field, has more than one unique process GUID associated with it:

![](Images/Pasted%20image%2020231118155856.png)

Looking at some of the previously found malicious programs I can see that this behavior was related to some of the lsass dumping activity:

![](Images/Pasted%20image%2020231118160103.png)

### Practice Scenario

#### Find the source process image that has created an unusually high number of threads in other processes (greater than 2 standard deviations)

To start looking for this process, I first want to know more about the events that I should be looking for. Sysmon event code 8 is for remote thread creation so I check all of these events where the SourceImage field is not the same as the TargetImage:

![](Images/Pasted%20image%2020231118162553.png)

Then, using a similar search to those I had done previously, I looked for events where the number of threads created exceeded 2 standard deviations:

![](Images/Pasted%20image%2020231118162700.png)

The steps of this search were to: 
1. Bin the events into 1 hour bins
2. Count the number of threads created based on the source and target images
3. Calculate the average and standard deviation of the number of threads created
4. Find all instances where the number of threads created was greater than 2 standard deviations

This resulted in finding the malicious file **randomfile.exe** created multiple threads in notepad.exe. 

## Finding the Source of the Intrusion

Throughout the previous sections I have been investigating different parts of an attack chain that started with domain credentials being dumped which resulted in host infections and data exfiltration. There have been a number of related malicious processes, commands, and DLLS, most notably notepad.exe and rundll32.exe. 

In this section I want to learn more about this attack and find its original method of intrusion. 

### Find the process that created remote threads in rundll32.exe

Finding this process was simple because doing a search on event code 8 events where the target image was rundll32.exe only resulted in one program, **randomfile.exe**:

![](Images/Pasted%20image%2020231118163633.png)

### Find the process that started the infection

My initial thoughts on how to further investigate the start of the infection was to combine the previous findings about **randomfile.exe** with the known C2 servers that I found earlier:

![](Images/Pasted%20image%2020231118170320.png)

Looking into the events that this search provided reminded me of the infected users that could lead to how this infection started:

![](Images/Pasted%20image%2020231118170310.png)

Since the **waldo** user has been prevalent throughout this project I decided to look into the types of events that are related to this account and the C2 servers. 

Interestingly, I found many events related to Sysmon event code 15 which is related to external downloads from the web:

![](Images/Pasted%20image%2020231118170403.png)

I wanted to focus on these event code 15 events so I started by first getting an idea of the processes that might be related to these events:

![](Images/Pasted%20image%2020231118170615.png)

Lots of these programs appear to be malicious based on the prior knowledge of the attack and the only one that I haven't seen before is **demon.exe**. Luckily this list is very small so I can now begin thinking in terms of a timeline. 

I do a simple search to see all of the events related to the waldo user and the C2 servers, but I make sure to see the very first events that have occurred:

![](Images/Pasted%20image%2020231118171921.png)

From this search I can see that on 10/5/22 the first occurrence of contact with the C2 servers was an event code 15 event categorized as a "Drive-by Compromise" related to the **Run.dll** file in the user waldo's downloads folder:

![](Images/Pasted%20image%2020231118171948.png)

A DLL file in the downloads folder itself is suspicious and along with the fact that there is no legitimate DLL named "Run.dll" it's safe to assume this is a malicious file worth investigating. 

In this search I also inspected the different target file names and saw some of the usual suspects:

![](Images/Pasted%20image%2020231118172039.png)

Since the Run.dll events seemed to happen before the demon.dll files, I did a quick search on it:

![](Images/Pasted%20image%2020231118172532.png)

![](Images/Pasted%20image%2020231118172516.png)

By looking at the first ever event that occurred with Run.dll I can see that **rundll32.exe** was used to load it (Sysmon event code 7) only 8 minutes after the Run.dll file was detected as a potential drive-by compromise. 

With this knowledge, I can conclude that the waldo user downloaded the malicious file Run.dll which then exploited rundll32.exe to initiate the attack.