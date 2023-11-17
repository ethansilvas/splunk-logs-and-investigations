# Splunk Logs and Investigations

in this project...
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




