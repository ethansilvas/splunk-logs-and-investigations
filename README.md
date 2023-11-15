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



## Splunk Applications

