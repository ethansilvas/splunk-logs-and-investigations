# Splunk Logs and Investigations

in this project...
## Splunk and SPL

In this section I will focus on the SIEM capabilities of Splunk and go through its many data analysis tools. I will also use Splunk Processing Language (SPL) to conduct various searches, filters, transformations, and visualizations. 

## Splunk as a SIEM 

To begin creating basic SPL commands, I will use a VM host setup with a Splunk Index named **main** containing Windows Security, Sysmon, and other logs. 

For some starter searches I first query the index for the term "UNKNOWN" using `index=main "UNKNOWN"`:

![](Images/Pasted%20image%2020231114151034.png)

Then I can modify that same query with wildcards to find all occurrences of "UNKNOWN" with any amount of characters before and after it:

![](Images/Pasted%20image%2020231114151417.png)

The wildcards return more results as the search criteria becomes less strict. 




## Splunk Applications

