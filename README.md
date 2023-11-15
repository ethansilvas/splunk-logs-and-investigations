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



## Splunk Applications


## Notes 

rex max_match=0 will capture all occurrences, default is only the first occurrence

