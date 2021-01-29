#
# IP2AS: This tool maps an IP address to an AS. It uses static table
#        Address prefix to AS number collected from whois DB and BGP
#        tables. This table is stored in a file and should be given to
#        the tool as a parameter. It will perform longest prefix
#        matching and will map the IP to an AS number.
#
#	 The tool should print out the longest prefix that the IP
#	 address is matched to, and the corresponding AS number.

Usage: 

   ip2as <DB file> <IP file>  
 
Steps:

1. Put the set of IP addresses you want to map to ASes into the <IP
   file>. You can list one IP address per line. 
   
   For example, look at IPlist.txt file, which contains the following:
   
   169.237.33.90
   208.30.172.70

2. The <DB file> has data about which address block belongs to
   a particular AS (look at DB_091803.txt file, for example).
   The <DB file> is constructed based on IRR database and
   BGP routing table.
  
3. Run ip2as and specify the <DB file> and <IP file>

   For example, if you run 
   >> ip2as DB_091803.txt IPlist.txt

   the output should look like the following:
   
   169.237.0.0/16  1852 169.237.33.90
   208.0.0.0/11  1239 208.30.172.70

   

