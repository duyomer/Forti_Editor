# Forti_Editor
Python script for creating Fortigate Rules and Objects from a CSV file.
The script gets 2 csv files:
  1. Rules
  2. Objects

With the following format:
Rules.csv:
  
    Source Address,Destination Address,Source Interface,Destination Interface,Service,Schedule,Action,NAT
  
Objects.csv:
  
    Object Name,Type,Subnet
  
Usage:

    forti_cmd.py --file <RULES_FILE_PATH> <OBJECTS_FILE_PATH>
    example:
    forti_cmd.py --file /tmp/Rules.csv /tmp/Objects.csv
