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

    forti_cmd.py --file <RULES_FILE_PATH> <OBJECTS_FILE_PATH> <-a OR --add>
    forti_cmd.py --file <RULES_FILE_PATH> <OBJECTS_FILE_PATH> <-d OR --delete> <RULE_ID>
    example:
      forti_cmd.py --file /tmp/Rules.csv /tmp/Objects.csv -a --> add all rules in csv rules file
      forti_cmd.py --file /tmp/Rules.csv /tmp/Objects.csv -d 3 --> delete rule No. 3
