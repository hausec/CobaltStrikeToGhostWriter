#!/usr/bin/env python
import csv, os, sys,time, datetime, time, operator, os.path, re
from glob import glob
from csv import writer

logfolder = sys.argv[1]
header = ['oplog_id', 'start_date', 'end_date', 'source_ip', 'dest_ip', 'tool', 'user_context', 'command', 'description', 'output', 'comments', 'operator_name']
with open('CS2GW.csv', 'wb') as outputcsv:    
    writer = csv.writer(outputcsv, delimiter=',')
    writer.writerow([i for i in header])  
    if os.path.exists(logfolder):
            result = [y for x in os.walk(logfolder) for y in glob(os.path.join(x[0], '*.log'))]
            for file in result:
                if file.endswith(".log"):
                    print "Parsing:",file                      
                    filehandle = open(file, 'r') 
                    lines = filehandle.readlines()                 
                    for line in lines:                                    
                        if '[metadata]' in line:
                            if 'beacon_' in line:
                                
                                pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})') 
                                lst = re.findall( r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", line )
                                sourceip = "SMB Beacon"   
                                dstip = lst[0]
                                dsthostugly = line.split("computer: ",1)[1]
                                dsthost = dsthostugly.split(";",1)[0]
                                userugly = line.split("user: ",1)[1]
                                usercontext = userugly.split(";",1)[0]
                                processugly = line.split("process: ",1)[1]
                                process = processugly.split(";",1)[0]                                     
                            
                            else:
                                pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})') 
                                lst = re.findall( r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", line )                             
                                sourceip = lst[0]
                                dstip = lst[1]   
                                dsthostugly = line.split("computer: ",1)[1]
                                dsthost = dsthostugly.split(";",1)[0]
                                userugly = line.split("user: ",1)[1]
                                usercontext = userugly.split(";",1)[0]
                                processugly = line.split("process: ",1)[1]
                                process = processugly.split(";",1)[0]     
                        if '[input]' in line:
                            date = line[:5]
                            month = date[:2]
                            day = date[3:5]
                            year = str(datetime.date.today().year)
                            times = line[5:14]                    
                            timeft = year + "-" + month + "-" + day + times          
                            userfind = re.search('<(.*)>', line)
                            user = (userfind.group(1))
                            usersearch = "<" + user + ">"
                            index1 = line.find(">") + 2
                            command = line[index1:-1]
                            writer.writerow(["1",timeft,timeft,sourceip,dsthost,"beacon",usercontext,command,process,"","",user]) 