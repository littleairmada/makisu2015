#
# Autopsy module based on Mari DeGrazia's Google analytic parser.
# This file contains her original code, plus the basics of an
# Autopsy ingest module. The GA-Parser code should probably be
# its own file.
#
###########################################################################
#
#GA-Parser
#This program carves and parses Google Analytic vales
#and outputs them into a tsv form.
#
#To read more about it, visit my blog at http://az4n6.blogspot.com/
#
# Copyright (C) 2014 Mari DeGrazia (arizona4n6@gmail.com)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You can view the GNU General Public License at <http://www.gnu.org/licenses/>


import jarray
import sys
#import uuid
import re
#import urllib
#import datetime
#import os
from java.lang import System
from org.python.core.util import StringUtil
from org.sleuthkit.datamodel import SleuthkitCase
from org.sleuthkit.datamodel import AbstractFile
from org.sleuthkit.datamodel import ReadContentInputStream
from org.sleuthkit.datamodel import BlackboardArtifact
from org.sleuthkit.datamodel import BlackboardAttribute
from org.sleuthkit.autopsy.ingest import IngestModule
from org.sleuthkit.autopsy.ingest import DataSourceIngestModule
from org.sleuthkit.autopsy.ingest import FileIngestModule
from org.sleuthkit.autopsy.ingest import IngestModuleFactoryAdapter
from org.sleuthkit.autopsy.ingest import IngestMessage
from org.sleuthkit.autopsy.ingest import IngestServices
from org.sleuthkit.autopsy.casemodule import Case
from org.sleuthkit.autopsy.casemodule.services import Services
from org.sleuthkit.autopsy.casemodule.services import FileManager

# Sample factory that defines basic functionality and features of the module
class SampleJythonIngestModuleFactory(IngestModuleFactoryAdapter):
    
    def getModuleDisplayName(self):
        return "CookieModule"
    
    def getModuleDescription(self):
        return "A sample Jython ingest module"
    
    def getModuleVersionNumber(self):
        return "1.0"
    
    # Return true if module wants to get passed in a data source
    def isDataSourceIngestModuleFactory(self):
        return False
    
    # can return null if isDataSourceIngestModuleFactory returns false
    def createDataSourceIngestModule(self, ingestOptions):
        return SampleJythonDataSourceIngestModule()

    # Return true if module wants to get called for each file
    def isFileIngestModuleFactory(self):
        return True
    
    # can return null if isFileIngestModuleFactory returns false
    def createFileIngestModule(self, ingestOptions):
        return CookieModule()


# File-level ingest module.  One gets created per thread.
# Looks at the attributes of the passed in file.
# if you don't need a file-level module, delete this class.
class CookieModule(FileIngestModule):
    current_file = None
    gFile = None
    processed = 0
    def startUp(self, context):
        pass

    def shutDown(self):
        pass
        
    def process(self, file):
        # If the file has a txt extension, post an artifact to the blackboard.
        lcFileName = file.getName().lower()
        lcParentPath = file.getParentPath().lower()
        #if lcFileName.find("cookies") != -1 or lcFileName.find(".txt") != -1 :
        if lcFileName.find("cookies") != -1 or lcParentPath.endswith("windows/cookies") != -1 and lcFileName.find(".txt") != -1 :
            self.gFile = file
            #tempFileName = "C:\\temp\\mak_" + uuid.uuid4()
            #print "temp file : " + tempFileName
            #outputFile = open("C:\\temp\\makisu_" + file.getName() + ".txt", "w") 
            #self.current_file = file.getName()            
        
            print "\n\n####################################################\n\nAnalyzing " + file.getName() + "\n"
            #outputFile.write("\n####################################################\n\nAnalyzing " + file.getName() + "\n")
            self.cookieMain(file)

            # Read the contents of the file.
            #inputStream = ReadContentInputStream(file)
            #buffer = jarray.zeros(1024, "b")
            #totLen = 0
            #len = inputStream.read(buffer)
            #while (len != -1):
            #    totLen = totLen + len
            #    len = inputStream.read(buffer)

            # Send the size of the file to the ingest messages in box. 
            #msgText2 = "Size of %s is %d bytes" % ((file.getName(), totLen))
            #message2 = IngestMessage.createMessage(IngestMessage.MessageType.DATA, "CookieModule", msgText2)
            #ingestServices = IngestServices.getInstance().postMessage(message2)
            #outputFile.closed
        return IngestModule.ProcessResult.OK  

    def cookieMain(self, file):
    
        global chrome_pattern_utmb
        global chrome_pattern_utmz
        global chrome_pattern_utma
        global moz_pattern_utma
        global moz_pattern_utmb
        global moz_pattern_utmz
        global ie_utma_pattern
        global ie_utmb_pattern
        global ie_utmz_pattern
        global apple_utma_pattern
        global apple_utmb_pattern
        global apple_utmz_pattern
        global chrome_utma_count
        global chrome_utmb_count
        global chrome_utmz_count

        global ff_utma_count
        global ff_utmb_count
        global ff_utmz_count

        global ie_utma_count
        global ie_utmb_count
        global ie_utmz_count

        global apple_utma_count
        global apple_utmb_count
        global apple_utmz_count

        global gif__UTF16_count
        global gif_ASCII_count
    
        #chrome utm grep patterns
        chrome_pattern_utma =  re.compile(r'__utma(([0-9]{0,10}\.){5}([0-9])*)(\/)')
        chrome_pattern_utmz =  re.compile(r'(__utmz)(([0-9]{0,10}\.){4}utm(.*?)\s*\x2F\x00\x2E)')
        chrome_pattern_utmb =  re.compile(r'(__utmb)(([0-9]{0,10}\.){3}[0-9]{0,10})')

        #firefox utm grep patterns
        moz_pattern_utma =  re.compile(r'(__utma(([0-9]{0,10}\.){5}[0-9]{1,5}))[^\/](\.?[a-zA-Z\d-]{0,63}){0,4}')
        moz_pattern_utmb =  re.compile(r'__utmb([0-9]{0,10}\.){3}[0-9]{0,10}([a-zA-Z\d-]{,63}\.[a-zA-Z\d-]{,63}){1,4}')
        moz_pattern_utmz =  re.compile(r'(__utmz)(([0-9]{0,20}\.){4}[ -~]*?)([a-zA-Z\d-]{,63}\.[a-zA-Z\d-]{,63}){0,4}\/[TS]{1}')

        #ie patterns
        ie_utma_pattern =  re.compile(r'(__utma)(\x0a(([0-9]{0,10}\.){5})[0-9]{1,10}\n)([ -~]{1,64}\x0a)')
        ie_utmb_pattern =  re.compile(r'(__utmb)(\x0a(([0-9]{0,10}\.){3})[0-9]{1,10}\n)([ -~]{1,64}\x0a)')
        ie_utmz_pattern =  re.compile(r'(__utmz)\x0a(([0-9]{0,10}\.){4}[ -~]{1,200}\x0a)([ -~]{1,64}\x0a)')

        apple_utma_pattern = re.compile(r'(__utma)\x00(([0-9]{0,10}\.){5}[0-9]{1,5})\x00([ -~]{1,64}\x00\/)')
        apple_utmb_pattern = re.compile(r'(__utmb)\x00(([0-9]{0,10}\.){3}[0-9]{10})\x00([ -~]{1,64})\x00\/')
        apple_utmz_pattern = re.compile(r'(__utmz)\x00(([0-9]{0,10}\.){4}[ -~]{1,200}\x00)([ -~]{1,64}\x00\/)')



        #count vars to keep track of total records processed
        chrome_utma_count = 0
        chrome_utmb_count = 0
        chrome_utmz_count = 0

        ff_utma_count = 0
        ff_utmb_count = 0
        ff_utmz_count = 0

        ie_utma_count=0
        ie_utmb_count=0
        ie_utmz_count=0

        apple_utma_count = 0
        apple_utmb_count = 0
        apple_utmz_count = 0

        gif__UTF16_count = 0
        gif_ASCII_count = 0

        self.processed = 0
        not_processed= []

        #can be increased if more ram is available
        global maxfilesize
        maxfilesize = 500000


        #printable chars allowed in urls and domain names
        allowed_chars = r'[\.a-zA-Z\d-]'
        p_allowed_chars = re.compile(allowed_chars)


        #loop to keep track of how many segments a file is broken into
        global loop
        loop = 0
        
        # Read the contents of the file.
        nLoops = 0
        while 1:
            inputStream = ReadContentInputStream(file)
            chunkJarray = jarray.zeros(maxfilesize, "b")
            if not chunkJarray:
               break
            len = inputStream.read(chunkJarray)   
            if len != maxfilesize:
                print "Not enough bytes read: %d\n" % (len)
                if nLoops > 0:
                    print"  nLoops = %d;breaking\n" % (nLoops)
                    break            
            chunk = StringUtil().fromBytes(chunkJarray)     
        
            print ("Bytes read: %d\n" % (len))
    
            self.process_chrome_utma(chrome_pattern_utma, chunk)
            #self.process_chrome_utmb(chrome_pattern_utmb, chunk)
            #self.process_chrome_utmz(chrome_pattern_utmz, chunk)
                    
            self.process_firefox_utma(moz_pattern_utma,chunk)
            #self.process_firefox_utmb(moz_pattern_utmb,chunk)
            #self.process_firefox_utmz(moz_pattern_utmz,chunk)
                
            self.process_ie_utma(ie_utma_pattern,chunk)
            #self.process_ie_utmb(ie_utmb_pattern,chunk)
            #self.process_ie_utmz(ie_utmz_pattern,chunk)
                
                
            self.process_apple_utma(apple_utma_pattern,chunk)
            #self.process_apple_utmb(apple_utmb_pattern,chunk)
            #self.process_apple_utmz(apple_utmz_pattern,chunk)
            
            nLoops = nLoops + 1
            if nLoops > 1:
                print "nLoops too big - breaking"
                break
                
        print "\r\r************ Summary ************"     
        print "Chrome __utma count processed: " + str(chrome_utma_count)
        print "Chrome __utmb count processed: " + str(chrome_utmb_count)
        print "Chrome __utmz count found: " + str(chrome_utmz_count)

        print "FireFox __utma count processed: " + str(ff_utma_count)
        print "FireFox __utmb count processed: " + str(ff_utmb_count)
        print "FireFox __utmz count found: " + str(ff_utmz_count)
        print "FireFox __utmz count processed: " + str(self.processed)

        print "IE __utma count processed: " + str(ie_utma_count)
        print "IE __utmb count processed: " + str(ie_utmb_count)
        print "IE __utmz count processed: " + str(ie_utmz_count)

        print "apple __utma count processed: " + str(apple_utma_count)
        print "apple __utmb count processed: " + str(apple_utmb_count) 
        print "apple __utmz count processed: " + str(apple_utmz_count)  
        
    #########################  Functions to process individual cookie values (utma, utmb and utmz)   ##########################

    def throwWarning(self, msg):
        message = IngestMessage.createMessage(IngestMessage.MessageType.DATA, "CookieModulez", msg)
        IngestServices.getInstance().postMessage(message)   

    #parse the utma values. Takes the utma value as input
    def parse_utma(self, cookie_value,file_offset,host,type,toPrint=True):
        #create dictionary to hold utma values
        utma_value = {}
        
        utma_value["Created"]=""
        utma_value["Created_Epoch"]=""
        utma_value["2ndRecentVisit"]=""
        utma_value["MostRecent"]=""
        utma_value["Hit"]=""
        
        utma_values = cookie_value.split('.')
        if len(utma_values) == 0:
            return 0
        else:
            
            #some utma domain hash values do not want to play nice and have some wonky values that include a period
            #which throws off the count. These also have a colon in them, so look for the colon, if found, advance the count by 1
            
            if ':' in utma_values[0]:
               
                utma_value["Created_Epoch"] = (utma_values[3])
                try:
                    utma_value["Created"]=(datetime.datetime.fromtimestamp(int(utma_values[3])).strftime("%Y-%m-%d %H:%M:%S"))
                except:
                    utma_value["Created"] = utma_values[3]#"Error on conversion"
                                
                #second most recent visit
                utma_value["2ndRecentVisit_Epoch"] = (utma_values[4])
                try:
                    utma_value["2ndRecentVisit"]=(datetime.datetime.fromtimestamp(int(utma_values[3])).strftime("%Y-%m-%d %H:%M:%S"))
                except:
                    utma_value["2ndRecentVisit"]   = utma_values[3]#"Error on conversion"
                            
                #most recent visit
                utma_value["MostRecent_Epoch"] = (utma_values[5])
                try:
                    utma_value["MostRecent"]=(datetime.datetime.fromtimestamp(int(utma_values[5])).strftime("%Y-%m-%d %H:%M:%S"))
                except:
                    utma_value["MostRecent"] = utma_values[5]#"Error on conversion"
                                
                #number of visits
                utma_value["Hit"]=(utma_values[6])
            
            else:
                #cookie create time
            
                utma_value["Created_Epoch"] = (utma_values[2])
                try:
                    utma_value["Created"]=(datetime.datetime.fromtimestamp(int(utma_values[2])).strftime("%Y-%m-%d %H:%M:%S"))
                except:
                    utma_value["Created"] = utma_values[2]#"Error on conversion"                
                #second most recent visit
                utma_value["2ndRecentVisit_Epoch"] = (utma_values[3])
                try:
                    utma_value["2ndRecentVisit"]=(datetime.datetime.fromtimestamp(int(utma_values[3])).strftime("%Y-%m-%d %H:%M:%S"))
                except:
                    utma_value["2ndRecentVisit"]   = utma_values[3]#"Error on conversion"          
                
                #most recent visit
                utma_value["MostRecent_Epoch"] = (utma_values[4])
                try:
                    utma_value["MostRecent"]=(datetime.datetime.fromtimestamp(int(utma_values[4])).strftime("%Y-%m-%d %H:%M:%S"))
                except:
                    utma_value["MostRecent"] = utma_values[4]#"Error on conversion"
               
                utma_value["Hit"]=(utma_values[5])
            
            if toPrint == True:
                msgText = "Fix this later"
                #msgText = self.current_file + "\t" + str(file_offset) + "\t" + str(type) + "\t" + str(host) + "\t" + str(utma_value['Created']) + "\t" + str(utma_value["2ndRecentVisit"]) +"\t" + str(utma_value["MostRecent"]) + "\t" +  str(utma_value["Hit"].rstrip("\n")) + "\n"
                #msgText = str(utma_value['Created']) + "\t" + str(utma_value["2ndRecentVisit"]) +"\t" + str(utma_value["MostRecent"]) + "\t" +  str(utma_value["Hit"].rstrip("\n")) + "\n"
                #print msgText
                hitCount = None;
                try:
                    hitCount = int(utma_value["Hit"])
                except:
                    hitCount = "Unknown"
                self.addInterestingItem(msgText, dateCreated = long(utma_value['Created']), secondRecentVisit = long(utma_value["2ndRecentVisit"]), hits = hitCount, domain = host, category = type, recentVisit = long(utma_value["MostRecent"]))
                #message = IngestMessage.createMessage(IngestMessage.MessageType.DATA, "CookieModule", msgText)
                #ingestServices = IngestServices.getInstance().postMessage(message)                
            return utma_value

    def addInterestingItem(self, sValue, dateCreated = None, secondRecentVisit = None, hits = None, domain = None, category = None, recentVisit = None):
        art = self.gFile.newArtifact(BlackboardArtifact.ARTIFACT_TYPE.TSK_INTERESTING_FILE_HIT)
        att = BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_SET_NAME.getTypeID(), "CookieModule", "Super Cookie")
        #value = BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_VALUE.getTypeID(), "CookieModule", sValue)
        art.addAttribute(att)
        if category != None:
            browser = BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_PROG_NAME.getTypeID(), "CookieModule", category)
            art.addAttribute(browser)
        if domain != None:
            host = BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_DOMAIN.getTypeID(), "CookieModule", domain)
            art.addAttribute(host)
        if dateCreated != None:
            creationDate = BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_FIRST_VISIT.getTypeID(), "CookieModule", dateCreated)
            art.addAttribute(creationDate)
        if recentVisit != None:
            visit = BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_LAST_VISIT.getTypeID(), "CookieModule", recentVisit)
            art.addAttribute(visit)
        if secondRecentVisit != None:
            secondVisit = BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_SECOND_RECENT_VISIT.getTypeID(), "CookieModule", secondRecentVisit)
            art.addAttribute(secondVisit)
        if hits != None:
            hitCount = BlackboardAttribute(BlackboardAttribute.ATTRIBUTE_TYPE.TSK_NUM_SESSIONS.getTypeID(), "CookieModule", hits)
            art.addAttribute(hitCount)
        #art.addAttribute(value)

    def parse_utmb(self, cookie_value,file_offset,host,c_type):
        
        #create dictionary to hold utmb values
        utmb_value = {}
        #utmb_value["URL"]=""
        utmb_value["PageViews"]=""
        utmb_value["Outbound"]=""
        utmb_value["StartCurrSess"]=""
        utmb_value["StartCurrSess_Epoch"]=""
           
        utmb_values = cookie_value.split('.')
        if len(utmb_values) <= 1:
            return 0
        else:
          
            #some utmb domain hash values do not want to play nice and have some wonky values that include a period
            #which throws off the count. These also have a colon in them, so look for the colon, if found, advance the count by 1
            
            if ':' in utmb_values[1]:
                #Page View
                utmb_value["PageViews"]=(utmb_values[2])
                    
                #outbound links
                utmb_value["Outbound"]=(utmb_values[3])
                #start of current session   
                #if date goes out to milliseconds, get rid of milliseconds
                if len(utmb_values[4])<= 10:
                    #utmb_value["StartCurrSess_Epoch"] = int(utmb_values[4])                   
                    
                    try:
                        utmb_value["StartCurrSess"]=(datetime.datetime.fromtimestamp(int(utmb_values[4])).strftime("%Y-%m-%d %H:%M:%S"))
                    except:
                        utmb_value["StartCurrSess"]="Error on conversion"
                else:
                    #utmb_value["StartCurrSess_Epoch"] = (int(utmb_values[4])/1000)
                    try:
                        utmb_value["StartCurrSess"]=(datetime.datetime.fromtimestamp(int(utmb_values[4])/1000).strftime("%Y-%m-%d %H:%M:%S"))
                    except:
                        utmb_value["StartCurrSess"]="Error on conversion"
            else:     
                #Page Views
                utmb_value["PageViews"]=(utmb_values[1])
                            
                #outbound links
                utmb_value["Outbound"]=(utmb_values[2])
                        
                #start of current session
                #if date goes out to milliseconds, get rid of milliseconds
                if len(utmb_values[3])<= 10:
                    #utmb_value["StartCurrSess_Epoch"] = int(utmb_values[3])
                    try:
                        utmb_value["StartCurrSess"]=(datetime.datetime.fromtimestamp(int(utmb_values[3])).strftime("%Y-%m-%d %H:%M:%S"))
                    except:
                        utmb_value["StartCurrSess"]="Error on conversion"
                else:
                    #utmb_value["StartCurrSess_Epoch"] = (int(utmb_values[3])/1000)
                    try:
                        utmb_value["StartCurrSess"]=(datetime.datetime.fromtimestamp(int(utmb_values[3])/1000).strftime("%Y-%m-%d %H:%M:%S"))
                    except:
                        utmb_value["StartCurrSess"]="Error on conversion"
                        
        #print(self.current_file + "\t" + str(file_offset) + "\t" + str(c_type) + "\t" + str(host) + "\t" + utmb_value["PageViews"] + "\t" + utmb_value["Outbound"] + "\t" + utmb_value["StartCurrSess"] +  "\n")
        return utmb_value    

    def parse_utmz(self, cookie_value,file_offset,host,c_type):
        
        #create dictionary to hold utmz values
        utmz_value = {}
        
        utmz_value["LastUpdate"]=""
        utmz_value["LastUpdate_Epoch"]=""
        utmz_value["Source"]=""
        utmz_value["CampName"]=""
        utmz_value["AccesMethod"]=""
        utmz_value["Keyword"]=""
        
        
        utmz_values = cookie_value.split('.')
       
        
        if len(utmz_values) == 0:
            return 0
        else:
                           
            #Last Update time
            if len(utmz_values[1])<=10:
                utmz_value["LastUpdate_Epoch"] = int(utmz_values[1])
                #utmz_value["LastUpdate"]=(datetime.datetime.fromtimestamp(int(utmz_values[1])).strftime("%Y-%m-%d %H:%M:%S"))
            
            #some utmz domain hash values do not want to play nice and have some wonky values that include a period
            #which throws off the count. These also have a colon in them, so look for the colon, if found, advance the count by 1
                   
            
            else:
                if ':' in utmz_values[1]:
                    utmz_value["LastUpdate_Epoch"] = int(utmz_values[2])
                    utmz_value["LastUpdate"]=(datetime.datetime.fromtimestamp(int(utmz_values[2])).strftime("%Y-%m-%d %H:%M:%S"))
                else:    
                    try:
                        utmz_value["LastUpdate_Epoch"] = int(utmz_values[1])/1000
                        utmz_value["LastUpdate"]=(datetime.datetime.fromtimestamp(int(utmz_values[1])/1000).strftime("%Y-%m-%d %H:%M:%S"))
                    except:
                        print "Error converting time for:"  + cookie_value                
            #the utm values are not always in order. thus, we need to located each one in the string and write them out
                                
            #source (utmcsr)
            if "utmcsr" in cookie_value:
                utmcsr = cookie_value.split("utmcsr=")
                
                #partition based on |, take the first section
                utmcsr_value,temp1,temp2 = utmcsr[1].partition('|')
                utmz_value["Source"]=utmcsr_value
            else:
                utmz_value["Source"]='utmcsr not found' 
                                
            #campaign
            if "utmccn" in cookie_value:
                utmccn = cookie_value.split("utmccn=")
                try:
                    utmccn_value,temp1, temp2 = utmccn[1].partition('|')
                    utmz_value["CampName"]=utmccn_value
                except:
                    utmz_value["CampName"]="unable to process, check offset" 
                    
                
            else:
                utmz_value["CampName"]="utmccn not found" 
                                    
            #access method
            if "utmcmd" in cookie_value:
                utmcmd = cookie_value.split("utmcmd=")
                try:
                    utmcmd_value,temp1, temp2 = utmcmd[1].partition('|')
                    utmz_value["AccesMethod"]=utmcmd_value 
                    print "utmz keyword: " + utmz_value["AccessMethod"] + "\n"
                except:
                    utmz_value["AccesMethod"]='unable to process, check offset' 
                    
            else:
                utmz_value["AccesMethod"]='utmcmd not found' 
                                    
            #keywords
            if "utmctr" in cookie_value:
                utmctr = cookie_value.split("utmctr=")
                try:
                    utmctr_value,temp1, temp2 = utmctr[1].partition('|')
                    utmz_value["Keyword"]=utmctr_value.replace('%20', " ")
                    print "utmz keyword: " + utmz_value["Keyword"] + "\n"
                except:
                    utmz_value["Keyword"]='unable to process, check offset'
            else:
                utmz_value["Keyword"]='utmctr not found' 
            
            #path to page on the site of the referring link
            if "utmcct" in cookie_value:
                utmcct = cookie_value.split("utmcct=")
                try:
                    utmcct_value,temp1, temp2 = utmcct[1].partition('|')
                    utmz_value["ReferringPage"]=utmcct_value.replace('%20', " ")
                except:
                    utmz_value["ReferringPage"]='unable to process, check offset'
                    
            else:
                utmz_value["ReferringPage"]='utmcct not found'
            
            
            #print(self.current_file + "\t" + str(file_offset) + "\t" + str(c_type) + "\t" + str(host) + "\t" + str(utmz_value['LastUpdate']) + "\t" + str(utmz_value["Source"]) +"\t" + str(utmz_value["CampName"]) + "\t" + utmz_value["AccesMethod"] + "\t" + str(utmz_value["Keyword"]) + "\t" + utmz_value["ReferringPage"] + "\n")   
            return utmz_value


    def parse_utm_gif(self, line):

        utm_gif={}

    #find utma value, _utma%3D55650728.920979037.1398568437.1398568437.1398568437.1
        pattern = r'(__utma%3D(\d+).(\d+).(\d+).(\d+).(\d+).(\d+)%3B)'
                
        utma = re.search(pattern,line)
                    
        if utma != None:
            file_offset = ""
            host = ""
            type = ""            
        #strip additional characters used for pattern matching so all we have are the utma values
            value = utma.group()[9:-3]
            #utma_v =parse_utma()
            utma_v = parse_utma(value,file_offset,host,"gif",False)
             
            utm_gif["utma_created"] = utma_v['Created']
            utm_gif["utma_previous"] = utma_v["2ndRecentVisit"]
            utm_gif["utma_current"] = utma_v["MostRecent"]
            utm_gif["utma_hit"] = utma_v["Hit"]
        else:
            #na na na na hey hey hey goodbye
            
            utm_gif["utma_created"] = "NA"
            utm_gif["utma_previous"] = "NA"
            utm_gif["utma_current"] = "NA"
            utm_gif["utma_hit"] = "NA"     
        
        #utmhn -hostname utmhn=www.reddit.com
        pattern = r'(utmhn=)(.*?)&'
        utmhn = re.search(pattern,line)
        if utmhn != None:
            
            utm_gif["utmhn_hostname"]=utmhn.group(2)
        else:   
           
            utm_gif["utmhn_hostname"]="NA"    
                    
        #utmdt page titlePage
        pattern = r'(utmdt=)(.*?)&'
        utmdt = re.search(pattern,line)
        if utmdt != None:
           
            utm_gif["utmdt_page_title"] = urllib.unquote(utmdt.group(2))
        else:
                   
            utm_gif["utmdt_page_title"] = "NA"   
        
        
        #utmp page request
        pattern = r'(utmp=)(.*?)&'
        utmp = re.search(pattern,line)
                    
        if utmp != None:
            
            utm_gif["utmp_page_request"]=urllib.unquote(utmp.group(2))
        else:
            utm_gif["utmp_page_request"]="NA"
                    
        #utmr full referrall URL
        pattern = r'(utmr=)(.*?)&'
        utmr = re.search(pattern,line)
        if utmr != None:
            
            utm_gif["utmr_full_referral"] = urllib.unquote(utmr.group(2))
        else:
            
            utm_gif["utmr_full_referral"] = "NA"   
            
        return utm_gif   


    #########################  Functions to grep utma, umtb, utmz and utm.gif values for various browsers    ##########################


    def process_chrome_utma(self, pattern, chunk):
        global chrome_utma_count
        global loop
        global maxfilesize
        count = 0  
        #max size of host name
        max_size = 70    
        
        for m in pattern.finditer(chunk):
            #print "Chrome utma hit found at offset " + str(m.start())
            file_offset = (loop*(maxfilesize))+m.start()
                                    
            beginning_offset = m.start()-1  
            while count < max_size:
                chara = chunk[beginning_offset]
                try:
                    ascii_char= chara.decode('ascii')
                    valid = re.match(p_allowed_chars, ascii_char) is not None
                    if valid: 
                        beginning_offset = beginning_offset-1
                            
                        count = count + 1
                    else:
                        break
                except:
                    break
            #reset count
            count = 0
            end_offset = m.start()
            host = chunk[beginning_offset+1:end_offset]
                
            file_offset = (loop*(maxfilesize))+beginning_offset
            self.parse_utma(m.group(1),file_offset,host,"chrome")
            chrome_utma_count = chrome_utma_count + 1      
           
            
    def process_chrome_utmb(self, pattern, chunk):
        global chrome_utmb_count
        global loop
        global maxfilesize
        count = 0  
        max_size = 70

        #parse the chrome utmb cookies
        p = re.compile(chrome_pattern_utmb)
        for m in p.finditer(chunk):
            print "Chrome utmb Hit found at offset " + str(m.start())
                     
            chrome_utmb_count = chrome_utmb_count + 1
                           
            beginning_offset = m.start()-1  
            while count < max_size:
                chara = chunk[beginning_offset]
                try:
                    ascii_char= chara.decode('ascii')
                    valid = re.match(p_allowed_chars, ascii_char) is not None
                    if valid: 
                        beginning_offset = beginning_offset-1
                            
                        count = count + 1
                    else:
                        break
                except:
                    break
            end_offset = m.start()
            host = chunk[beginning_offset+1:end_offset]
            #reset count
            count = 0
            file_offset = (loop*(maxfilesize))+beginning_offset
            self.parse_utmb(m.group(2),file_offset,host,"chrome")
     
    def process_chrome_utmz(self, pattern,chunk):
        global chrome_utmz_count
        global loop
        global maxfilesize
        count = 0 
        #maximun size of Hostname
        max_size = 70
        
        p = re.compile(chrome_pattern_utmz)
        for m in p.finditer(chunk):
            print "Chrome utmz Hit found at offset " + str(m.start())
            
            chrome_utmz_count = chrome_utmz_count + 1
                
            beginning_offset = m.start()-1  
            while count < max_size:
                chara = chunk[beginning_offset]
                try:
                    ascii_char= chara.decode('ascii')
                    valid = re.match(p_allowed_chars, ascii_char) is not None
                    if valid: 
                        beginning_offset = beginning_offset-1
                            
                        count = count + 1
                    else:
                        break
                except:
                    break
            end_offset = m.start()
            host = chunk[beginning_offset+1:end_offset]
            #reset count
            count = 0
            
                
            file_offset = (loop*(maxfilesize))+beginning_offset
                
            self.parse_utmz((m.group())[6:-3],file_offset,host,"chrome")
            
     
    def process_firefox_utma(self, pattern, chunk):
        global ff_utma_count
        global loop
        global maxfilesize
        count = 0
        
        for m in pattern.finditer(chunk):
            #print "FireFox utma hit found at offset " + str(m.start())
               
            parts = re.split('([0-9]{0,10}\.){5}[0-9]{0,200}',m.group())
            host = parts[2]
                       
            if host != "":
                            
                file_offset = (loop*(maxfilesize))+m.start()
                self.parse_utma(m.group(),file_offset,host,"firefox")
                    
                ff_utma_count = ff_utma_count + 1
            
    def process_firefox_utmb(self, pattern,chunk):
        global ff_utmb_count
        global loop
        global maxfilesize
        #count = 0
        
        for m in pattern.finditer(chunk):
            print "FireFox utmb hit found at offset " + str(m.start())
                
            #get utmb value
            ff_utmb_count = ff_utmb_count + 1
                
            v_pattern = '([0-9]{0,10}\.){3}[0-9]{0,10}'
            v = re.search(v_pattern,m.group())
            value = v.group()
                        
            #get __utmb host
               
            parts = re.split('([0-9]{0,10}\.){3}[0-9]{0,10}',m.group())
            host = parts[2]
            
            file_offset = (loop*(maxfilesize))+m.start()
            self.parse_utmb(str(value),file_offset,host,"firefox")
            
    def process_firefox_utmz(self, p,chunk):
        global ff_utmz_count
        global loop
        global maxfilesize        
        
        for m in p.finditer(chunk):
            ff_utmz_count = ff_utmz_count + 1
            
            print "FireFox utmz hit found at offset " + str(m.start())
            pattern = '([0-9]{0,20}\.){4}'
            
            value = re.search('([0-9]{0,20}\.){4}',m.group())
            split1 = re.split(pattern,m.group())
           
            v= value.group()
               
            pattern = r'((\.?[a-zA-Z\d-]{0,63}\.){1,2}[a-zA-Z]{0,4}\/[TS]?)'
            split2 = re.split(pattern,split1[2])
            
            h = re.search(pattern,m.group())
            if h != None:
                host = h.group()[:-2]
                self.processed = self.processed + 1
                file_offset = (loop*(maxfilesize))+m.start()   
                self.parse_utmz(m.group(2),file_offset,host,"firefox")
                 
            else:
                file_offset = (loop*(maxfilesize))+m.start()
                info = str(file_offset) + " " + str(m.group())
                not_processed.append(info)    

    def process_ie_utma(self, p,chunk):
        global ie_utma_count
        global maxfilesize
        
        p = re.compile(ie_utma_pattern)
        for m in p.finditer(chunk):
            file_offset = (loop*(maxfilesize))+m.start()
            print "IE utma hit found at offset " + str(file_offset)
            ie_utma_count =  ie_utma_count+1
            host = str(m.group(5).rstrip('\n'))
            self.parse_utma(m.group(2),file_offset,host, "ie")
               
    def process_ie_utmb(self, p,chunk):
        global ie_utmb_count
        global maxfilesize
        for m in p.finditer(chunk):
            file_offset = (loop*(maxfilesize))+m.start()
            print "IE utmb hit found at offset " + str(file_offset)
                   
            ie_utmb_count = ie_utmb_count + 1
                           
            host = m.group(5).rstrip("\n")
            file_offset = (loop*(maxfilesize))+m.start()
            self.parse_utmb(m.group(2).rstrip("\n"),file_offset,host,"ie")
            
    def process_ie_utmz(self, p,chunk):
        global ie_utmz_count
        global maxfilesize
        for m in p.finditer(chunk):
            file_offset = (loop*(maxfilesize))+m.start()
            print "IE utmz hit found at offset " + str(file_offset)
                
            #get utmb value
            ie_utmz_count = ie_utmz_count + 1
            host = m.group(4).rstrip("\n")
            file_offset = (loop*(maxfilesize))+m.start()    
            self.parse_utmz(m.group(2).rstrip("\n"),file_offset,host,"ie")
          
    def process_apple_utma(self, pattern,chunk):
        global loop
        global apple_utma_count
        global maxfilesize
        
        for m in pattern.finditer(chunk):
            file_offset = (loop*(maxfilesize))+m.start()
            print "apple utma hit found at offset " + str(file_offset)
                  
            host = m.group(4)
            self.parse_utma(m.group(2),file_offset,host,"apple")
            apple_utma_count = apple_utma_count + 1

    def process_apple_utmb(self, pattern, chunk):
        global loop
        global apple_utmb_count
        global maxfilesize
        
        for m in pattern.finditer(chunk):
            file_offset = (loop*(maxfilesize))+m.start()
            print "apple utmb hit found at offset " + str(file_offset)
            
            apple_utmb_count = apple_utmb_count + 1
            host = m.group(4)
            self.parse_utmb(m.group(2),file_offset,host,"apple")
            file_offset = (loop*(maxfilesize))+m.start()
     
    def process_apple_utmz(self, pattern,chunk):
        global apple_utmz_count
        global maxfilesize
        global loop
        
        for m in pattern.finditer(chunk):
            file_offset = (loop*(maxfilesize))+m.start()
            print "apple utmz hit found at offset " + str(file_offset)
                    
            apple_utmz_count = apple_utmz_count + 1
            host = m.group(4)
            self.parse_utmz(m.group(2),file_offset,host,"apple")
          
    def process_utm_gif_UTF16(self, pattern,chunk):
        global gif__UTF16_count
        global maxfilesize
        count = 0
        line = ""
        max_size = 2000
        #gif_cache_pattern
        p = re.compile(gif_cache_pattern_UTF16)
        for m in p.finditer(chunk):
            count =0
            gif__UTF16_count = gif__UTF16_count + 1
            file_offset = (loop*(maxfilesize))+m.start()
            print "UTF16 gif hit found at offset " + str(file_offset)
            line = ""
            beginning_offset = m.start()
            while count < max_size:
                chara = chunk[beginning_offset] + chunk[beginning_offset+1]
                try:
                    ascii_char= chara.decode('utf-16','ignore')
                    line = line + str(ascii_char)
                    beginning_offset +=2
                    count = count +2
                except:
                    break
                                       
            if line:
                utm_gif = self.parse_utm_gif(line)
                
                #print utma values
                print(self.current_file + "\t"+ str(file_offset) + "\t" + "utm.gif UTF16\t" + (utm_gif['utma_created']) + "\t" + str(utm_gif["utma_previous"]) +"\t" + str(utm_gif["utma_current"]) + "\t" +  str(utm_gif["utma_hit"]) + "\t")
                
                #print utmhn value
                print(utm_gif["utmhn_hostname"]+"\t")
                
                #utmdt page title
                print(utm_gif["utmdt_page_title"]+ "\t")
                   
                #utmp page request
                print(utm_gif["utmp_page_request"] + "\t")
                  
                #utmpr full referral URL
                print(utm_gif["utmr_full_referral"]+ "\n")
             
    def process_utm_gif_ASCII(self, pattern, chunk):        
        count = 0
        line = ""
        max_size = 2000
        global gif_ASCII_count
        global maxfilesize
        
        p = re.compile(gif_cache_pattern_ASCII)
        for m in p.finditer(chunk):
            count =0
            gif_ASCII_count = gif_ASCII_count + 1
            file_offset = (loop*(maxfilesize))+m.start()
            print "ASCII gif hit found at offset " + str(file_offset)
            line = ""
            beginning_offset = m.start()
            while count < max_size:
                try:
                    chara = chunk[beginning_offset]
                except:
                    not_processed.append(str(file_offset) + m.group())
                    break
                try:
                    ascii_char= chara.decode('ascii')
                        
                    line = line + str(ascii_char)
                    beginning_offset +=1
                    count = count +1
                except:
                    break
                                      
            if line:
                utm_gif = self.parse_utm_gif(line)
                
                #print utma values
                print(self.current_file + "\t"+ str(file_offset) + "\tutm.gif ASCII\t" + (utm_gif['utma_created']) + "\t" + str(utm_gif["utma_previous"]) +"\t" + str(utm_gif["utma_current"]) + "\t" +  str(utm_gif["utma_hit"]) + "\t")
                
                #print utmhn value
                print(utm_gif["utmhn_hostname"]+"\t")
                
                #utmdt page title
                print(utm_gif["utmdt_page_title"]+ "\t")
                   
                #utmp page request
                print(utm_gif["utmp_page_request"] + "\t")
                  
                #utmpr full referall URL
                print(utm_gif["utmr_full_referral"]+ "\n")
                


    
