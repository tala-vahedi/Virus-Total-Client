# Script Purpose: Create a Virus Total Client
# Script Version: 1.0 
# Script Author:  Tala Vahedi

# Script Revision History:
# Version 1.0 Nov 24, 2021, Python 3.x


# IMPORT MODULES
# Standard Python Libraries
import json
import hashlib
import os
import pandas as pd
from virus_total_apis import PublicApi as VirusTotalPublicApi

# Script Constants
SCRIPT_NAME    = "Script: Create a Virus Total Client"
SCRIPT_VERSION = "Version 1.0"
SCRIPT_AUTHOR  = "Author: Tala Vahedi"

# enter API key here
API_KEY = 'xxxxxxxxxxxxxxxxxxxxxxxxxxx'

if __name__ == '__main__':
    # print basic script info
    print()
    print(SCRIPT_NAME)
    print(SCRIPT_VERSION)
    print(SCRIPT_AUTHOR)
    print()

    # prompting the user for a directory path continoulsy 
    while True:
        # prompting user to enter a path or enter 'exit' to end the program
        fileDir = input("Please enter a path (or enter 'exit' to stop the program): ")
        # condition that ends the program if user inputs 'exit'
        if fileDir == "exit":
            exit()
        # if path is not found, prompt the user to re-enter a path or exit the program
        elif os.path.exists(fileDir) == False:
            print("ERROR: Invalid file path, please try another path\n")
            continue
        # print processing the file path and break while statement to continue with code
        else:
            print("\nProcessing File, please wait...\n")
            break
    
    # using the os.listdir() method to extract filenames from the directory path
    directory = os.listdir(fileDir)
    # looping through each filename and instantiating an object using the FileProcessor Class
    for fileName in directory:
        with open(os.path.join(fileDir, fileName), 'r') as f:
            # getting contents of the file
            text = f.read().encode("utf-8")
            # creating an md5 hash of the content to validate agaisnt
            MD5 = hashlib.md5(text).hexdigest()
            # validating whether hash exists within vt
            vt = VirusTotalPublicApi(API_KEY)
            # getting response
            response = vt.get_file_report(MD5)
            # getting  the json data
            res = json.dumps(response, sort_keys=False, indent=4)
            # loading the json data
            data = json.loads(res)
            # creating an empty list to hold all data
            lst = []
            # iterating through the scanned results since it is a dict
            for key, value in data['results']['scans'].items():
                # checking to see if the virus was detected with "true"
                if value['detected'] == True:
                    # appending the viruses that were detected into a master list
                    lst.append(key)
                else:
                    # if not detected do not append anything
                    lst.append(None)
            
            # printing out results of our scan based on master list created above
            if None in lst:
                print(fileName + " is clean.  No VirusTotal matches detected. ")
            else:
                print(fileName + " includes the following VirusTotal matches:")
                for virus in lst:
                    print(virus)
