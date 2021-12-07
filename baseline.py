#!/usr/bin/python
import sys
import os
import json
import argparse
import sys
import subprocess
import re
from zipfile import ZipFile
import tempfile


ANSI_BLUE = "\u001B[34m"
ANSI_RED = "\u001B[31m"
ANSI_YELLOW = "\u001B[33m"
ANSI_WHITE = "\u001B[37m"
ANSI_GREEN = "\u001B[32m"
ANSI_RESET = "\u001B[0m"

SUMMARY_TABLE_SEPARATOR_WIDTH_VERBOSE = 222
SUMMARY_TABLE_SEPARATOR_WIDTH = 178

HEADER_FORMAT_VERBOSE = " {:>5} {:<30} {:50} {:>14} {:>14} {:>44} {:>43} {:>13}"
ROW_FORMAT_VERBOSE = " {:>5} {:<30} {:50} {:>23} {:>23} {:>53} {:>52} {:>22}"
FOOTER_FORMAT_VERBOSE = " {:>5} {:<30} {:50} {:>29} {:>88} {:>13}"

HEADER_FORMAT = " {:>5} {:<30} {:50} {:>14} {:>14} {:>44}{:>13}"
ROW_FORMAT = " {:>5} {:<30} {:50} {:>23} {:>23} {:>53} {:>22}"
FOOTER_FORMAT = " {:>5} {:<30} {:50} {:>29} {:>44} {:>13}"

def red(s):
    return ANSI_RED + s + ANSI_RESET
def green(s):
    return ANSI_GREEN + s + ANSI_RESET
def blue(s):
    return ANSI_BLUE + s + ANSI_RESET
def filler(s):
    return s + (" " * 9)

def isTool(name):
    rc = subprocess.call(['which', name])
    return rc == 0

def getSeperator(separatorChar, verbose):
    width = SUMMARY_TABLE_SEPARATOR_WIDTH_VERBOSE if verbose  else SUMMARY_TABLE_SEPARATOR_WIDTH
    return separatorChar * width

def getHeader(verbose):
    output = getSeperator("=", verbose) + "\n"

    if verbose:
        output += HEADER_FORMAT_VERBOSE.format("", "APK", "Package", "Version", "Installed", "Version", "Installed", "Installed") + "\n"
        output += HEADER_FORMAT_VERBOSE.format("", "Filename", "Name", "Code", "Version Code", "Name", "Version Name", "Partition") + "\n"
    else:
        output += HEADER_FORMAT.format("", "APK", "Package", "Version", "Installed", "Installed", "Installed") + "\n"
        output += HEADER_FORMAT.format("", "Filename", "Name", "Code", "Version Code", "Version Name", "Partition") + "\n"
    output += getSeperator("=", verbose)
    return output

def getSummaryRow(app, appNum, verbose):

    def rowToString():
        if verbose:
            return ROW_FORMAT_VERBOSE.format(f"[{appNum}]", app["apk"], app["package"], versionCode, installedVersionCode, versionName, installedVersionName, installedPartition)
        else:
            return ROW_FORMAT.format(f"[{appNum}]", app["apk"], app["package"], versionCode, installedVersionCode, installedVersionName, installedPartition)


    installedPartition = app["installedPartition"]
    installedPartitionSuffix = ""
    if app["isPreInstalled"] and app["isOnDataPartition"]:
        installedPartitionSuffix = "*"

    if app["excluded"]:
        versionCode = blue(app["versionCode"])
        versionName = blue(app["versionName"])
        installedVersionCode = blue(app["installedVersionCode"])
        installedVersionName = blue(app["installedVersionName"])
        installedPartition = blue(app["installedPartition"] + installedPartitionSuffix)
    else:
        versionCode = green(app["versionCode"])
        versionName = green(app["versionName"])
        installedVersionCode = green(app["installedVersionCode"])
        installedVersionName = green(app["installedVersionName"])
        installedPartition = filler(app["installedPartition"] + installedPartitionSuffix)

    if not app["versionCodeMatched"]:
            versionCode = red(app["versionCode"])
            installedVersionCode = red(app["installedVersionCode"])

    if not app["versionNameMatched"]:
            versionName = red(app["versionName"])
            installedVersionName = red(app["installedVersionName"])

    if app["canUninstallToBaseline"]:
        installedPartition = green(app["installedPartition"] + installedPartitionSuffix)

    if app["installedVersionUnknown"]:
        installedVersionCode = red("Unknown")
        installedVersionName = red("Unknown")
        installedPartition = red(app["installedPartition"] + installedPartitionSuffix)

    return rowToString()


def getFooter(apps, verbose):
    numApps = len(apps)
    codeMismatches = sum(a["versionCodeMatched"] == False for a in apps)
    nameMismatches = sum(a["versionNameMatched"] == False for a in apps)
    mismatches = sum((a["versionCodeMatched"] == False) or (a["versionNameMatched"] == False) for a in apps)
    dataPartition = sum(a["installedPartition"] == "/data" for a in apps)
    output = getSeperator("-", verbose) + "\n"
    if verbose:
        output += FOOTER_FORMAT_VERBOSE.format("", f"Total # of apps: {numApps}", f"Total Mismatches: {mismatches}", f"Version Code Mismatches: {codeMismatches}", f"Version Name Mismatches: {nameMismatches}", f"/data: {dataPartition}") + "\n"
    else:
        output += FOOTER_FORMAT.format("", f"Total # of apps: {numApps}", f"Total Mismatches: {mismatches}", f"Version Code Mismatches: {codeMismatches}", f"Version Name Mismatches: {nameMismatches}", f"/data: {dataPartition}") + "\n"

    output += getSeperator("=", verbose)
    return output


def performAudit(zipFilename, excludePackages, appendVersionCodeToPackage, tempDir):
    apps = []
    appDetails = {}

    numCodeandNameMismatches = 0
    numCodeMismatches = 0
    numNameMismatches = 0
    numUnknowns = 0
    totalMismatches = 0
    both = []
    code = []
    name = []
    unknown = []

    print(f"\nAnalyzing file: {zipFilename}\n")

    with ZipFile(zipFilename, 'r') as zipObject:
       listOfFileNames = zipObject.namelist()
       for filename in listOfFileNames:
           if filename.endswith('.apk'):
                print(".", end="", flush=True)

                extractedFilename = f'{tempDir.name}/{filename}'
                zipObject.extract(filename, tempDir.name)

                cmd = f"aapt2 dump badging {extractedFilename}| grep package"
                appInfo = subprocess.getoutput(cmd)

                result = re.search(r".*package: name='(.*?)' versionCode='(\d+)' versionName='(.*?)'", appInfo)
                packageName = result.group(1)
                versionCode = result.group(2)
                versionName = result.group(3).split(' ')[0]
                installedVersionCode = ""
                installedVersionName = ""

                dumpsysPackageName = packageName
                if packageName in appendVersionCodeToPackage:
                    dumpsysPackageName = f"{packageName}_{versionCode}"

                adbcmd = f"adb shell dumpsys package {dumpsysPackageName}"

                dumpSys = subprocess.getoutput(adbcmd)
                installedPartition = "Unknown"
                preInstalledVersionCode = ""
                preInstalledVersionName = ""
                preInstalledPartition = ""
                canUninstall = False
                canUninstallToBaseline = False

                result = re.search(r"(?s)Packages:.*?codePath=(\S+?)\/.*?versionCode=(\d+) minSdk.*?versionName=(\S+)", dumpSys)
                if result:
                    installedPartition = result.group(1)
                    installedVersionCode = result.group(2)
                    installedVersionName = result.group(3)
                    if installedPartition == "/data":
                        canUninstall = True

                result = re.search(r"(?s)Hidden system packages:.*?codePath=(\S+?)\/.*?versionCode=(\d+) minSdk.*?versionName=(\S+)", dumpSys)
                if result:
                    if canUninstall:
                        preInstalledPartition = result.group(1)
                        preInstalledVersionCode = result.group(2)
                        preInstalledVersionName = result.group(3)
                    else:
                        installedPartition = result.group(1)
                        installedVersionCode = result.group(2)
                        installedVersionName = result.group(3)

            
                if canUninstall and (versionCode != installedVersionCode) and (versionCode == preInstalledVersionCode):
                    canUninstallToBaseline = True


                excluded = packageName in excludePackages
                isPreInstalled = preInstalledPartition != ""
                isOnDataPartition = "/data" == installedPartition

                appDetails = {
                    "apk": filename,
                    "extractedFilename": extractedFilename,
                    "excluded": excluded,
                    "package": packageName,
                    "versionCode": versionCode,
                    "versionName": versionName,
                    "installedVersionCode": installedVersionCode,
                    "installedVersionName": installedVersionName,
                    "canUninstall" : canUninstall,
                    "canUninstallToBaseline" : canUninstallToBaseline,
                    "isPreInstalled": isPreInstalled,
                    "preInstalledPartition": preInstalledPartition,
                    "preInstalledVersionCode": preInstalledVersionCode,
                    "preInstalledVersionName": preInstalledVersionName,
                    "versionCodeMatched": False,
                    "versionNameMatched": False,
                    "installedVersionUnknown": False,
                    "installedPartition": installedPartition,
                    "isOnDataPartition": isOnDataPartition
                }

                if not installedVersionCode:
                    numUnknowns += 1
                    appDetails["installedVersionUnknown"] = True
                    totalMismatches += 1
                    unknown.append(filename)
                    apps.append(appDetails)
                    continue
        
                versionCodeMatch = (versionCode == installedVersionCode)
                versionNameMatch = (versionName == installedVersionName)

                if versionCodeMatch and versionNameMatch or excluded:
                    appDetails["versionCodeMatched"] = True
                    appDetails["versionNameMatched"] = True
                    apps.append(appDetails)
                    continue

                if versionCodeMatch and not versionNameMatch:
                    numNameMismatches+= 1
                    totalMismatches += 1
                    name.append(filename)
                    appDetails["versionCodeMatched"] = True
                    apps.append(appDetails)
                    continue

                if versionNameMatch and not versionCodeMatch:
                    numCodeMismatches+= 1
                    totalMismatches += 1
                    code.append(filename)
                    appDetails["versionNameMatched"] = True
                    apps.append(appDetails)
                    continue

                if not versionCodeMatch and not versionNameMatch:
                    numCodeandNameMismatches+= 1
                    totalMismatches += 1
                    both.append(filename)
                    apps.append(appDetails)
    return apps

def outputSummaryTable(apps, verbose):
    print(getHeader(verbose))
    appNum = 0
    for app in apps:
        appNum += 1
        print(getSummaryRow(app, appNum, verbose))

    print(getFooter(apps, verbose))

# Main program

parser = argparse.ArgumentParser(description='Audit and optionally update a device against a baseline set of apks specified in a zip file.')
parser.add_argument('zipFilename', help='The name of the zip file containing the baseline apks.')
parser.add_argument('-u', dest='updateApps', action='store_true', default=False, help='Update mismatched apps to baseline')
parser.add_argument('-c', dest='config', action='store', default="", help='Config file')
parser.add_argument('-j', dest='outputToJson', action='store_true', default=False, help='Output GTVS app baseline info to <zipFilename>.json file')
args = parser.parse_args()


if not isTool('aapt2'):
    print("aapt2 must be in your search path and have executable permissions, exiting")
    sys.exit()

tempDir = tempfile.TemporaryDirectory()

excludePackages = []
appendVersionCodeToPackage = ["com.google.android.trichromelibrary"]

if args.config:
    print(args.config)
    file = open(args.config)
    config = json.load(file)
    print(config)
    excludePackages = config["excludePackages"]
    appendVersionCodeToPackage = config["appendVersionCodeToPackage"]
    file.close()

apps = performAudit(args.zipFilename, excludePackages, appendVersionCodeToPackage, tempDir)
print("\n")

showInstalledVersionNameColumn = (sum(a["versionNameMatched"] == False for a in apps) > 0)
outputSummaryTable(apps, showInstalledVersionNameColumn)


if args.outputToJson:
    jsonFilename = f"{os.path.splitext(args.zipFilename)[0]}.json"
    print(f"\nOutputting to GTVS App info to {jsonFilename}\n")
    jsonString = json.dumps(apps, indent=2)
    jsonFile = open(jsonFilename, "w")
    jsonFile.write(jsonString)
    jsonFile.close()

adbCmds = []
for app in apps:
    if app["versionCodeMatched"] and app["versionNameMatched"]:
        continue

    if app["canUninstallToBaseline"] or app["canUninstall"]:
        adbCmds.append(f'adb uninstall {app["package"]}')

    if app["canUninstallToBaseline"]:
        continue

    adbCmds.append(f'adb install -r {app["extractedFilename"]}')


if len(adbCmds) == 0:
    sys.exit()

if not args.updateApps:
    print("\nUse the -u option to update this device to baseline.  The following commands will be run:")
    print("=========================================================================================")
else:
    print("\nUpdating device to baseline:")
    print("============================")    



for adbCmd in adbCmds:
    print(adbCmd)
    if args.updateApps:
        result = subprocess.getoutput(adbCmd)    
        print(result)
print("\n")

tempDir.cleanup()
