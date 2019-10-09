# :apple: ARDvark 

ARDvark parses the Apple Remote Desktop (ARD) database file, and associated cache files to pull out application usage, user activity, and filesystem listing\
The ARD database contains information about all systems within an ARD deployment in an enterprise.

## ARD Artifacts to Parse
The ARD database file collects user login activity and detailed application usage from all reporting ARD client systems.
This information been confirmed for macOS 10.14 (Mojave). 

The ARD database file ("RMDB") is located at the following location and is only populated on ARD administrator systems:\
`/private/var/db/RemoteManagement/RMDB/rmdb.sqlite3`

The following plist files exist on ARD client systems and contain cached user activity and application usage that is eventually written to the RMDB:
1.  `/private/var/db/RemoteManagement/caches/UserAcct.tmp`
2.  `/private/var/db/RemoteManagement/caches/AppUsage.plist`

The `/private/var/db/RemoteManagement/caches/filesystem.cache` file is a database that contains a complete file listing of the ARD client system.\

The plists are also forwarded to the ARD ADMIN SYSTEM and are stored in subdirectories within the `/private/var/db/RemoteManagement/ClientCaches` directory. 
The plists are renamed to the reporting client system's MAC address. For example:
1. `/private/var/db/RemoteManagement/ClientCaches/ApplicationUsage/{macaddress}` -> AppUsage.plist files sent by all ARD CLIENT SYSTEMS
2. `/private/var/db/RemoteManagement/ClientCaches/UserAccounting/{macaddress}` -> UserAcct.tmp files sent by all ARD CLIENT SYSTEMS
3. `/private/var/db/RemoteManagement/ClientCaches/SoftwareInfo/{macaddress}` -> filesystem.cache files sent by all ARD CLIENT SYSTEMS

## ARDvark Results
ARDvark can provide the following information:\
Application Usage:
* Host name (RMDB only)
* MAC address (RMDB only)
* Application path
* Application name
* Launch time
* Frontmost time
* End time
* User
* Last report time
* Whether or not the application was running at the time of last report to the ARD admin system

User Activity:
* Host name (RMDB only)
* MAC addess (RMDB only)
* Last report time
* Username
* Login type
* Login time
* Logout time
* Source system (not consistently present)


## Usage
`ardvark.py [-h] [-d rmdb.sqlite3] [-u UserAcct.tmp] [-a AppUsage.plist] [-f filesystem.cache]`

NOTE: Due to the size of the rmdb.sqlite3 and filesystem.cache files, parsing isn't instantaneous. Please be patient.

#### Parsing RMDB:
`ardvark.py -d rmdb.sqlite`\
This will produce 2 output files in your working directory:
* AppUsageRMDB.csv
* UserActivityRMDB.csv

#### Parsing User Activity files:
`ardvark.py -u UserAcct.tmp`\
ARDvark will accept UserAcct.tmp files fromm client systems, or the files under `/private/var/db/RemoteManagement/ClientCaches/UserAccounting` 
on on ARD administrator system.\
This will produce 1 output file in your working directory:
* UserActivityPlist.csv

#### Parsing AppUsage.plist files:
`ardvark.py -u AppUsage.plist`\
ARDvark will accept AppUsage.plist files from client systems, or the files under `private/var/db/RemoteManagement/ClientCaches/ApplicationUsage`
on on ARD administrator system.\
This will produce 1 output file in your working directory:
* AppUsagePlist.csv

#### Parsing filesystem.cache files:
`ardvark.py -f filesystem.cache`\
This will produce 1 output file in your working directory:
* fscache.txt