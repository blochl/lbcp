lbcp
====

Basic Python backup script to Amazon's S3

Provides locally compressed & encrypted, file-level deduplicated backup to S3. (AWS account required)

The files are not broken into parts, thus can be downloaded & decrypted manually anytime.

Usage examples
==============

Backup:

lbcp.py backup [-e PATTERN [PATTERN ...]] [-d DEVICE] [-c PATH] [--bucket BUCKET] [--oldlogbucket BUCKET] [--credsenc] [--geolocation LOCATION] [--logpath PATH] BACKUPPATH [BACKUPPATH ...]

For example:

lbcp.py backup -e .directory -d MY-LAPTOP -c /path/to/creds.csv --bucket MY-BUCKET --oldlogbucket BUCKET-FOR-OLD-LOGS --geolocation EU --logpath /home/user/.lbcp \<path 1\> \<path 2\> \<path 3\>

Minimal options (you will be prompted for additional options, and default settings will be used):

lbcp.py backup \<path 1\> \<path 2\> \<path 3\>

(If it is your first backup on a device, you also need to specify the credentials file location, -c)

==============

Restore:

lbcp.py restore [-d DEVICE] [-c PATH] [--bucket BUCKET] [--credsenc] [--logpath PATH] RESTOREPATH [RESTOREPATH ...] SAVEPATH

For example:

lbcp.py restore -d MY-LAPTOP -c /path/to/creds.csv --bucket MY-BUCKET --logpath /home/user/.lbcp \<path 1\> \<path 2\> \<path 3\> \<WHERE TO SAVE THE RESTORE\>

Minimal options (you will be prompted for additional options, and default settings will be used):

lbcp.py restore \<path 1\> \<path 2\> \<path 3\> \<WHERE TO SAVE THE RESTORE\>

(If you are restoring to a different device, you also need to specify the credentials file location, -c)

==============

Encryption & Decryption (encrypt/decrypt one file locally):

lbcp.py encrypt PLAINTEXT_FILE ENCRYPTED_FILE

lbcp.py decrypt ENCRYPTED_FILE PLAINTEXT_FILE

==============

See help (lbcp.py -h) for explanation of the different options.

==============

Works on Linux, requires the following:

1) Python 2.7

2) Numpy

3) Python Cryptography Toolkit (pycrypto)

4) Boto

5) Progressbar (text progressbar library for python)

(And may be more packages - depends on your installation)

==============

License: GPLv2.

==============


Features not implemented yet:

1) Search capabilities.

2) Browsing the backed up directory tree.

3) Deletion of backed-up files/directories.

Since this is meant to serve as an additional backup (for the case that the local backup fails) these features are not crucial, but eventually I'd like to implement them.
