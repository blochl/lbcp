lbcp
====

Basic Python backup script to Amazon's S3

Provides locally compressed & encrypted, file-level deduplicated backup to S3. (AWS account required)

The files are not broken into parts, thus can be downloaded & decrypted manually anytime.

Usage examples:

Backup
======


Features not implemented yet:

1) Search capabilities.

2) Browsing the backed up directory tree.

3) Deletion of backed-up files/directories.

Since this is meant to serve as an additional backup (for the case that the local backup fails) these features are not crucial, but eventually I'd like to implement them.
