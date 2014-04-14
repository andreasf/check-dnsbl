check-dnsbl
===========

Checks a list of DNS blocklists for hosts and IPs.

Given any hostname or IP address, this will try to resolve the matching
IP/hostname, and check for both in all blocklists. For every match that
is found, a warning is written to STDERR, and the return code will be 1.
Gevent is used for concurrent lookups, the number of active greenlets
is limited to (the constant) PARALLELISM.

Example usage:

```
$ check-dnsbl.py gmail.com test 8.8.8.8
WARNING: test found in spam blocklist dob.sibl.support-intelligence.net!
WARNING: test found in spam blocklist dbl.spamhaus.org!
WARNING: 8.8.8.8 found in spam blocklist cblless.anti-spam.org.cn!
WARNING: 8.8.8.8 found in spam blocklist cbl.anti-spam.org.cn!
WARNING: 8.8.8.8 found in spam blocklist cblplus.anti-spam.org.cn!
```
