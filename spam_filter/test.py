#!/usr/bin/python

import os

for i in range(1,76):
    if i != 69:
        command = "procmail .procmailrc < junkMail_{}".format(i)
        os.system(command)