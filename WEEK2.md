# WEEK 2 
## BANDIT LEVEL 12- LEVEL 21:- 
### LEVEL12:-

Login to the host using 
`$ ssh bandit12@bandit.labs.overthewire.org -p2220`
The goal is to decompress the hexdump file to retrieve the password  from the file data.txt which is repeatedly compressed. 
First , use the cat command to read the file

`ls`

`cat data.txt`

we get the output as follows

![Screenshot from 2023-10-27 11-22-30](https://github.com/vishwatejD/BanditOTW/assets/141154035/910ba88b-0931-40f5-bf26-6d015a3ec201)

The command used for decrypting the hexdump file into normal file is xxd -r thus i used the command

`$ xxd -r data.txt > new`

but the permission is denied.

Using the hint in the question 

I created a new directory  using the following command

`$ mkdir /tmp/vishwa2006`

now as we have made a new directory which has various permissions we copy the data.txt file into the new directory using the command 

`$ cp data.txt /tmp/vishwa2006`

Now we dive into the new directory and check the files inside

`$ cd /tmp/vishwa2006`

`$ ls`

it shows 
![Screenshot from 2023-10-27 11-38-08](https://github.com/vishwatejD/BanditOTW/assets/141154035/515d3351-c2ba-42f7-8711-b33c2c94b6fe)

![Screenshot from 2023-10-27 11-41-10](https://github.com/vishwatejD/BanditOTW/assets/141154035/03ab6887-eb41-4354-ab24-aaeda720dfa6)


Now if we run the cat command on the decrypted ‘new’ file we get unreadable characters. If we run file command on new to know its type we get it is a gzip file….


![Screenshot from 2023-10-27 11-45-52](https://github.com/vishwatejD/BanditOTW/assets/141154035/4a7c263a-0c0a-49db-ae00-5d646d54f504)

if we try to decompress the file new using gzip -d we get

![Screenshot from 2023-10-27 11-50-42](https://github.com/vishwatejD/BanditOTW/assets/141154035/49c5d884-7b7b-4f11-b4d8-e6766ecc18da)

This is because the file extension is wrong. We thus change the name of the file using mv command.
`$ mv new new2.gz`

![Screenshot from 2023-10-27 11-55-21](https://github.com/vishwatejD/BanditOTW/assets/141154035/0d12927f-c796-4a1d-8e70-d11219c2b5b8)


Now the new2.gz file has been decompressed.(The extension changes as shown in th image)
it is now as bzip2 compressed file.
similar to 1st case now we change extension to bz2. then use bzip2 -d command to decrypt it. after its decryption we check the file type of new2 again, now it is gzip again.
we change its extension to gz

`$ mv new2.out new3.gz`

as we check the file type of new3 it is POSIX tar archive (GUI)
we change extension to new3.tar using mv command.
after we decompress the file using the tar xf command we can find the data5.bin file in the contents. 

Similarly after repeated decompression of files from data2.bin to data9.bin we get the final password in form of ascii text.

![Screenshot from 2023-10-27 11-55-21](https://github.com/vishwatejD/BanditOTW/assets/141154035/47af54d3-0433-4a00-82da-3e5435785afd)

PASSWORD:- wbWdlBxEir4CaE8LaPhauuOo6pwRmrDw
RESOURCES USED:- https://www.geeksforgeeks.org/cp-command-linux-examples/
https://www.geeksforgeeks.org/mv-command-linux-examples/

OTHER COMMANDS USED FOR HELP:- `man gzip`,`man bzip2`

### LEVEL13:-

Login to the host using $ ssh bandit13@bandit.labs.overthewire.org -p2220

Using the ls command we get to know that there is a file named as sshkey.private

Using cat command we get a long string named as private key.

Now we use the command ssh -i filename user@ hostname -port0000

`$ssh -i sshkey.private bandit14@localhost -p2220`

this takes us directly into the next level

![Screenshot from 2023-10-27 18-45-31](https://github.com/vishwatejD/BanditOTW/assets/141154035/a68ee697-8085-4893-994d-7db983bc111f)


If we want to know the password , we use the path given in etc/bandit_pass/bandit14

![Screenshot from 2023-10-27 18-50-25](https://github.com/vishwatejD/BanditOTW/assets/141154035/d0aadbfb-4798-4165-bab9-740db4320677)


PASSWORD:- fGrHPx402xGC7U7rXKDaxiWFTOiF0ENq

RESOURCES USED:- https://www.cloudbolt.io/blog/linux-how-to-login-with-a-ssh-private-key/

### LEVEL14:-

We are now already logged in in bandit14@bandit .

COMMANDS TO BE KNOWN FOR SOLVING THIS LEVEL:- nc

**nc** :-The Netcat ( nc ) command is **a command-line utility for reading and writing data between two computer networks.**

![Screenshot from 2023-10-27 19-00-18](https://github.com/vishwatejD/BanditOTW/assets/141154035/4919f897-17b5-42b7-891e-2ac989f72f1f)

We follow the above command, then enter the password to get the password for the next level.

![Screenshot from 2023-10-27 18-59-18](https://github.com/vishwatejD/BanditOTW/assets/141154035/6e4c6cf5-618f-481b-ab05-8ba6236bf7f8)

PASSWORD:- jN2kgmIXJ6fShzhT2avhotn4Zcka6tnt

RESOURCES USED:- https://www.geeksforgeeks.org/practical-uses-of-ncnetcat-command-in-linux/


### LEVEL15:-

Login to the host using `$ ssh bandit15@bandit.labs.overthewire.org -p2220`

The goal is to use ssl encryption do retrieve the password from the localhost.

The command syntax which is used for ssl encryption is 

`$ openssl s_client -connect hostname :[port]`
`$ openssl s_client -connect localhost :30001`

Then we enter the password. this gives the password for next level

![Screenshot from 2023-10-27 21-29-41](https://github.com/vishwatejD/BanditOTW/assets/141154035/c7108e92-3047-412f-9819-c990f9ef3326)

PASSWORD:- JQttfApK4SeyHwDlI9SXGR50qclOAil1

### LEVEL16:-

Login to the host using `$ ssh bandit16@bandit.labs.overthewire.org -p2220`

The goal is to retrieve the password from the specific file present in the ports range.

The command which helps us to scan for open ports is nmap.

The command to be used is `$ nmap localhost -p 31000-32000`

This command gives all of the open ports in the server.


![Screenshot from 2023-10-28 01-27-58](https://github.com/vishwatejD/BanditOTW/assets/141154035/8b046010-4d31-4f9c-a12b-420e74c0ec1c)

Now to know the service version present in the different ports we need to use the sV command along with the nmap scanning command.

`$ nmap localhost -p 31046,31518,31691,31790,31960 -sV`

this gives the version of all the open ports

There are two open ports with ssl service in them. After we input password in both of them we get the private key from port 31790.

![Screenshot from 2023-10-28 01-37-51](https://github.com/vishwatejD/BanditOTW/assets/141154035/eb916bcb-e486-45e9-8710-0b5714224c8c)

Now i copied the entire rsa private key. This is now only a simple text, i have to save it in a file this is done by nano command .This file is to be made in a tmp directory thus the following process must be followed.


![Screenshot from 2023-10-28 01-57-22](https://github.com/vishwatejD/BanditOTW/assets/141154035/99bcc921-441b-415b-b634-ba4a5c814b8f)


nano command is a line editor command where we paste the key and convert it to a file.

After we save the file then we can use the `$ssh -i filename bandit17@localhost -p2220 ` command to directly login into the next level.

NOTE:- the permissions of the rsa key must be changed because it must be kept secure. We thus use chmod command to change permission to 600.


![Screenshot from 2023-10-28 02-12-05](https://github.com/vishwatejD/BanditOTW/assets/141154035/e63ad8ea-c5c4-4ddd-a45a-4222c296e7f5)


**logic behind the permissions:-** 

-use ls -la command to know permissions

![Screenshot from 2023-10-28 02-28-06](https://github.com/vishwatejD/BanditOTW/assets/141154035/1bf37170-d002-4f5b-91ba-2c422395b361)

in 3rd line we can see -rw-rw-r

this says that the user can read and write it, groups can read and write it , people can read it.

4 stands for permission to read and 2 stands for permission to write.

Thus the user gets 6. and others get a 0.

Thus we used 600 with chmod command.

PASSWORD:- VwOSWtCA7lRKkTfbr2IDh6awj9RNZM5e

RESOURCES USED:- https://docs.digitalocean.com/support/how-to-troubleshoot-ssh-authentication-issues/#fixing-key-permissions-and-ownership

https://beebom.com/how-use-nano-linux/

https://www.techtarget.com/searchsecurity/feature/How-to-use-Nmap-to-scan-for-open-ports

### LEVEL17:-

As we are already logged in in level 17…

we use ls command to look at what files are present ,

it shows passwords.old and passwords.new 

To know the password we must know the string which is different in the files. The command which fulfills this task is diff command .

`$ diff passwords.new passwords.old`

![Screenshot from 2023-10-28 03-05-47](https://github.com/vishwatejD/BanditOTW/assets/141154035/11794842-4721-441f-a651-c33416862c3c)

The password is present in password.new so the 1st line is the password.

PASSWORD:- hga5tuuCLF6fFzUpnagiMN8ssu9LFrdg

### LEVEL18:- 

Login to the host using `$ ssh bandit18@bandit.labs.overthewire.org -p2220`

When logging in due to the modification of .bashrc we get a message byebye! and we are logged out of the server.

Thus we can use two commands at once 

`$ ssh bandit18@bandit.labs.overthewire.org -p2220 ls`

Then we use the following command

`$ ssh bandit18@bandit.labs.overthewire.org -p2220 cat readme`

PASSWORD:- awhqfNnAbc1naukrpqDYcF95h7HoMTrC

### LEVEL19:- 

Login to the host using `$ ssh bandit19@bandit.labs.overthewire.org -p2220`

To execute a file the command used is ./ 

Now we use that command along with the cat command and using the path given in question.

`$ ./bandit20-do cat /etc/bandit_pass/bandit20`

This gives us the password for the next level.

PASSWORD:- VxCazJaVykI6W36BkBU0mJTCM8rR95XT

### LEVEL20:-

Login to the host using `$ ssh bandit20@bandit.labs.overthewire.org -p2220`

To solve this level we use two shells simultaneously, one for logging into the port and listening and one for sending the password string.

In one shell , we use nc -l  [port] command,

`$ nc -l 2006`

This command is used to make the port listen to a incoming connection.

![Screenshot from 2023-10-28 19-01-35](https://github.com/vishwatejD/BanditOTW/assets/141154035/b13e3c6f-4345-44b0-bb8d-1cf13e86578b)


In other shell , type `$ ./suconnect 2006`

This command is used to send the password from one shell to other for checking.

Now we type password in the shell with nc command.

We receive the password for next level.

![Screenshot from 2023-10-28 19-58-21](https://github.com/vishwatejD/BanditOTW/assets/141154035/04367c05-9fe7-4065-bba5-a235674bffb2)


![Screenshot from 2023-10-28 19-58-50](https://github.com/vishwatejD/BanditOTW/assets/141154035/37279f6a-de45-407c-921b-ba0f2632ee29)

PASSWORD:- NvEJF7oVjkddltPSrdKEFOllh9V1IBcq

### LEVEL21:-

Login to the host using `$ ssh bandit21@bandit.labs.overthewire.org -p2220`

We now use ls command , but we dont find any file inside . Thus we use the path present in the question to enter the directory.

`$  cd /etc/cron.d/`

Now we use ls command to see all the files inside.

![Screenshot from 2023-10-28 20-31-11](https://github.com/vishwatejD/BanditOTW/assets/141154035/acdd43d2-e4a1-416c-89d4-3429be98faa9)

we require password for level 22 so we open cronjob_bandit22 using cat command.

![Screenshot from 2023-10-28 20-32-47](https://github.com/vishwatejD/BanditOTW/assets/141154035/73ecd9b3-5245-4c76-8a9e-a686d96c0b50)

It says that this file is being run at regular intervals.

If we use the path given in above file and use cat command again we will find the bash file which will repeat.

![Screenshot from 2023-10-28 20-46-15](https://github.com/vishwatejD/BanditOTW/assets/141154035/7127ae7c-b9c3-42ff-a1f7-6f5562c8431b)

This says that it changes permissions of the /tmp/t7O6lds9S0RqQh9aMcz6ShpAoZKF7fgv file and the password is in the file.

Thus we use cat command once again for that file to get the password.

PASSWORD:- WdDozAdTM2z9DiFEQ2mGlwngMfj4EZff



















































































