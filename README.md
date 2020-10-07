# AWS File Encryption Tunkki

AWS File Encryption Tunkki is a small command line tool for password encrypting and decrypting files using AES-256 encryption and scrypt with 128-bit salts.
It can be used locally (to encrypt) as well as run on CI machines such as TravisCI (for decrypting).

*Note: This tool is released as MIT licensed open source software.*


### How to use
```
user@localhost:~$ crypto encrypt myfile.txt mysecretpassword
File encryption complete.

IMPORTANT! Salt: sgDEQWHyK5owYW1m

Make sure you keep your salt safe! It is required for decryption.

user@localhost:~$ ls -l
-rw-rw-r-- 1 user user 1101 Oct  7 15:53 myfile.txt
-rw-rw-r-- 1 user user 1101 Oct  7 15:53 myfile.txt.encrypted

user@localhost:~$ crypto decrypt myfile.txt.encrypted mysecretpassword sgDEQWHyK5owYW1m
File decryption complete.
```


### Example use case with TravisCI
Say your application has a directory called *secrets/* and inside it, you have some 
ssh keys or authentication certificates, etc. secret stuff you know..
It's common practice to NOT put these files into GitHub as is, so what you can do 
instead is to add the original files into your .gitignore and push encrypted copies 
of those files into GitHub. The idea is that you also encrypt a decryption key into 
your .travis.yml or other CI configuration file which will then decrypt those secret files on-fly 
right before deploying your application.


1. Encrypt file(s):
```
user@localhost:~$ crypto encrypt ./secrets/something.cert mysecretpassword
File encryption complete.

IMPORTANT! Salt: sgDEQWHyK5owYW1m

Make sure you keep your salt safe! It is required for decryption.
```

2. Encrypt password(s) and salt(s) into .travis.yml using TravisCI CLI:
```
travis encrypt MYCERT_PASSWORD=mysecretpassword --add
travis encrypt MYCERT_SALT=sgDEQWHyK5owYW1m --add
```

3. Add the following to `.travis.yml`:
```
before_deploy:
  - wget https://github.com/almamedia/aws-crypto-tunkki/releases/download/v1.0/crypto-linux
  - ./crypto-linux decrypt ./secrets/something.cert.encrypted $MYCERT_PASSWORD $MYCERT_SALT
```