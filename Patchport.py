#!/usr/bin/env python3
import os
import sys
import subprocess

def command(cmd):
    try:
        result = subprocess.check_output(cmd, shell=True)
        result = result.decode().split('\n')[:-1]
    except:
        result = ''

    return result

def Patchport(INDEX):
    os.chdir('./scripts')

    for i in range(1,10):
        find ="listen=:"+str(i)+"00"
        match = "listen=:"+str(INDEX)+"00"
        cmd = 'find ./makeNetwork.py -name "*" -exec perl -pi -e "s/'+str(find)+'/'+str(match)+'/g" {} \;'
        command(cmd+' 2> /dev/null')
        print("Patch "+str(i))

    os.chdir('../')

if __name__ == "__main__":
    INDEX = sys.argv[1]
    argc = len(sys.argv)

    if argc != 2:
        print('Arguement Error')

    if int(INDEX) <= 0 or int(INDEX) > 9:
        sys.exit(-1)

    buf = []
    
    while True:
        if int(INDEX) >= 10:
            print("INDEX 0~9")
            sys.exit(-1)

        buf = command('netstat -nlp | grep "'+str(INDEX)+'001"')

        if len(buf) != 0:
            INDEX = input("Already Use, bind error...'\n INDEX : ")
        else:
            Patchport(INDEX)
            break
