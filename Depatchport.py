#!/usr/bin/env python3
import os
import subprocess

def command(cmd):
    try:
        result = subprocess.check_output(cmd, shell=True)
        result = result.decode().split('\n')[:-1]
    except:
        result = ''

    return result

if __name__ == "__main__":
    os.chdir('./scripts')

    for i in range(1,10):
        find ="listen=:"+str(i)+"00"
        match = "listen=:200"
        cmd = 'find ./makeNetwork.py -name "*" -exec perl -pi -e "s/'+str(find)+'/'+str(match)+'/g" {} \;'
        command(cmd+' 2> /dev/null')
    print("Success Patch.")

    os.chdir('../')
