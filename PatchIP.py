import subprocess
import time
import sys
import os
import operator

def command(cmd):
    try:
        result = subprocess.check_output(cmd, shell=True)
        result = result.decode().split('\n')[:-1]
    except:
        result = ''

    return result

def NetCheck(ip):
    res = os.system('ping '+str(ip)+' -c 1 -w 1')

    if res == 0:
        return 0 #NOT
    else:
        return 1 #OK

if __name__ == '__main__':
    argc = len(sys.argv)
    if argc != 2:
        print("usage: ipHook.py [firmware] [index]")
        exit()

    FIRMWARE = sys.argv[1]
    filename = FIRMWARE+'_PATCH.tar.gz'

    OUTPUT = '_'+FIRMWARE+'.extracted'
    IPlist = [0 for i in range(255)] #ip research

    command('rm -r '+OUTPUT)
    #time.sleep(100000)

    print('[+] Firmware Extract using binwalk.....')
    command('binwalk -Me {}'.format(FIRMWARE)) 

    ls = command('ls')

    if filename in ls:
        command('rm -r ./'+filename)

    if OUTPUT in ls:
        print('[*] Success!!')
    else:
        print('[-] Extract Error')
        sys.exit(-1)

    os.chdir('./'+OUTPUT)
    result = command('grep -r "192.168" ./')

    s = "[*] Search Firmware Webserver IP."
    print(s)
    for data in result:
        for i in range(0,256): #0~255
            if '192.168.'+str(i) in data:
                IPlist[i] += 1
                break


    ip, value = max(enumerate(IPlist), key=operator.itemgetter(1))

    search = []
    for i in range(len(IPlist)):
        if(IPlist[i] == 0):
            search.append(i)

    print(search)
    print('\n\n')
    X = input('Input x of Change IP(192.168.x.1) : ') 
    x = int(X)
    
    res = NetCheck('192.168.'+str(x)+'.1')

    if res == 0:
        print("[-] Can not use IP address. ")
        sys.exit(-1)

    print("[*] IP OK")
    cmd = 'find . -name "*" -exec perl -pi -e "s/192.168.'+str(ip)+'/192.168.'+str(x)+'/g" {} \;'
    command(cmd+' 2> /dev/null')

    cmd = 'tar -czvf '+filename+' ./*'
    command(cmd)

    command('mv ./'+filename+' ../')
    os.chdir('../')

    ls = command('ls')

    if filename in ls:
        print("PATCH Success!!!")

