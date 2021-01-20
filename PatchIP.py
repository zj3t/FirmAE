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
    pwd = command('pwd')[0]

    OUTPUT = '_'+FIRMWARE+'.extracted'
    IPlist = [0 for i in range(255)] #ip research

    command('rm -r '+OUTPUT)
    #time.sleep(100000)

    print('[+] Firmware Extract using binwalk.....')
    command('binwalk -e {}'.format(FIRMWARE)) 

    ls = command('ls')
    #print(ls)

    #input(OUTPUT)
    if filename in ls:
        command('rm -r ./'+filename) #Already exist


    if OUTPUT in ls:
        print('[*] Success!!')
    else:
        print('[-] Extract Error')
        sys.exit(-1)

    os.chdir('./'+OUTPUT) #in
    
    #test code
    ls = command('ls')
    
    binfile = ''

    if len(ls) < 10:
        for f in ls:
            if '.bin' in f:
                binfile = f
                break

        command('find ./ ! -name "*.bin" -exec rm -rf {} \;')
        command('binwalk -e '+binfile)
        command('find ./ -name "*.bin" -exec rm -rf {} \;')

        ls = command('ls')

        os.chdir('./'+ls[0])
        command('mv ./* ../')
        os.chdir('../')
    
    ###
    NAT = input('Input Local IP x (192.168.x.N): ')

    result = command('grep -r "192.168." ./')

    s = "[*] Search Firmware Webserver IP."
    print(s)
    for data in result:
        for i in range(0,256): #0~255
            if '192.168.'+str(i)+'.' in data:
                IPlist[i] += 1
                break


    ip, value = max(enumerate(IPlist), key=operator.itemgetter(1))

    '''
    search = []
    for i in range(len(IPlist)):
        if(IPlist[i] == 0):
            search.append(i)

    print(search)
    print('\n\n')
    '''
    X = input('Input x(10~200) : ') 
    x = int(X)
    res = NetCheck('192.168.'+str(NAT)+'.'+str(x))

    if res == 0:
        print("[-] Can not use IP address. ")
        sys.exit(-1)

    print("[*] IP OK")

    cmd = 'find ./ -name "*" -exec perl -pi -e "s/192.168.'+str(ip)+'/192.168.'+str(NAT)+'/g" {} \;'
    command(cmd+' 2> /dev/null')

    cmd = 'find ./ -name "*" -exec perl -pi -e "s/192.168.'+str(NAT)+'.1'+'/192.168.'+str(NAT)+'.'+str(x)+'/g" {} \;'
    command(cmd+' 2> /dev/null')

    for i in range(0,10):
        cmd = 'find ./ -name "*" -exec perl -pi -e "s/192.168.'+str(NAT)+'.'+str(x)+str(i)+'/192.168.'+str(NAT)+'.1'+str(i)+'/g" {} \;'
        command(cmd+' 2> /dev/null')

    cmd = 'tar -czvf '+filename+' ./*'
    command(cmd)

    command('mv ./'+filename+' ../')
    os.chdir('../')

    ls = command('ls')

    if filename in ls:
        print("PATCH Success!!!")

