from xml.etree.ElementTree import parse
from bs4 import BeautifulSoup
import sys
import subprocess
import socket
import time
import datetime
import re
import login
import requests
import random 

MODE = None
BRAND = None
IID = None
FIRMWARE = None
TARGET = None
LOGIN_TYPE = 'unknown'
SESSION = None
UNIQ = '| sort | uniq'
AWK_UNIQ = '| awk \'{split($0,a,":"); print a[1]}\'' + UNIQ
CUT_CGI = " | sed 's@\\(\\.cgi\\).*@\\1@' | sed 's@.*\\(/\\)@\\1@' | sed 's@.*\\( \\)@\\1@' | sed 's@.*\\(\"\\)@\\1@'"
GREP_CGI = " | grep -P '^/?[A-Za-z0-9]+\.cgi$'"
GREP_PARAM = " | grep -P '^(\?)?[A-Za-z0-9]+=$'"
GREP_HEADER = " | grep -P '^(\?)?[A-Za-z0-9]+:$'"
GREP_HNAP = " | grep -P '/HNAP1/[A-Za-z0-9]+'"
CUT_PARAM = " | sed 's@[a-z]*\\(\\=\\).*@\\1@' | sed 's@.*\\(?\\)@\\1@'"
UPNP_REGEX = '[A-Za-z0-9-]+:[A-Za-z0-9:-]*'
HNAP_REGEX = '/HNAP1/[A-Za-z0-9]+'

PAYLOAD_LIST = []
key_value_map = {}

POST_PACKET = '''POST {uri} HTTP/1.0
Host: {host}
Content-Type: text/xml
Content-Length: {length}
{header}
{body}'''

makebuf = lambda n : ('a'*(8-len(str(n)))+ str(n))*1250

def readHTML(filepath):
    with open(filepath, 'rb') as f:
        data = re.sub(b"(<!--.*?-->)", b"", f.read(), flags=re.MULTILINE)
        return data.decode()
    return ''

def command(cmd):
    try:
        result = subprocess.check_output(cmd, shell=True)
        result = result.decode().split('\n')[:-1]
    except:
        result = ''

    return result

def preprocess(payload, PAYLOAD_LIST):
    for q_l in ['', '\'', '"']:
        for q_r in ['', '\'', '"', '#']:
            for sep in ['','&&', '|', '||',  ';', '`']:
                PAYLOAD_LIST.append(q_l + sep + payload + sep + q_r)

def get_open_port(NMAP):
    if NMAP == True:
        print("[NMAP] Scanning Port")
        command('nmap -O -sV '+TARGET+' -oX {}.txt'.format(IID))
    results = []
    tmp_port_map = {'1900':False, '5000':False}
    tree = parse(str(IID)+'.txt')
    nmap = tree.getroot()
    for host in nmap.iter('host'):
        for ports in host.iter('ports'):
            for port, state in zip(ports.iter('port'), ports.iter('state')):
                port_num = port.attrib.get('portid')
                if port_num in tmp_port_map:
                    tmp_port_map[port_num] = True
                results.append({'port': port_num, 'state': state.attrib.get('state'), 'files':[], 'uris':[], 'params':[], 'headers':[]})

    for port in tmp_port_map:
        if not tmp_port_map[port]:
            results.append({'port': port, 'state': 'unknown', 'files':[], 'uris':[], 'params':[], 'headers':[]})

    return results


def get_information():
    # cgibin, fileaccess.cgi in DIR-816L_REVB_FIRMWARE_PATCH_2.06.B09_BETA.ZIP
    cgi_map = {'uri':[], 'param':[], 'header':[]}
    action_map = {}
    hnap_map = {}
    binary_list = []
    param_map = {}
    ssdp_list = []

    webpage = []
    hidden_data = []
    http_map = {}

    cmd = 'find ./ -name "*.htm" 2> /dev/null'
    buf = command(cmd)

    for i in range(0, len(buf)):
        #webpage.append(buf[i][16::])
        webpage.append(buf[i])

    cmd = 'grep -r \'<input type="hidden" name=\' ./'+str(IID) 
    hidden = command(cmd)

    keyword ='name='

    var_name = []
    var_page = []
    var_value = []
    htmlcheck = []
     
    http_name_value = {}
    #collect argument
    for page in webpage:
        try:
            soup = BeautifulSoup(readHTML(page),'html.parser')
            for i in soup.find_all('input'):
                n = i.get('name')
                v = i.get('value','default')
                if n not in var_name and n != None:
                    var_name.append(n)
                if v not in var_value:
                    var_value.append(v)

        except:
            continue

        for name in var_name:
            http_name_value[name] = var_value
        
        page = page[23::]
        #print(page)
        #input()
        http_map[page] = http_name_value
        #print(page)
        #print(http_name_value)
        #print(http_map)
        if page not in var_page:
            var_page.append(page)
        
        var_value = []
        var_name = []
        http_name_value = {}
    #print(http_map)
    #input()

    return http_map, var_page

def send_http_dummy(port, uri, params):
    global SESSION, LOGIN_TYPE
    headers = requests.utils.default_headers()
    headers['Accept'] = 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8'
    headers['Accept-Encoding'] = 'gzip, deflate'
    headers['Accept-Language'] = "en-US,en;q=0.5"
    headers['Authorization'] = "Basic YWRtaW46"
    headers['Connection'] = 'keep-alive'
    headers['Content-Type'] = 'application/x-www-form-urlencoded'
    headers['Upgrade-Insecure-Requests'] = '1'
    headers['User-Agent'] = 'Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; Touch; rv:11.0) like Gecko'
    headers['origin'] = 'http://{}/'.format(TARGET)
    headers['Referer'] = 'http://{}:{}/{}/'.format(TARGET, port, uri)

    url = 'http://{}:{}/{}/'.format(TARGET, port, uri)
    print("[O]send URL : "+url)
    try:
        r = requests.post('http://{}:{}/{}/'.format(TARGET, port, uri), headers=headers, data=params)
    except:
        r = requests.get('http://{}:{}/{}/'.format(TARGET, port, uri), headers=headers, data=params)
    
    print("[O]send_http_POST_dummy_headers: "+str(r.request.headers))
    print("[O]send_http_POST_dummy_data: "+str(params))  

    data = r.text.encode()

    print('Status Code: '+str(r.status_code))
    
    return data, r.status_code

def fuzz(infos, http_map, html_page, payload, idx):
    random.seed(time.time())
    dummy_idx_list = []
    idx = 0
    nameTag = []

    for info in infos:
        print('[*] Attack : '+str(info['port']))
        for html in html_page:
            data = {}
            for name in http_map[html]:
                value = http_map[html][name]
                nameTag.append(name)
            

            range_ = len(value) - 1
            count = 0
            while count < 1000:
                for name in nameTag:
                    index = random.randrange(0,range_)
                    data[name] = value[index]

                    if nameTag[0] == 'ReplySuccessPage':
                        data[nameTag[0]] = value[0]

                    if nameTag[1] == 'ReplyErrorPage':
                        data[nameTag[1]] = value[1]

                    attack = count % len(nameTag)
                    data[nameTag[attack]] = payload+str(idx)

                try:
                    #send_http_dummy(info['port'], html, data)
                    send_http_dummy('80', html, data)
                    time.sleep(1)
                    dummy_idx_list.append([data, payload, idx])
                except:
                    continue
                count += 1
                idx = idx +1

    return dummy_idx_list, idx

def extract_image():
    command('mkdir {} 2> /dev/null'.format(IID))
    command('tar xzf ../../images/{}.tar.gz -C ./{} 2> /dev/null'.format(IID, IID))

def get_execve_log(dummy_length):
    execve_list = []
    for line in command('strings ../scratch/{}/qemu.final.serial.log | grep -i zj3t'.format(IID)):
        match = re.search('d34d[0-9]+', line, re.IGNORECASE).group()

        num = int(match[4:])
        while num > dummy_length:
            num = num // 10

        if num not in execve_list:
            execve_list.append(num)

    return execve_list

def main():
    
    idx = 0
    extract_image()

    PAYLOAD_LIST = []

    preprocess('zj3t',PAYLOAD_LIST)

    http_map = {}
    webpage = []
    
    infos = get_open_port(NMAP=False)
    #@print("[*] ports info")
    #print(infos)
    http_map, webpage = get_information()

    cnt = 0
    if infos:
        for payload in PAYLOAD_LIST:
            dummy_list,idx = fuzz(infos, http_map, webpage, 'zj3t', idx)

            time.sleep(3)
            dummy_idx_list = get_execve_log(len(dummy_list))
            
            for idx in dummy_idx_list:
                print('[+] '+str(idx))
                print('[+] {}'.format(dummy_list[idx]))
            cnt+=1

if __name__ == "__main__":
    argc = len(sys.argv)
    if argc != 4:
        print("usage: fuzzer.py [target] [brand] [IID]")
        exit()

    MODE = "ci"
    TARGET = sys.argv[1]
    BRAND = sys.argv[2]
    IID = sys.argv[3]

    main()
