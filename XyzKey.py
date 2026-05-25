import base64, json, uuid
import urllib.request, urllib.error
import os

class XyzKey:
    def __init__(self, api_key="Replace API"): #Thay API của bạn ở đây
        self.key = api_key
        u = 'aHR0cHM6Ly94eWFua2FuYS5pby52bi9LZXlBdXRoL2FwaS9jaGVjay9DaGVjaw=='
        self.url = base64.b64decode(u).decode('utf-8')
        
        self.hdrs = {
            'Content-Type': 'application/json',
            'User-Agent': 'XyanKanaApp/1.0',
            'X-App-Bypass': 'xyankana_app_secret'
        }

    def get_hwid(self):
        try:
            m = uuid.getnode()
            return ':'.join(("%012X" % m)[i:i+2] for i in range(0, 12, 2))
        except:
            return 'Unknown'

    def send(self, data):
        try:
            d = json.dumps(data).encode('utf-8')
            r = urllib.request.Request(self.url, data=d, headers=self.hdrs, method='POST')
            with urllib.request.urlopen(r, timeout=15) as res:
                out = res.read().decode('utf-8')
                if not out: return {'success': False, 'message': 'Empty'}
                return json.loads(out)
        except:
            return {'success': False, 'message': 'Connection error'}

    def license(self, k):
        return self.send({
            'type': 'license',
            'apiKey': self.key,
            'licenseKey': k,
            'hwid': self.get_hwid()
        })

    def login(self, user, pwd):
        return self.send({
            'type': 'user',
            'apiKey': self.key,
            'username': user,
            'password': pwd,
            'hwid': self.get_hwid()
        })


if __name__ == '__main__':
    auth = XyzKey()
    
    print("1. Login (License)")
    print("2. Login (User/Pass)")
    c = input("> ")
    
    if c == '1':
        k = input("Key: ")
        res = auth.license(k)
        if res.get('success'):
            print("\n[+] Login Success!")
            print("Welcome to Bro")
        else:
            print(f"\n[-] Failed: {res.get('message')}")
            
    elif c == '2':
        u = input("User: ")
        p = input("Pass: ")
        res = auth.login(u, p)
        if res.get('success'):
            print("\n[+] Login Success!")
            print("Welcome to Bro")
        else:
            print(f"\n[-] Failed: {res.get('message')}")
            
    os.system('pause' if os.name == 'nt' else "read -p 'Press Enter...'")
