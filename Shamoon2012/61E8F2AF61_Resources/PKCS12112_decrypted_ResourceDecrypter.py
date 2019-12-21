"""
Works for 1/3 resources
"""
files = {
   
    'PKCS12_Eldos': ["PKCS12112_Resources\wiper_encrypted.sys_",  
                    "PKCS12112_Resources\wiper_decrypted.sys_", 
                    [0x15, 0xAF, 0x52, 0xF0, 0xA0, 0xFF, 0xCA, 0x10]
                    # [0x10, 0xCA, 0xFF, 0xA0, 0xF0, 0x52, 0xAF, 0x15]
            ],
        }

import os 

def decrypt(data, key):
    keyLength = len(key)
    decoded = ""
    for i in range(0, len(data)):
        decoded += chr(data[i] ^ key[i & 3])

    return decoded

def main():
     for rname, file in files.items():
        src_resource = file[0]
        dst_resource = file[1]
        xor_key = file[2]
        
        print("[+] Decrypting resource {}".format(rname))
        print("[+] Using Decryption key: {}\n".format(xor_key))
        
        key = bytearray(xor_key)
        data = bytearray(open(src_resource, 'rb').read())
    
        decryptedData = decrypt(data, key)
        if len(decryptedData) == 0:
            print("[!] not able to decrypt resource {}".format(src_resource))
        with open(dst_resource, "wb+") as dst:
            dst.write(decryptedData)

if __name__ =="__main__":
    main()