"""
Works for 3/3 resources
"""
files = {
   
    'PKCS7': ["61E8F2AF61_Resources\PKCS7113.bin",  
                    "61E8F2AF61_Resources\PKCS7113_decrypted.bin", 
                     [0x17, 0xD4, 0xBA, 0x00]
            ],
     # x64 variant of dropper
    'x509': ["61E8F2AF61_Resources\X509116.bin", 
                "61E8F2AF61_Resources\X509116_decrypted.bin",  
                [0x5C, 0xC2, 0x1A, 0xBB]
               ],
    # Wiper module
    'PKCS12': ["61E8F2AF61_Resources\PKCS12112.bin", 
                     "61E8F2AF61_Resources\PKCS12112_decrypted.bin",  
                     [0x25, 0x7F, 0x5D, 0xFB]
                ]    
            }

import os 

def decrypt(data, key):
    keyLength = len(key)
    decoded = ""
    for i in range(0, len(data)):
            decoded += chr(data[i] ^ key[i % keyLength])

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