# Structural_Analysis_of_Shi's_LW_WBC

This project is a code that conducted sturctural analysis study on the 'Light-weight White-box Cryptographic model' proposed in 2019.  
The paper was published in IEEE transaction on Computers as "A Light-Weight White-Box Encryption Scheme for Securing Distributed Embedded Devices" by Shi et al. (<u>https://ieeexplore.ieee.org/abstract/document/8675491</u>)  
Although LW-WBC(Light-Weight White-Box Cryptography) claims to be safe against various attack methods, we can obtain each component function through a structural analysis attack.  
Therefore, we implement the proposed LW-WBC based on the C language and obtain each component function through Python language. 
Since the attack is completed using file input/output between C and Python, operating as follows is necessary.  

-----------
## Implementation Phase
#### 0. Preset  
**'S1AS2 attack (Structural Analysis)'** folder is set in the environment running Python like ***Jupyter Notebook***, and the rest of the files move the code to ***Visual Studio 2019***.  
#### 1. Shi's LW-WBC Code (C language)  
``` C
//WB_gen_encryption_table(&tab, &enc_data, &dec_data);
WB_read_enc_ext_encoding(&enc_data, "enc_data.bin");
//WB_read_dec_ext_encoding(&dec_data, "dec_data.bin");
```
The encryption data created with 'WB_gen_encryption_table()' is loaded through 'WB_read_enc_ext_encoding()'
