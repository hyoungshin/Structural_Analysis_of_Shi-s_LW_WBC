# Structural Analysis of Shi's LW-WBC

This project is a code that conducted sturctural analysis study on the 'Light-weight White-box Cryptographic model' proposed in 2019.  
The paper was published in IEEE transaction on Computers as "A Light-Weight White-Box Encryption Scheme for Securing Distributed Embedded Devices" by Shi et al. (<u>https://ieeexplore.ieee.org/abstract/document/8675491</u>)  
Although LW-WBC(Light-Weight White-Box Cryptography) claims to be safe against various attack methods, we can obtain each component function through a structural analysis attack.  
Therefore, we implement the proposed LW-WBC based on the C language and obtain each component function through Python language. 
Since the attack is completed using file input/output between C and Python, operating as follows is necessary.  

-----------
## Code Working Process
#### 0. Preset  
**'S1AS2 attack (Structural Analysis)'** folder is set in the environment running Python like ***Jupyter Notebook***, and the rest of the files move the code to ***Visual Studio 2019***.  
#### 1. Shi's LW-WBC Code (C language)  
``` C
//WB_gen_encryption_table(&tab, &enc_data, &dec_data);
WB_read_enc_ext_encoding(&enc_data, "enc_data.bin");
//WB_read_dec_ext_encoding(&dec_data, "dec_data.bin");
```
The encryption data created with *'WB_gen_encryption_table()'* is loaded through *'WB_read_enc_ext_encoding()'*
Here, *'WB_gen_encryption_table'* is executed only once, and when the user needs verification, **'dec_data'** data is loaded.
``` C
Encryption(&plaintext, &ciphertext, middle_state, &enc_data);
```
Next, the encryption algorithm of LW-WBC is operated, and the fixed_value is stored in the **'middle_state'**.  
**'middle_state'** is a fixed value used for S-box attacks and affine attacks in sturctural analysis. 
``` C
//Run the code for each round. That is, since the total round is 16, it is a total of 16 times.
int round = 0;
Fullround_attack_get_ciphertext(fp, fp2, fp3, round, &enc_data, middle_state[round], &bit5_temp, &temp_Matrix);

#if 0
    byte round1_Sbox1_inv[16][12][32] = { 0 };
    bool round1_affine_inv[16][60][60] = { 0 };
    byte round1_Sbox2_inv[16][15][16] = { 0 };
    ....
#endif
```
*'Fullround_attack_get_ciphertext()'* stores ciphertext data sets necessary for the round attacl as file input/output. 

    round_ciphertext_sbox.bin
    round_ciphertext_affine.bin
    round_ciphertext_firstsbox.bin
    
Paste the data outputs above into the corresponding round folder file in **'S1AS2 attack (Structural Analysis).'** 
Complete that task for every round.

#### 2. S1AS2 attack (Python language)  
Execute the code in an environment that can run Python code. We ran the attack in ***Jupyter notebook 3.7.3***.  

    [21.12.28] SAS+Shi (1-round).ipynb
    [21.12.28] SAS+Shi (2-round).ipynb
    ...
    
    
    1round_inverse.bin
    2round_inverse.bin
    ...
    
If you run the **.ipynb** file in all folders, *'1round_inverse.bin' et al.* is created in the folder.  
After that, put the generated file in the **'recovery file'** folder of ***Visual Studio 2019***.

#### 3. Structural analysis of Shi's LW-WBC Code (C language)  
Comment out *'Fullround_attack_get_ciphertext(),'* a function that generates ciphertext, and set the if statement to 1.   
``` C
//int round = 0;
//Fullround_attack_get_ciphertext(fp, fp2, fp3, round, &enc_data, middle_state[round], &bit5_temp, &temp_Matrix);

#if 1
    byte round1_Sbox1_inv[16][12][32] = { 0 };
    bool round1_affine_inv[16][60][60] = { 0 };
    byte round1_Sbox2_inv[16][15][16] = { 0 };
    ....
#endif
```
As a result, the code is activated as follows.  
``` C
    //1round_file_read
    FILE* fp4;

    fopen_s(&fp4, "recovery_file/1round_inverse.bin", "rb");
    if (fp4 == NULL) {
        printf("file open fail!\n");
        return -1;
    }
    else {
        fread(round1_Sbox1_inv[0], sizeof(round1_Sbox1_inv[0]), 1, fp4);
        fread(round1_affine_inv[0], sizeof(round1_affine_inv[0]), 1, fp4);
        fread(round1_Sbox2_inv[0], sizeof(round1_Sbox2_inv[0]), 1, fp4);
    }
    fclose(fp4);
    
    //2round_file_read
    ...
    
    recovery_decryption(&recovery_plaintext, &ciphertext, round1_Sbox1_inv, round1_affine_inv, round1_Sbox2_inv);
```
*'recovery_decryption()'* is an algorithm that constructs functions obtained from **Python** as a decryption process.  
As a result, we can obtain a functionally equivalent decryption oracle with LW-WBC.  

-----------
## Related research
+ Hyoungshin Yim, Ju-Sung Kang, and Yongjin Yeom. "An Efficient Structural Analysis of SAS and its Application to White-Box Cryptography." 2021 IEEE Region 10 Symposium (TENSYMP). IEEE, 2021.
+ Hyoungshin Yim. "A Study on the Efficient Sturctural Analysis and its Application to White-Box Cryptography." 2021. Kookmin University, MS dissertation. 
