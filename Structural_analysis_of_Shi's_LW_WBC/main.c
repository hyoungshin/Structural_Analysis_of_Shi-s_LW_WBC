/*
<Structural analysis of Shi's LW-WBC>
name: Hyoungshin Yim
data: 2021.12.30
Department: Mathematics and Financial Information Security, Kookmin University, Seoul 02707, South Korea
email: kuunh2@kookmin.ac.kr
*/

#include "main.h"

byte S_function(byte* input, byte* roundKey, int round_num, int num) {

    byte input_o[8] = { 0 };
    bit5_to_bit8(input, input_o, 12, 8, 0x5);

    byte output = 0;

    if (round_num < 3 && (5 < round_num && round_num < 9)) {
        output = (input[round_num % 8] & input[(round_num + 1) % 8]) ^ (input[(round_num + 1) % 8] & input[(round_num + 2) % 8]) ^ (input[round_num % 8] & input[(round_num + 1) % 8]);
        output = Omega_function[output];
    }
    else {
        output = (input[round_num % 8] & input[(round_num + 1) % 8]) | (~input[round_num % 8] & input[(round_num + 2) % 8]);
        output = Omega_function[output];
    }

    output = output ^ roundKey[(12 * round_num) + num];

    return output;
}

void shuffle(byte* arr, int num, int iteration_num) {

    srand(time(NULL));
    int temp;
    int rn;

    for (int i = 0; i < iteration_num; i++) {
        for (int j = 0; j < num - 1; j++) {
            rn = rand() % (num - j) + j;
            temp = arr[j];
            arr[j] = arr[rn];
            arr[rn] = temp;
        }
    }
}

void Fixed_set(byte(*input)[12], byte* fixed_value, int size_num) {

    for (int i = 0; i < size_num; i++) {
        for (int j = 0; j < 12; j++) {
            input[i][j] = fixed_value[j];
        }
    }
}

void Multiset_plaintext(byte(*input)[12], int iteration_num) {//P C C C ....

    srand(time(NULL));

    byte temp[32] = { 0 };
    byte Inv_temp[32] = { 0 };

    for (int i = 0; i < 32; i++) {
        temp[i] = i;
    }

    shuffle(temp, 32, iteration_num);

    for (int i = 0; i < 32; i++) {
        input[i][0] = temp[i];
    }

    int value = 0;
    for (int i = 0; i < 11; i++) {
        value = rand() % 32;
        for (int j = 0; j < 32; j++) {
            input[j][i + 1] = value;
        }
    }
}

void Set_differential_plaintext(byte(*input)[12], int sbox_num, int iteration_num) {

    srand(time(NULL));

    byte temp[32] = { 0 };
    for (int i = 0; i < 32; i++) {
        temp[i] = i;
    }

    shuffle(temp, 32, iteration_num);

    for (int i = 0; i < 12; i++) {
        for (int j = 0; j < 5; j++) {
            if (i == sbox_num) {
                input[2 * j][i] = temp[2 * j];
                input[2 * j + 1][i] = temp[2 * j + 1];
            }
            else {
                int value = rand() % 32;
                input[2 * j][i] = value;
                input[2 * j + 1][i] = value;
            }
        }
    }
}

void SA_structure(byte(*input)[12], byte(*output)[12], byte(*bit5_sbox)[32], bool(*Matrix)[60]) {

    for (int i = 0; i < 32; i++) {

        byte temp[12] = { 0 };

        for (int j = 0; j < 12; j++) {
            temp[j] = bit5_sbox[j][input[i][j]];
        }

        Matrix_multiplication_total(Matrix, temp, output[i], 12, 12);
    }
}

void Get_plaintext_ciphertext_in_round_sbox(byte(*plaintext)[24], byte(*ciphertext)[30], int round_num, int iteration_num, byte* fixed_value, enc_data* enc_data, byte(*bit5_sbox)[32], bool(*Matrix)[60]) {

    byte L_input_temp[32][12] = { 0 };
    byte L_input[32][12] = { 0 };
    byte R_input[32][12] = { 0 };
    byte R_input_temp[15] = { 0 };
    byte output_temp[15] = { 0 };
    byte temp[12][15] = { 0 };

    int i, j, k;
    byte tmp = 0;
    byte algorithm_output = 0;

    Multiset_plaintext(L_input_temp, iteration_num);
    Fixed_set(R_input, fixed_value, 32);

    SA_structure(L_input_temp, L_input, bit5_sbox, Matrix);

    for (k = 0; k < 32; k++) {
        memcpy(plaintext[k], L_input[k], 12);
        memcpy(plaintext[k] + 12, R_input[k], 12);
    }

    for (k = 0; k < 32; k++) {

        for (i = 0; i < 12; i++) {
            algorithm_output = S_function(R_input[k], enc_data->Key, round_num, i);
            for (j = 0; j < 15; j++) {
                temp[i][j] = enc_data->TBOX[i][(L_input[k][i] << 6) + algorithm_output][j];
            }
        }

        for (i = 0; i < 15; i++) {
            tmp = temp[11][i];
            for (j = 9; j >= 0; j--) {
                tmp = enc_data->Masked_adders[i][j][(tmp << 4) + temp[j + 1][i]];
            }
            output_temp[i] = enc_data->Masked_adders_Last[round_num][i][(tmp << 4) + temp[0][i]];
        }

        bit5_to_bit4(R_input[k], R_input_temp, 12, 15);
        memcpy(ciphertext[k], R_input_temp, 15);
        memcpy(ciphertext[k] + 15, output_temp, 15);

    }
}

void Get_plaintext_ciphertext_in_round_affine(byte(*plaintext)[24], byte(*ciphertext)[30], int round_num, int sbox_num, int iteration_num, byte* fixed_value, enc_data* enc_data) {

    byte L_input[10][12] = { 0 };
    byte R_input[10][12] = { 0 };
    byte R_input_temp[15] = { 0 };
    byte output_temp[15] = { 0 };
    byte temp[12][15] = { 0 };

    int i, j, k;
    byte tmp = 0;
    byte algorithm_output = 0;

    Set_differential_plaintext(L_input, sbox_num, iteration_num);
    Fixed_set(R_input, fixed_value, 10);

    for (k = 0; k < 10; k++) {
        memcpy(plaintext[k], L_input[k], 12);
        memcpy(plaintext[k] + 12, R_input[k], 12);
    }

    for (k = 0; k < 10; k++) {

        for (i = 0; i < 12; i++) {

            algorithm_output = S_function(R_input[k], enc_data->Key, round_num, i);
            for (j = 0; j < 15; j++) {
                temp[i][j] = enc_data->TBOX[i][(L_input[k][i] << 6) + algorithm_output][j];
            }
        }

        for (i = 0; i < 15; i++) {
            tmp = temp[11][i];
            for (j = 9; j >= 0; j--) {
                tmp = enc_data->Masked_adders[i][j][(tmp << 4) + temp[j + 1][i]];
            }
            output_temp[i] = enc_data->Masked_adders_Last[round_num][i][(tmp << 4) + temp[0][i]];
        }
        bit5_to_bit4(R_input[k], R_input_temp, 12, 15);
        memcpy(ciphertext[k], R_input_temp, 15);
        memcpy(ciphertext[k] + 15, output_temp, 15);

    }
}

void Get_plaintext_ciphertext_in_round_firstsbox(byte(*ciphertext)[30], int round_num, byte* fixed_value, enc_data* enc_data) {

    byte L_input[32][12] = { 0 };
    byte R_input[32][12] = { 0 };
    byte R_input_temp[15] = { 0 };
    byte output_temp[15] = { 0 };
    byte temp[12][15] = { 0 };

    int i, j, k;
    byte tmp = 0;
    byte algorithm_output = 0;

    for (int a = 0; a < 32; a++) {
        for (int b = 0; b < 12; b++) {
            L_input[a][b] = a;
        }
    }

    Fixed_set(R_input, fixed_value, 32);

    for (k = 0; k < 32; k++) {

        for (i = 0; i < 12; i++) {

            algorithm_output = S_function(R_input[k], enc_data->Key, round_num, i);
            for (j = 0; j < 15; j++) {
                temp[i][j] = enc_data->TBOX[i][(L_input[k][i] << 6) + algorithm_output][j];
            }
        }

        for (i = 0; i < 15; i++) {
            tmp = temp[11][i];
            for (j = 9; j >= 0; j--) {
                tmp = enc_data->Masked_adders[i][j][(tmp << 4) + temp[j + 1][i]];
            }
            output_temp[i] = enc_data->Masked_adders_Last[round_num][i][(tmp << 4) + temp[0][i]];
        }

        bit5_to_bit4(R_input[k], R_input_temp, 12, 15);
        memcpy(ciphertext[k], R_input_temp, 15);
        memcpy(ciphertext[k] + 15, output_temp, 15);

    }
}

void Encryption(byte* input, byte* output, byte(*middle_state)[12], enc_data* enc_data) {

    byte L_input[12] = { 0 };
    byte L_input_temp[12] = { 0 };
    byte R_input[12] = { 0 };
    byte Matrix_ith[60][5];

    int i, j, r;
    byte tmp = 0;
    byte output_temp[15] = { 0 };
    byte algorithm_output = 0;

    memcpy(L_input, input, 12);
    memcpy(R_input, input + 12, 12);

    byte G_value, F_value = 0;
    byte temp_matrix[15] = { 0 };
    byte temp_Sbox[15] = { 0 };
    byte temp[12][15] = { 0 };

    for (r = 0; r < enc_data->round_num; r++) {//enc_data->round_num

        memcpy(middle_state[r], R_input, 12);
        for (i = 0; i < 12; i++) {
            algorithm_output = S_function(R_input, enc_data->Key, r, i);
            for (j = 0; j < 15; j++) {
                temp[i][j] = enc_data->TBOX[i][(L_input[i] << 6) + algorithm_output][j];
            }
        }

        for (i = 0; i < 15; i++) {
            tmp = temp[11][i];
            for (j = 9; j >= 0; j--) {
                tmp = enc_data->Masked_adders[i][j][(tmp << 4) + temp[j + 1][i]];
            }
            output_temp[i] = enc_data->Masked_adders_Last[r][i][(tmp << 4) + temp[0][i]];
        }
        bit4_to_bit5(output_temp, L_input_temp, 15, 12);


        memcpy(L_input, R_input, 12);
        memcpy(R_input, L_input_temp, 12);

        for (int l = 0; l < 12; l++) {
            printf("%02x ", L_input[l]);
        }

        for (int l = 0; l < 12; l++) {
            printf("%02x ", R_input[l]);
        }printf("\n");
    }

    memcpy(output, L_input, 12);
    memcpy(output + 12, R_input, 12);
}

void Decryption(byte* input, byte* output, int input_size, dec_data* dec_data) {

    byte L_input[12] = { 0 };
    byte R_input[12] = { 0 };
    byte R_4bit[15] = { 0 };
    byte temp[15] = { 0 };
    byte temp_matrix[12] = { 0 };
    byte output_temp[12] = { 0 };

    byte a = 0;

    memcpy(L_input, input, 12);
    memcpy(R_input, input + 12, 12);

    for (int r = dec_data->round_num - 1; r >= 0; r--) {//dec_data->round_num - 1

        bit5_to_bit4(R_input, R_4bit, 12, 15);

        for (int j = 0; j < 15; j++) {
            temp[j] = dec_data->Inv_H_addLast_BOX[r][j][R_4bit[j]];
        }

        Matrix_multiplication_total(dec_data->Inv_binary_Matrix, temp, temp_matrix, 15, 12);


        for (int i = 0; i < 12; i++) {
            a = S_function(L_input, dec_data->Key, r, i);
            output_temp[i] = dec_data->Inv_G_BOX[i][dec_data->F_BOX[i][a] ^ temp_matrix[i]];
        }

        memcpy(R_input, L_input, 12);
        memcpy(L_input, output_temp, 12);
    }

    memcpy(output, L_input, 12);
    memcpy(output + 12, R_input, 12);

}

void Fullround_attack_get_ciphertext(FILE* fp, FILE* fp1, FILE* fp2, int round_num, enc_data* enc_data, byte* fixed_value, byte(*Sbox0)[32], bool(*affine0)[60]) {

    byte plaintext_sbox[15][16][32][24] = { 0 };
    byte ciphertext_sbox[15][16][32][30] = { 0 };

    byte plaintext_affine[12][50][10][24] = { 0 };
    byte ciphertext_affine[12][50][10][30] = { 0 };

    byte ciphertext_firstsbox[32][30] = { 0 };

    for (int sbox_num = 0; sbox_num < 15; sbox_num++) {
        for (int r = 0; r < 16; r++) {
            Get_plaintext_ciphertext_in_round_sbox(plaintext_sbox[sbox_num][r], ciphertext_sbox[sbox_num][r], round_num, (16 * sbox_num + r) + 1, fixed_value, enc_data, Sbox0, affine0);
        }
    }

    for (int sbox_num = 0; sbox_num < 15; sbox_num++) {
        for (int r = 0; r < 16; r++) {
            for (int l = 0; l < 32; l++) {
                write_byte_file(fp, &ciphertext_sbox[sbox_num][r][l], 15, 30);
            }
        }
    }

    for (int sbox_num = 0; sbox_num < 12; sbox_num++) {
        for (int r = 0; r < 50; r++) {
            Get_plaintext_ciphertext_in_round_affine(plaintext_affine[sbox_num][r], ciphertext_affine[sbox_num][r], round_num, sbox_num, (sbox_num * 20 + r) + 1, fixed_value, enc_data);
        }
    }

    for (int sbox_num = 0; sbox_num < 12; sbox_num++) {
        for (int r = 0; r < 50; r++) {
            for (int l = 0; l < 10; l++) {
                write_byte_file(fp1, &ciphertext_affine[sbox_num][r][l], 15, 30);
            }
        }
    }

    Get_plaintext_ciphertext_in_round_firstsbox(ciphertext_firstsbox, round_num, fixed_value, enc_data);

    for (int r = 0; r < 32; r++) {
        write_byte_file(fp2, &ciphertext_firstsbox[r], 15, 30);
    }

}

void recovery_decryption(byte* plaintext, byte* ciphertext, byte(*Sbox1_inv)[12][32], bool(*affine_inv)[60][60], byte(*Sbox2_inv)[15][16]) {

    byte L_input[12] = { 0 };
    byte R_input[12] = { 0 };
    byte R_4bit[15] = { 0 };
    byte temp[15] = { 0 };
    byte temp_matrix[12] = { 0 };
    byte output_temp[12] = { 0 };

    byte a = 0;

    memcpy(L_input, ciphertext, 12);
    memcpy(R_input, ciphertext + 12, 12);

    for (int r = 15; r >= 0; r--) {

        bit5_to_bit4(R_input, R_4bit, 12, 15);

        for (int j = 0; j < 15; j++) {
            temp[j] = Sbox2_inv[r][j][R_4bit[j]];
        }

        Matrix_multiplication_total(affine_inv[r], temp, temp_matrix, 15, 12);


        for (int i = 0; i < 12; i++) {
            output_temp[i] = Sbox1_inv[r][i][temp_matrix[i]];
        }

        memcpy(R_input, L_input, 12);
        memcpy(L_input, output_temp, 12);

        for (int l = 0; l < 12; l++) {
            printf("%02x ", L_input[l]);
        }

        for (int l = 0; l < 12; l++) {
            printf("%02x ", R_input[l]);
        }printf("\n");
    }

    memcpy(plaintext, L_input, 12);
    memcpy(plaintext + 12, R_input, 12);
}

void write_byte_file(FILE* fp, byte* input, int start, int end) {
    word test = 0;
    for (int i = start; i < end; i++) {
        test = input[i];
        fprintf_s(fp, "%02x", test);
    }
}

int main() {

    /*
    A 'tab' is a structure that contains all data, and can be used at will by the user during verification. However, in reality, the attacker cannot know the data.
    A 'enc_data' is a structure that contains encryption data. This is information that is only exposed to attackers.
    A 'dec_data' is a structure that contains decryption data. However, in reality, the attacker cannot know the data.
    */

    WB_ENCRYPTION_TABLE tab;
    enc_data enc_data;
    dec_data dec_data;

    /*0. */
    FILE* fp;
    fopen_s(&fp, "round_ciphertext_sbox.bin", "wb");
    if (fp == NULL) {
        printf("file open fail!\n");
        return -1;
    }

    FILE* fp2;
    fopen_s(&fp2, "round_ciphertext_affine.bin", "wb");
    if (fp2 == NULL) {
        printf("file open fail!\n");
        return -1;
    }

    FILE* fp3;
    fopen_s(&fp3, "round_ciphertext_firstsbox.bin", "wb");
    if (fp3 == NULL) {
        printf("file open fail!\n");
        return -1;
    }

    srand(time(NULL));
    clock_t start, end, start1, end1;

    /*0. "WB_gen_encryption_table()": Generate the data needed for Shi's white-box cryptographic model. You only need to run it once.*/
    //WB_gen_encryption_table(&tab, &enc_data, &dec_data);

    /*1. "WB_read_enc_ext_encoding()": Get the created 'enc_data.bin' and save it in the table
    If you want to verify, get 'dec_data.bin'. 
    */
    WB_read_enc_ext_encoding(&enc_data, "enc_data.bin");
    //WB_read_dec_ext_encoding(&dec_data, "dec_data.bin");

    /*2. The attack is carrited out using the example plaintext!*/
    byte plaintext[24] = { 0x19, 0x01, 0x0e, 0x0d, 0x0b, 0x10, 0x12, 0x08, 0x07, 0x1a, 0x1d, 0x10, 0x19, 0x01, 0x0e, 0x0d, 0x0b, 0x10, 0x12, 0x08, 0x07, 0x1a, 0x1d, 0x10 };
    byte ciphertext[24] = { 0 };
    byte middle_state[16][12] = { 0 };

    printf("[original_plaintext]\n");
    for (int i = 0; i < 24; i++) {
        printf("%02x ", plaintext[i]);
    }printf("\n\n");

    /*2-1. Get the ciphertext of Shi's LW-WBC for a given plaintext. 
    A 'middle_state' is a variable that stores fixed values for each round. It is used for later attacks. 
    */
    Encryption(&plaintext, &ciphertext, middle_state, &enc_data);

    printf("\n[original_ciphertext]\n");
    for (int i = 0; i < 24; i++) {
        printf("%02x ", ciphertext[i]);
    }printf("\n\n");

    /*2-2. Generate ciphertext required for attack by round - Do it when you need it!*/
    //int round = 15;
    //Fullround_attack_get_ciphertext(fp, fp2, fp3, round, &enc_data, middle_state[round], &bit5_temp, &temp_Matrix);

    /*3. When all rounds of equivalent function data are obtained, the code is executed with if set to 1*/
#if 1
    byte round1_Sbox1_inv[16][12][32] = { 0 };
    bool round1_affine_inv[16][60][60] = { 0 };
    byte round1_Sbox2_inv[16][15][16] = { 0 };

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
    FILE* fp5;

    fopen_s(&fp5, "recovery_file/2round_inverse.bin", "rb");
    if (fp5 == NULL) {
        printf("file open fail!\n");
        return -1;
    }
    else {
        fread(round1_Sbox1_inv[1], sizeof(round1_Sbox1_inv[1]), 1, fp5);
        fread(round1_affine_inv[1], sizeof(round1_affine_inv[1]), 1, fp5);
        fread(round1_Sbox2_inv[1], sizeof(round1_Sbox2_inv[1]), 1, fp5);
    }
    fclose(fp5);

    //3round_file_read
    FILE* fp6;

    fopen_s(&fp6, "recovery_file/3round_inverse.bin", "rb");
    if (fp6 == NULL) {
        printf("file open fail!\n");
        return -1;
    }
    else {
        fread(round1_Sbox1_inv[2], sizeof(round1_Sbox1_inv[2]), 1, fp6);
        fread(round1_affine_inv[2], sizeof(round1_affine_inv[2]), 1, fp6);
        fread(round1_Sbox2_inv[2], sizeof(round1_Sbox2_inv[2]), 1, fp6);
    }
    fclose(fp6);

    //4round_file_read
    FILE* fp7;

    fopen_s(&fp7, "recovery_file/4round_inverse.bin", "rb");
    if (fp7 == NULL) {
        printf("file open fail!\n");
        return -1;
    }
    else {
        fread(round1_Sbox1_inv[3], sizeof(round1_Sbox1_inv[3]), 1, fp7);
        fread(round1_affine_inv[3], sizeof(round1_affine_inv[3]), 1, fp7);
        fread(round1_Sbox2_inv[3], sizeof(round1_Sbox2_inv[3]), 1, fp7);
    }
    fclose(fp7);

    //5round_file_read
    FILE* fp8;

    fopen_s(&fp8, "recovery_file/5round_inverse.bin", "rb");
    if (fp8 == NULL) {
        printf("file open fail!\n");
        return -1;
    }
    else {
        fread(round1_Sbox1_inv[4], sizeof(round1_Sbox1_inv[4]), 1, fp8);
        fread(round1_affine_inv[4], sizeof(round1_affine_inv[4]), 1, fp8);
        fread(round1_Sbox2_inv[4], sizeof(round1_Sbox2_inv[4]), 1, fp8);
    }
    fclose(fp8);

    //6round_file_read
    FILE* fp9;

    fopen_s(&fp9, "recovery_file/6round_inverse.bin", "rb");
    if (fp9 == NULL) {
        printf("file open fail!\n");
        return -1;
    }
    else {
        fread(round1_Sbox1_inv[5], sizeof(round1_Sbox1_inv[5]), 1, fp9);
        fread(round1_affine_inv[5], sizeof(round1_affine_inv[5]), 1, fp9);
        fread(round1_Sbox2_inv[5], sizeof(round1_Sbox2_inv[5]), 1, fp9);
    }
    fclose(fp9);

    //7round_file_read
    FILE* fp10;

    fopen_s(&fp10, "recovery_file/7round_inverse.bin", "rb");
    if (fp10 == NULL) {
        printf("file open fail!\n");
        return -1;
    }
    else {
        fread(round1_Sbox1_inv[6], sizeof(round1_Sbox1_inv[6]), 1, fp10);
        fread(round1_affine_inv[6], sizeof(round1_affine_inv[6]), 1, fp10);
        fread(round1_Sbox2_inv[6], sizeof(round1_Sbox2_inv[6]), 1, fp10);
    }
    fclose(fp10);

    //8round_file_read
    FILE* fp11;

    fopen_s(&fp11, "recovery_file/8round_inverse.bin", "rb");
    if (fp11 == NULL) {
        printf("file open fail!\n");
        return -1;
    }
    else {
        fread(round1_Sbox1_inv[7], sizeof(round1_Sbox1_inv[7]), 1, fp11);
        fread(round1_affine_inv[7], sizeof(round1_affine_inv[7]), 1, fp11);
        fread(round1_Sbox2_inv[7], sizeof(round1_Sbox2_inv[7]), 1, fp11);
    }
    fclose(fp11);

    //9round_file_read
    FILE* fp12;

    fopen_s(&fp12, "recovery_file/9round_inverse.bin", "rb");
    if (fp12 == NULL) {
        printf("file open fail!\n");
        return -1;
    }
    else {
        fread(round1_Sbox1_inv[8], sizeof(round1_Sbox1_inv[8]), 1, fp12);
        fread(round1_affine_inv[8], sizeof(round1_affine_inv[8]), 1, fp12);
        fread(round1_Sbox2_inv[8], sizeof(round1_Sbox2_inv[8]), 1, fp12);
    }
    fclose(fp12);

    //10round_file_read
    FILE* fp13;

    fopen_s(&fp13, "recovery_file/10round_inverse.bin", "rb");
    if (fp13 == NULL) {
        printf("file open fail!\n");
        return -1;
    }
    else {
        fread(round1_Sbox1_inv[9], sizeof(round1_Sbox1_inv[9]), 1, fp13);
        fread(round1_affine_inv[9], sizeof(round1_affine_inv[9]), 1, fp13);
        fread(round1_Sbox2_inv[9], sizeof(round1_Sbox2_inv[9]), 1, fp13);
    }
    fclose(fp13);

    //11round_file_read
    FILE* fp14;

    fopen_s(&fp14, "recovery_file/11round_inverse.bin", "rb");
    if (fp14 == NULL) {
        printf("file open fail!\n");
        return -1;
    }
    else {
        fread(round1_Sbox1_inv[10], sizeof(round1_Sbox1_inv[10]), 1, fp14);
        fread(round1_affine_inv[10], sizeof(round1_affine_inv[10]), 1, fp14);
        fread(round1_Sbox2_inv[10], sizeof(round1_Sbox2_inv[10]), 1, fp14);
    }
    fclose(fp14);

    //12round_file_read
    FILE* fp15;

    fopen_s(&fp15, "recovery_file/12round_inverse.bin", "rb");
    if (fp15 == NULL) {
        printf("file open fail!\n");
        return -1;
    }
    else {
        fread(round1_Sbox1_inv[11], sizeof(round1_Sbox1_inv[11]), 1, fp15);
        fread(round1_affine_inv[11], sizeof(round1_affine_inv[11]), 1, fp15);
        fread(round1_Sbox2_inv[11], sizeof(round1_Sbox2_inv[11]), 1, fp15);
    }
    fclose(fp15);

    //13round_file_read
    FILE* fp16;

    fopen_s(&fp16, "recovery_file/13round_inverse.bin", "rb");
    if (fp16 == NULL) {
        printf("file open fail!\n");
        return -1;
    }
    else {
        fread(round1_Sbox1_inv[12], sizeof(round1_Sbox1_inv[12]), 1, fp16);
        fread(round1_affine_inv[12], sizeof(round1_affine_inv[12]), 1, fp16);
        fread(round1_Sbox2_inv[12], sizeof(round1_Sbox2_inv[12]), 1, fp16);
    }
    fclose(fp16);

    //14round_file_read
    FILE* fp17;

    fopen_s(&fp17, "recovery_file/14round_inverse.bin", "rb");
    if (fp17 == NULL) {
        printf("file open fail!\n");
        return -1;
    }
    else {
        fread(round1_Sbox1_inv[13], sizeof(round1_Sbox1_inv[13]), 1, fp17);
        fread(round1_affine_inv[13], sizeof(round1_affine_inv[13]), 1, fp17);
        fread(round1_Sbox2_inv[13], sizeof(round1_Sbox2_inv[13]), 1, fp17);
    }
    fclose(fp17);

    //15round_file_read
    FILE* fp18;

    fopen_s(&fp18, "recovery_file/15round_inverse.bin", "rb");
    if (fp18 == NULL) {
        printf("file open fail!\n");
        return -1;
    }
    else {
        fread(round1_Sbox1_inv[14], sizeof(round1_Sbox1_inv[14]), 1, fp18);
        fread(round1_affine_inv[14], sizeof(round1_affine_inv[14]), 1, fp18);
        fread(round1_Sbox2_inv[14], sizeof(round1_Sbox2_inv[14]), 1, fp18);
    }
    fclose(fp18);

    //16round_file_read
    FILE* fp19;

    fopen_s(&fp19, "recovery_file/16round_inverse.bin", "rb");
    if (fp19 == NULL) {
        printf("file open fail!\n");
        return -1;
    }
    else {
        fread(round1_Sbox1_inv[15], sizeof(round1_Sbox1_inv[15]), 1, fp19);
        fread(round1_affine_inv[15], sizeof(round1_affine_inv[15]), 1, fp19);
        fread(round1_Sbox2_inv[15], sizeof(round1_Sbox2_inv[15]), 1, fp19);
    }
    fclose(fp19);

    byte recovery_plaintext[24] = { 0 };

    /*3-1. Executes a decryption function composed of equivalent functions*/
    recovery_decryption(&recovery_plaintext, &ciphertext, round1_Sbox1_inv, round1_affine_inv, round1_Sbox2_inv);

    printf("\n[recovery_plaintext]\n");
    for (int i = 0; i < 24; i++) {
        printf("%02x ", recovery_plaintext[i]);
    }printf("\n");

    fclose(fp);
    fclose(fp2);
    fclose(fp3);
#endif

    return 0;
}