#include "table_gen.h"

void bit5_to_bit8(byte* input, byte* output, byte padding_value) {

    output[0] = (input[0] & 0x1f) + (input[1] & 0x7);
    output[1] = ((input[1] >> 3) & 0x3) + (input[2] << 2) + ((input[3] & 0x1) << 7);
    output[2] = ((input[3] >> 1) & 0xf) + ((input[4] & 0xf) << 4);
    output[3] = ((input[4] >> 4) & 0x1) + ((input[5] & 0x1f) << 1) + ((input[6] & 0x3) << 6);
    output[4] = ((input[6] >> 2) & 0x3) + (input[7] << 3);
    output[5] = input[8] + ((input[9] & 0x7) << 5);
    output[6] = ((input[9] >> 3) & 0x3) + (input[10] << 2) + ((input[11] & 0x1) << 7);
    output[7] = ((input[11] >> 1) & 0xf) + ((padding_value & 0xf) << 4);
}

void bit4_to_bit5(byte* input, byte* output) {

    for (int i = 0; i < 3; i++) {
        output[4 * i] = ((input[5 * i] & 0xf) << 1) + ((input[5 * i + 1] >> 3) & 0x1);
        output[4 * i + 1] = ((input[5 * i + 1] & 0x7) << 2) + ((input[5 * i + 2] >> 2) & 0x3);
        output[4 * i + 2] = ((input[5 * i + 2] & 0x3) << 3) + ((input[5 * i + 3] >> 1) & 0x7);
        output[4 * i + 3] = ((input[5 * i + 3] & 0x1) << 4) + (input[5 * i + 4] & 0xf);
    }
}

void bit5_to_bit4(byte* input, byte* output) {

    for (int i = 0; i < 3; i++) {
        output[5 * i] = (input[4 * i] >> 1) & 0xf;
        output[5 * i + 1] = ((input[4 * i] & 0x1) << 3) + ((input[4 * i + 1] >> 2) & 0x7);
        output[5 * i + 2] = ((input[4 * i + 1] & 0x3) << 2) + ((input[4 * i + 2] >> 3) & 0x3);
        output[5 * i + 3] = ((input[4 * i + 2] & 0x7) << 1) + ((input[4 * i + 3] >> 4) & 0x1);
        output[5 * i + 4] = (input[4 * i + 3] & 0xf);
    }
}

void swap_byte(byte* x, byte* y)
{
    byte tmp = *x;
    *x = *y;
    *y = tmp;
}

void shuffle_5bits(byte* x) {
    int i, j;
    for (i = 31; i > 0; i--) {
        j = rand() % (i + 1);
        swap_byte(x + i, x + j);
    }
}

void shuffle_4bits(byte* x) {
    int i, j;
    for (i = 15; i > 0; i--) {
        j = rand() % (i + 1);
        swap_byte(x + i, x + j);
    }
}

void get_inv_map_4bits(byte* dst, const byte* src)
{
    int j;
    for (j = 0; j < 16; j++)
        dst[src[j]] = j;
}

void gen_random_4bits(byte* map, byte* map_inv) {

    int j;
    for (j = 0; j < 16; j++) {
        map[j] = j;
    }

    shuffle_4bits(map);
    get_inv_map_4bits(map_inv, map);
}

void get_inv_map_5bits(byte* dst, const byte* src)
{
    int j;
    for (j = 0; j < 32; j++)
        dst[src[j]] = j;
}

void gen_random_5bits(byte* map, byte* map_inv) {

    int j;
    for (j = 0; j < 32; j++) {
        map[j] = j;
    }

    shuffle_5bits(map);
    get_inv_map_5bits(map_inv, map);
}

void WB_write_tab_ext_encoding(WB_ENCRYPTION_TABLE* ctx, char* file_name)
{
    FILE* fp = fopen(file_name, "wb");
    if (fp != NULL)
    {
        fwrite(ctx, sizeof(WB_ENCRYPTION_TABLE), 1, fp);
        fclose(fp);
    }
}

void WB_read_tab_ext_encoding(WB_ENCRYPTION_TABLE* ctx, char* file_name)
{
    FILE* fp = fopen(file_name, "rb");
    if (fp != NULL)
    {
        fread(ctx, sizeof(WB_ENCRYPTION_TABLE), 1, fp);
        fclose(fp);
    }
}

void WB_write_enc_ext_encoding(enc_data* ctx, char* file_name)
{
    FILE* fp = fopen(file_name, "wb");
    if (fp != NULL)
    {
        fwrite(ctx, sizeof(enc_data), 1, fp);
        fclose(fp);
    }
}

void WB_read_enc_ext_encoding(enc_data* ctx, char* file_name)
{
    FILE* fp = fopen(file_name, "rb");
    if (fp != NULL)
    {
        fread(ctx, sizeof(enc_data), 1, fp);
        fclose(fp);
    }
}

void WB_write_dec_ext_encoding(dec_data* ctx, char* file_name)
{
    FILE* fp = fopen(file_name, "wb");
    if (fp != NULL)
    {
        fwrite(ctx, sizeof(dec_data), 1, fp);
        fclose(fp);
    }
}

void WB_read_dec_ext_encoding(dec_data* ctx, char* file_name)
{
    FILE* fp = fopen(file_name, "rb");
    if (fp != NULL)
    {
        fread(ctx, sizeof(dec_data), 1, fp);
        fclose(fp);
    }
}

void enc_data_write(enc_data* enc_data, WB_ENCRYPTION_TABLE* tab, byte* Master_Key, char* file_name) {

    int i, j, k;

    enc_data->round_num = Round;
    memcpy(enc_data->Key, Master_Key, sizeof(byte) * enc_data->round_num * 72);

    for (i = 0; i < 12; i++) {
        for (j = 0; j < 2048; j++) {
            for (k = 0; k < 15; k++) {
                enc_data->TBOX[i][j][k] = tab->TBOX[i][j][k];
            }
        }
    }

    for (i = 0; i < 15; i++) {
        for (j = 0; j < 10; j++) {
            for (k = 0; k < 256; k++) {
                enc_data->Masked_adders[i][j][k] = tab->Masked_adders[i][j][k];
            }
        }
    }

    for (i = 0; i < Round; i++) {
        for (j = 0; j < 15; j++) {
            for (k = 0; k < 256; k++) {
                enc_data->Masked_adders_Last[i][j][k] = tab->Masked_adders_Last[i][j][k];
            }
        }
    }
    WB_write_enc_ext_encoding(enc_data, file_name);
}

void dec_data_write(dec_data* dec_data, WB_ENCRYPTION_TABLE* tab, byte* Master_Key, char* file_name) {

    int i, j, k;

    dec_data->round_num = Round;
    memcpy(dec_data->Key, Master_Key, sizeof(byte) * dec_data->round_num * 72);

    for (i = 0; i < Round; i++) {
        for (j = 0; j < 15; j++) {
            for (k = 0; k < 16; k++) {
                dec_data->Inv_H_addLast_BOX[i][j][k] = tab->Inv_H_addLast_BOX[i][j][k];
            }
        }
    }

    for (i = 0; i < 60; i++) {
        for (j = 0; j < 60; j++) {
            dec_data->Inv_binary_Matrix[i][j] = tab->Inv_binary_Matrix[i][j];
        }
    }

    for (i = 0; i < 12; i++) {
        for (j = 0; j < 32; j++) {
            dec_data->Inv_G_BOX[i][j] = tab->Inv_G_BOX[i][j];
        }
    }

    for (i = 0; i < 12; i++) {
        for (j = 0; j < 64; j++) {
            dec_data->F_BOX[i][j] = tab->F_BOX[i][j];
        }
    }
    WB_write_dec_ext_encoding(dec_data, file_name);
}

void Key_generation_in_Round(byte* Master_Key) {

    for (int i = 0; i < 72; i++) {
        Master_Key[i] = rand() & 0x3f;
    }
}

void matrix_distribution(bool(*output)[5], bool(*M)[60], byte i) {

    for (int a = 0; a < 60; a++) {
        for (int b = 0; b < 5; b++) {
            output[a][b] = M[a][i + b];
        }
    }
}

void Matrix_multiplication_inTBOX(bool(*M)[5], byte input, byte* output) {

    byte k = 0;
    bool temp_input[5] = { 0 };
    bool temp_output[60] = { 0 };

    temp_input[0] = (input >> 4) & 1;
    temp_input[1] = (input >> 3) & 1;
    temp_input[2] = (input >> 2) & 1;
    temp_input[3] = (input >> 1) & 1;
    temp_input[4] = input & 1;

    for (int i = 0; i < 60; i++) {
        for (int j = 0; j < 5; j++) {
            temp_output[i] ^= M[i][j] & temp_input[j];
        }
    }

    for (int j = 0; j < 15; j++) {
        output[j] = (temp_output[4 * j + 3] & 0x1) + ((temp_output[4 * j + 2] << 1) & 0x3) + ((temp_output[4 * j + 1] << 2) & 0x7) + ((temp_output[4 * j] << 3) & 0xf);
    }

}

void Matrix_multiplication_total(bool(*M)[60], byte* input, byte* output, int input_size, int output_size) {

    byte k = 0;
    bool temp_input[60] = { 0 };
    bool temp_output[60] = { 0 };

    if (input_size == 12) {
        for (int j = 0; j < 12; j++) {
            temp_input[5 * j] = (input[j] >> 4) & 1;
            temp_input[5 * j + 1] = (input[j] >> 3) & 1;
            temp_input[5 * j + 2] = (input[j] >> 2) & 1;
            temp_input[5 * j + 3] = (input[j] >> 1) & 1;
            temp_input[5 * j + 4] = (input[j]) & 1;
        }
    }
    else {
        for (int j = 0; j < 15; j++) {
            temp_input[4 * j] = (input[j] >> 3) & 1;
            temp_input[4 * j + 1] = (input[j] >> 2) & 1;
            temp_input[4 * j + 2] = (input[j] >> 1) & 1;
            temp_input[4 * j + 3] = (input[j]) & 1;
        }
    }


    for (int i = 0; i < 60; i++) {
        for (int j = 0; j < 60; j++) {
            temp_output[i] ^= M[i][j] * temp_input[j];
        }
    }


    if (output_size == 12) {
        for (int j = 0; j < 12; j++) {
            output[j] = (temp_output[5 * j + 4] & 0x1) + ((temp_output[5 * j + 3] << 1) & 0x3) + ((temp_output[5 * j + 2] << 2) & 0x7) + ((temp_output[5 * j + 1] << 3) & 0xf) + ((temp_output[5 * j] << 4) & 0x1f);
        }
    }
    else {
        for (int j = 0; j < 15; j++) {
            output[j] = (temp_output[4 * j + 3] & 0x1) + ((temp_output[4 * j + 2] << 1) & 0x3) + ((temp_output[4 * j + 1] << 2) & 0x7) + ((temp_output[4 * j] << 3) & 0xf);
        }
    }
}

void WB_gen_encryption_table(WB_ENCRYPTION_TABLE* tab, enc_data* enc_data, dec_data* dec_data) {
    int i, j, k, x, y, z;
    byte temp[15] = { 0 };
    byte Matrix_ith[60][5];
    byte masked_test = 0;
    byte input;

    matrix_gen(tab->binary_Matrix, tab->Inv_binary_Matrix, Matrix_size);

    for (i = 0; i < 12; i++) {

        gen_random_5bits(tab->G_BOX[i], tab->Inv_G_BOX[i]);

        for (j = 0; j < 64; j++)
            tab->F_BOX[i][j] = rand() & 0x1f;

        for (j = 0; j < 15; j++)
            gen_random_4bits(tab->H_BOX[i][j], tab->Inv_H_BOX[i][j]);

        matrix_distribution(Matrix_ith, tab->binary_Matrix, 5 * i);
        for (j = 0; j < 32; j++) {
            for (k = 0; k < 64; k++) {
                input = tab->G_BOX[i][j] ^ tab->F_BOX[i][k];
                Matrix_multiplication_inTBOX(Matrix_ith, input, temp);
                for (z = 0; z < 15; z++)
                    tab->TBOX[i][(j << 6) + k][z] = tab->H_BOX[i][z][temp[z]];
            }
        }
    }

    for (i = 0; i < 15; i++) {
        for (j = 0; j < 10; j++) {
            gen_random_4bits(tab->H_add_BOX[i][j], tab->Inv_H_add_BOX[i][j]);
        }

        for (j = 0; j < 16; j++) {
            for (k = 0; k < 16; k++) {
                masked_test = (j << 4) + k;
                tab->Masked_adders[i][9][masked_test] = tab->H_add_BOX[i][9][tab->Inv_H_BOX[11][i][j] ^ tab->Inv_H_BOX[10][i][k]];
            }
        }

        for (j = 0; j < 9; j++) {
            for (k = 0; k < 16; k++) {
                for (z = 0; z < 16; z++) {
                    masked_test = (k << 4) + z;
                    tab->Masked_adders[i][8 - j][masked_test] = tab->H_add_BOX[i][8 - j][tab->Inv_H_add_BOX[i][9 - j][k] ^ tab->Inv_H_BOX[9 - j][i][z]];
                }
            }
        }

        for (j = 0; j < Round; j++) {
            gen_random_4bits(tab->H_addLast_BOX[j][i], tab->Inv_H_addLast_BOX[j][i]);
            for (k = 0; k < 16; k++) {
                for (z = 0; z < 16; z++) {
                    masked_test = (k << 4) + z;
                    tab->Masked_adders_Last[j][i][masked_test] = tab->H_addLast_BOX[j][i][tab->Inv_H_add_BOX[i][0][k] ^ tab->Inv_H_BOX[0][i][z]];
                }
            }
        }
    }

    byte Master_Key[72 * Round] = { 0 };

    int d = 0;
    for (k = 0; k < Round; k++) {
        Key_generation_in_Round(Master_Key + d);
        d += 72;
    }

    WB_write_tab_ext_encoding(tab, "tab_data.bin");
    enc_data_write(enc_data, tab, Master_Key, "enc_data.bin");
    dec_data_write(dec_data, tab, Master_Key, "dec_data.bin");

}