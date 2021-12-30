#pragma once
#include<stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <memory.h>

typedef unsigned char byte;
typedef unsigned int word;
#define Round 16
#define Matrix_size 60

typedef struct {
    __int16 TBOX[12][2048][15];
    bool binary_Matrix[Matrix_size][Matrix_size];
    bool Inv_binary_Matrix[Matrix_size][Matrix_size];
    byte G_BOX[12][32];
    byte Inv_G_BOX[12][32];
    byte F_BOX[12][64];
    byte H_BOX[12][15][16];
    byte Inv_H_BOX[12][15][16];
    byte H_add_BOX[15][10][16];
    byte Inv_H_add_BOX[15][10][16];
    byte H_addLast_BOX[Round][15][16];
    byte Inv_H_addLast_BOX[Round][15][16];
    byte Masked_adders[15][10][256];
    byte Masked_adders_Last[Round][15][256];
} WB_ENCRYPTION_TABLE;

typedef struct {
    int round_num;
    byte Key[72 * Round];
    __int16 TBOX[12][2048][15];
    byte Masked_adders[15][10][256];
    byte Masked_adders_Last[Round][15][256];
} enc_data;

typedef struct {
    int round_num;
    byte Key[72 * Round];
    byte Inv_H_addLast_BOX[Round][15][16];
    bool Inv_binary_Matrix[Matrix_size][Matrix_size];
    byte Inv_G_BOX[12][32];
    byte F_BOX[12][64];
} dec_data;

/*********functions***********/
void bit5_to_bit8(byte* input, byte* output, byte padding_value);
void bit4_to_bit5(byte* input, byte* output);
void bit5_to_bit4(byte* input, byte* output);

/***********Random Bytes functions*************/
void swap_byte(byte* x, byte* y);
void shuffle_5bits(byte* x);
void shuffle_4bits(byte* x);
void get_inv_map_4bits(byte* dst, const byte* src);
void gen_random_4bits(byte* map, byte* map_inv);
void get_inv_map_5bits(byte* dst, const byte* src);
void gen_random_5bits(byte* map, byte* map_inv);

/***********WB encoding fwrite/fread functions*************/
void WB_write_enc_ext_encoding(enc_data* ctx, char* file_name);
void WB_read_enc_ext_encoding(enc_data* ctx, char* file_name);
void WB_write_dec_ext_encoding(dec_data* ctx, char* file_name);
void WB_read_dec_ext_encoding(dec_data* ctx, char* file_name);

/***********WB table generation functions*************/
void enc_data_write(enc_data* enc_data, WB_ENCRYPTION_TABLE* tab, byte* Master_Key, char* file_name);
void dec_data_write(dec_data* dec_data, WB_ENCRYPTION_TABLE* tab, byte* Master_Key, char* file_name);
void Key_generation_in_Round(byte* Master_Key);
void matrix_distribution(bool(*output)[5], bool(*M)[60], byte i);
void Matrix_multiplication_inTBOX(bool(*M)[5], byte input, byte* output);
void Matrix_multiplication_total(bool(*M)[60], byte* input, byte* output, int input_size, int output_size);
void WB_gen_encryption_table(WB_ENCRYPTION_TABLE* tab, enc_data* enc_data, dec_data* dec_data);