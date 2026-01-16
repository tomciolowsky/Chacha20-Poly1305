#include <bits/stdc++.h>
using namespace std;

uint32_t roll(uint32_t x, int n){
    return (x << n) | (x >> (32-n));
}

void hexprint(uint32_t x){
    printf("%08" PRIx32 "  ", x);
}

void stateprint(uint32_t (&state)[16]){
    for (int i=0; i<16; i++){
        hexprint(state[i]);
        if (i % 4 == 3){
            cout<<'\n';
        }
    }
}

void QUARTERROUND(uint32_t (&state)[16], int x, int y, int z, int w){
    uint32_t a = state[x];
    uint32_t b = state[y];
    uint32_t c = state[z];
    uint32_t d = state[w];
    a += b; d ^= a; d = roll(d,16);
    c += d; b ^= c; b = roll(b,12);
    a += b; d ^= a; d = roll(d,8);
    c += d; b ^= c; b = roll(b,7);
    state[x] = a;
    state[y] = b;
    state[z] = c;
    state[w] = d;
}

void inner_block(uint32_t (&state)[16]){
    QUARTERROUND(state, 0, 4, 8, 12);
    QUARTERROUND(state, 1, 5, 9, 13);
    QUARTERROUND(state, 2, 6, 10, 14);
    QUARTERROUND(state, 3, 7, 11, 15);
    QUARTERROUND(state, 0, 5, 10, 15);
    QUARTERROUND(state, 1, 6, 11, 12);
    QUARTERROUND(state, 2, 7, 8, 13);
    QUARTERROUND(state, 3, 4, 9, 14);
}

void chacha20_block(uint32_t (&state)[16], uint8_t (&key)[32], uint8_t (&nonce)[12], uint32_t block_counter){
    state[0] = 0x61707865;
    state[1] = 0x3320646e;
    state[2] = 0x79622d32;
    state[3] = 0x6b206574;

    int j=0;
    for (int i=4; i<12; i++){
        state[i] = (key[j]<<0)+(key[j+1]<<8)+(key[j+2]<<16)+(key[j+3]<<24);
        j+=4; 
    }

    state[12] = block_counter;

    j=0;
    for (int i=13; i<16; i++){
        state[i] = (nonce[j]<<0)+(nonce[j+1]<<8)+(nonce[j+2]<<16)+(nonce[j+3]<<24);
        j+=4; 
    }

    uint32_t initial_state[16];

    copy(begin(state), end(state), begin(initial_state));

    for (int i = 0; i < 10; i++)
    {
        inner_block(state);
    }

    for (int i = 0; i < 16; i++)
    {
        state[i] += initial_state[i];
    }
}

void chacha20_encrypt(vector<uint8_t>&encrypted_message, uint8_t (&key)[32], uint8_t (&nonce)[12], uint32_t block_counter, vector<uint8_t>&plaintext){
    uint32_t keystream[16];
    
    for (int j=0; j<=(int)(plaintext.size()/64)-1; j++){
        chacha20_block(keystream, key, nonce, block_counter+j);
        
        for (int i = 0; i < 16; i++){
            encrypted_message.push_back((plaintext[j*64+(i*4)+0] ^ ((keystream[i]>>0)&0x000000FF)));
            encrypted_message.push_back((plaintext[j*64+(i*4)+1] ^ ((keystream[i]>>8)&0x000000FF)));
            encrypted_message.push_back((plaintext[j*64+(i*4)+2] ^ ((keystream[i]>>16)&0x000000FF)));
            encrypted_message.push_back((plaintext[j*64+(i*4)+3] ^ ((keystream[i]>>24)&0x000000FF)));
        }
    }
    if ((plaintext.size() % 64) != 0){
        int j = (int)(plaintext.size()/64);
        chacha20_block(keystream, key, nonce, block_counter+j);

        for (int i = j*64, k=0; i < plaintext.size(); i++, k++){
            encrypted_message.push_back((plaintext[i] ^ ((keystream[(k/4)]>>((k%4)*8))&0x000000FF)));
        }
    }
}

void chacha20_decrypt(vector<uint8_t>&plaintext, uint8_t (&key)[32], uint8_t (&nonce)[12], uint32_t block_counter, vector<uint8_t>&encrypted_message){
    uint32_t keystream[16];
    
    for (int j=0; j<=(int)(encrypted_message.size()/64)-1; j++){
        chacha20_block(keystream, key, nonce, block_counter+j);
        
        for (int i = 0; i < 16; i++){
            plaintext.push_back((encrypted_message[j*64+(i*4)+0] ^ ((keystream[i]>>0)&0x000000FF)));
            plaintext.push_back((encrypted_message[j*64+(i*4)+1] ^ ((keystream[i]>>8)&0x000000FF)));
            plaintext.push_back((encrypted_message[j*64+(i*4)+2] ^ ((keystream[i]>>16)&0x000000FF)));
            plaintext.push_back((encrypted_message[j*64+(i*4)+3] ^ ((keystream[i]>>24)&0x000000FF)));
        }
    }
    if ((encrypted_message.size() % 64) != 0){
        int j = (int)(encrypted_message.size()/64);
        chacha20_block(keystream, key, nonce, block_counter+j);

        for (int i = j*64, k=0; i < encrypted_message.size(); i++, k++){
            plaintext.push_back((encrypted_message[i] ^ ((keystream[(k/4)]>>((k%4)*8))&0x000000FF)));
        }
    }
}


void poly1305_key_gen(uint8_t (&key_gen)[32], uint8_t (&key)[32], uint8_t (&nonce)[12]){
    uint32_t counter = 0;
    uint32_t block[16];
    chacha20_block(block, key, nonce, counter);

    for (int i = 0; i < 8; i++)
    {
        key_gen[(i*4)+0] = (block[i]>>0) & 0x000000FF;
        key_gen[(i*4)+1] = (block[i]>>8) & 0x000000FF;
        key_gen[(i*4)+2] = (block[i]>>16) & 0x000000FF;
        key_gen[(i*4)+3] = (block[i]>>24) & 0x000000FF;
    }
    
}

void poly1305_mac(uint8_t (&tag)[16], uint8_t (&key)[32], vector<uint8_t>&plaintext){
    uint32_t r[5] = {};
    for (int j=0; j<4; j++){
        r[j] =  ((uint32_t)key[(j*4)+0]<<0) |
                ((uint32_t)key[(j*4)+1]<<8) |
                ((uint32_t)key[(j*4)+2]<<16) |
                ((uint32_t)key[(j*4)+3]<<24);
    }

    r[0] &= 0x0fffffff;
    r[1] &= 0x0ffffffc;
    r[2] &= 0x0ffffffc;
    r[3] &= 0x0ffffffc;

    uint32_t s[5] = {};
    for (int j=4; j<8; j++){
        s[j-4] =  ((uint32_t)key[(j*4)+0]<<0) |
                ((uint32_t)key[(j*4)+1]<<8) |
                ((uint32_t)key[(j*4)+2]<<16) |
                ((uint32_t)key[(j*4)+3]<<24);
    }

    uint32_t P[5] = {0xfffffffb, 0xffffffff, 0xffffffff, 0xffffffff, 0x3};
    uint32_t a[5] = {0x0, 0x0, 0x0, 0x0, 0x0};
    uint32_t n[5] = {};

    int total_len = plaintext.size();
    int num_blocks = (total_len + 15) / 16;

    for (int i = 0; i < num_blocks; i++){

        int offset = i*16;
        int remaining = total_len - offset;
        int block_len = remaining;
        if (remaining >= 16){
            block_len = 16;
        }

        uint8_t block[17] = {0};

        if (block_len > 0) {
            memcpy(block, &plaintext[offset], block_len);
        }

        block[block_len] = 0x01;
        
        memset(n, 0, sizeof(n));
        for (int j=0; j<4; j++){
            n[j] =  ((uint32_t)block[(j*4)+0]<<0) |
                    ((uint32_t)block[(j*4)+1]<<8) |
                    ((uint32_t)block[(j*4)+2]<<16) |
                    ((uint32_t)block[(j*4)+3]<<24);
        }
        n[4] = block[16];

        uint64_t carry = 0;

        // ADD & CARRY
        for (int j=0; j<5; j++){
            uint64_t sum = (uint64_t)a[j]+n[j]+carry;
            a[j] = (uint32_t)sum;
            carry = sum >> 32;
        }
        a[0] += carry * 5;

        for (int j = 0; j < 5; j++) {
            uint64_t x = a[j];
            a[j] = (uint32_t)x;
            carry = x >> 32;

            if (j < 4)
                a[j+1] += carry;
            else
                a[0] += carry * 5;
        }

        // MULTIPLY
        uint64_t t[10] = {};
        for (int j = 0; j < 5; j++){
            for (int k = 0; k < 5; k++)
            {
                t[j+k] += (uint64_t)a[j] * r[k];
            }
        }

        // CARRY
        for (int j = 0; j < 9; j++) {
            uint64_t carry = t[j] >> 32;
            t[j] &= 0xffffffff;
            t[j+1] += carry;
        }

        // H (bits from 130 upwards)
        uint64_t h0 = ((uint64_t)t[4] >> 2) | ((uint64_t)t[5] << 30);
        h0 &= 0xFFFFFFFF;
        uint64_t h1 = ((uint64_t)t[5] >> 2) | ((uint64_t)t[6] << 30);
        h1 &= 0xFFFFFFFF;
        uint64_t h2 = ((uint64_t)t[6] >> 2) | ((uint64_t)t[7] << 30);
        h2 &= 0xFFFFFFFF;
        uint64_t h3 = ((uint64_t)t[7] >> 2) | ((uint64_t)t[8] << 30);
        h3 &= 0xFFFFFFFF;

        // L (bits from 129 downwards)
        t[4] &= 0x00000003;

        t[5] = t[6] = t[7] = t[8] = t[9] = 0;

        carry = (uint64_t)t[0] + h0*5;
        t[0] = (uint32_t)carry;
        carry >>= 32;

        carry += (uint64_t)t[1] + h1*5;
        t[1] = (uint32_t)carry;
        carry >>= 32;

        carry += (uint64_t)t[2] + h2*5;
        t[2] = (uint32_t)carry;
        carry >>= 32;

        carry += (uint64_t)t[3] + h3*5;
        t[3] = (uint32_t)carry;
        carry >>= 32;

        carry += (uint64_t)t[4];
        t[4] = (uint32_t)carry;
        carry >>= 32;

        uint32_t high_carry = t[4] >> 2;
        t[4] &= 0x00000003;

        carry = (uint64_t)t[0] + (high_carry*5);
        t[0] = (uint32_t)carry;
        carry >>= 32;

        t[1] += (uint32_t)carry;

        for (int j = 0; j < 5; j++){
            a[j] = (uint32_t)t[j];
        } 
    }

    uint64_t sum = 0;
    for (int i = 0; i < 4; i++){
        sum = (uint64_t)a[i]+s[i]+(sum>>32);
        a[i] = (uint32_t)sum;
    }
    
    for (int i = 0; i < 4; i++)
    {
        tag[(i*4)+0] = (a[i]>>0) & 0x000000FF;
        tag[(i*4)+1] = (a[i]>>8) & 0x000000FF;
        tag[(i*4)+2] = (a[i]>>16) & 0x000000FF;
        tag[(i*4)+3] = (a[i]>>24) & 0x000000FF;
    }
    
}

void chacha20_aead_encrypt(vector<uint8_t>&ciphertext, uint8_t (&tag)[16], vector<uint8_t>aad, uint8_t (&key)[32], uint8_t (&iv)[8], uint8_t (&constant)[4], vector<uint8_t>&plaintext){
    uint8_t nonce[12];
    for (int i = 0; i < 4; i++){
        nonce[i] = constant[i];
    }
    for (int i = 0; i < 8; i++){
        nonce[i+4] = iv[i];
    }

    uint8_t otk[32];
    poly1305_key_gen(otk, key, nonce);

    uint32_t counter = 1;
    chacha20_encrypt(ciphertext, key, nonce, counter, plaintext);
    
    int len;
    vector<uint8_t> mac_data;

    for (uint8_t x : aad){
        mac_data.push_back(x);
    }
    
    len = (16-(aad.size()%16))%16;
    for (int i=0; i<len; i++){
        mac_data.push_back(0x00);
    }

    for (uint8_t x : ciphertext){
        mac_data.push_back(x);
    }
    
    len = (16-(ciphertext.size()%16))%16;
    for (int i=0; i<len; i++){
        mac_data.push_back(0x00);
    }

    uint8_t aad_length[8];
    uint8_t ciphertext_length[8];

    uint64_t aad_l = (uint64_t)aad.size();
    uint64_t ciphertext_l = (uint64_t)ciphertext.size();

    for (int i = 0; i < 8; i++){
        aad_length[i] = (aad_l >> (i*8)) & 0x000000FF;
        ciphertext_length[i] = (ciphertext_l >> (i*8)) & 0x000000FF;
    }

    for (uint8_t x : aad_length){
        mac_data.push_back(x);
    }
    for (uint8_t x : ciphertext_length){
        mac_data.push_back(x);
    }

    poly1305_mac(tag, otk, mac_data);
}

void chacha20_aead_decrypt(vector<uint8_t>&plaintext, vector<uint8_t>aad, uint8_t (&key)[32], uint8_t (&nonce)[12], vector<uint8_t>&ciphertext, uint8_t (&received_tag)[16]){
    uint8_t otk[32];
    poly1305_key_gen(otk, key, nonce);

    int len;
    vector<uint8_t> mac_data;

    for (uint8_t x : aad){
        mac_data.push_back(x);
    }
    
    len = (16-(aad.size()%16))%16;
    for (int i=0; i<len; i++){
        mac_data.push_back(0x00);
    }

    for (uint8_t x : ciphertext){
        mac_data.push_back(x);
    }
    
    len = (16-(ciphertext.size()%16))%16;
    for (int i=0; i<len; i++){
        mac_data.push_back(0x00);
    }

    uint8_t aad_length[8];
    uint8_t ciphertext_length[8];

    uint64_t aad_l = (uint64_t)aad.size();
    uint64_t ciphertext_l = (uint64_t)ciphertext.size();

    for (int i = 0; i < 8; i++){
        aad_length[i] = (aad_l >> (i*8)) & 0x000000FF;
        ciphertext_length[i] = (ciphertext_l >> (i*8)) & 0x000000FF;
    }

    for (uint8_t x : aad_length){
        mac_data.push_back(x);
    }
    for (uint8_t x : ciphertext_length){
        mac_data.push_back(x);
    }

    uint8_t tag[16];
    poly1305_mac(tag, otk, mac_data);


    for (int i=0; i<16; i++){
        if (tag[i]!=received_tag[i])
        {
            cout<<"\n\nWRONG TAG!\n\n";
            return;
        }
    }

    uint32_t counter = 1;
    chacha20_decrypt(plaintext, key, nonce, counter, ciphertext);
}

int main(){
    
    // EXAMPLE ENCRYPTION

    string s = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    vector<uint8_t> plaintext(s.begin(), s.end());

    vector<uint8_t> aad = {0x50,0x51,0x52,0x53,0xc0,0xc1,0xc2,0xc3,0xc4,0xc5,0xc6,0xc7};

    uint8_t key[] = {0x80,0x81,0x82,0x83,0x84,0x85,0x86,0x87,
                     0x88,0x89,0x8a,0x8b,0x8c,0x8d,0x8e,0x8f,
                     0x90,0x91,0x92,0x93,0x94,0x95,0x96,0x97,
                     0x98,0x99,0x9a,0x9b,0x9c,0x9d,0x9e,0x9f};

    uint8_t iv[8] = {0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47};
    
    uint8_t constant[4] = {0x07,0x00,0x00,0x00};

    uint8_t resulting_tag[16];
    vector<uint8_t> resulting_ciphertext;
    chacha20_aead_encrypt(resulting_ciphertext, resulting_tag, aad, key, iv, constant, plaintext);

    cout<<"TAG: \n";
    for(auto x : resulting_tag){
        printf("%02" PRIx8 " ", x);
    }
    cout<<'\n';

    cout<<"CIPHERTEXT: \n";
    for(auto x : resulting_ciphertext){
        printf("%02" PRIx8 " ", x);
    }
    cout<<'\n';



    // EXAMPLE DECRYPTION
    uint8_t key2[]={0x1c,0x92,0x40,0xa5,0xeb,0x55,0xd3,0x8a,
                    0xf3,0x33,0x88,0x86,0x04,0xf6,0xb5,0xf0,
                    0x47,0x39,0x17,0xc1,0x40,0x2b,0x80,0x09,
                    0x9d,0xca,0x5c,0xbc,0x20,0x70,0x75,0xc0};

    vector<uint8_t>ciphertext2= {0x64,0xa0,0x86,0x15,0x75,0x86,0x1a,0xf4,0x60,0xf0,0x62,0xc7,0x9b,0xe6,0x43,0xbd,
                                0x5e,0x80,0x5c,0xfd,0x34,0x5c,0xf3,0x89,0xf1,0x08,0x67,0x0a,0xc7,0x6c,0x8c,0xb2,
                                0x4c,0x6c,0xfc,0x18,0x75,0x5d,0x43,0xee,0xa0,0x9e,0xe9,0x4e,0x38,0x2d,0x26,0xb0,
                                0xbd,0xb7,0xb7,0x3c,0x32,0x1b,0x01,0x00,0xd4,0xf0,0x3b,0x7f,0x35,0x58,0x94,0xcf,
                                0x33,0x2f,0x83,0x0e,0x71,0x0b,0x97,0xce,0x98,0xc8,0xa8,0x4a,0xbd,0x0b,0x94,0x81,
                                0x14,0xad,0x17,0x6e,0x00,0x8d,0x33,0xbd,0x60,0xf9,0x82,0xb1,0xff,0x37,0xc8,0x55,
                                0x97,0x97,0xa0,0x6e,0xf4,0xf0,0xef,0x61,0xc1,0x86,0x32,0x4e,0x2b,0x35,0x06,0x38,
                                0x36,0x06,0x90,0x7b,0x6a,0x7c,0x02,0xb0,0xf9,0xf6,0x15,0x7b,0x53,0xc8,0x67,0xe4,
                                0xb9,0x16,0x6c,0x76,0x7b,0x80,0x4d,0x46,0xa5,0x9b,0x52,0x16,0xcd,0xe7,0xa4,0xe9,
                                0x90,0x40,0xc5,0xa4,0x04,0x33,0x22,0x5e,0xe2,0x82,0xa1,0xb0,0xa0,0x6c,0x52,0x3e,
                                0xaf,0x45,0x34,0xd7,0xf8,0x3f,0xa1,0x15,0x5b,0x00,0x47,0x71,0x8c,0xbc,0x54,0x6a,
                                0x0d,0x07,0x2b,0x04,0xb3,0x56,0x4e,0xea,0x1b,0x42,0x22,0x73,0xf5,0x48,0x27,0x1a,
                                0x0b,0xb2,0x31,0x60,0x53,0xfa,0x76,0x99,0x19,0x55,0xeb,0xd6,0x31,0x59,0x43,0x4e,
                                0xce,0xbb,0x4e,0x46,0x6d,0xae,0x5a,0x10,0x73,0xa6,0x72,0x76,0x27,0x09,0x7a,0x10,
                                0x49,0xe6,0x17,0xd9,0x1d,0x36,0x10,0x94,0xfa,0x68,0xf0,0xff,0x77,0x98,0x71,0x30,
                                0x30,0x5b,0xea,0xba,0x2e,0xda,0x04,0xdf,0x99,0x7b,0x71,0x4d,0x6c,0x6f,0x2c,0x29,
                                0xa6,0xad,0x5c,0xb4,0x02,0x2b,0x02,0x70,0x9b};

    uint8_t nonce2[] = {0x00,0x00,0x00,0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08};

    vector<uint8_t>aad2 = {0xf3,0x33,0x88,0x86,0x00,0x00,0x00,0x00,0x00,0x00,0x4e,0x91};

    uint8_t received_tag2[16] = {0xee,0xad,0x9d,0x67,0x89,0x0c,0xbb,0x22,
                                0x39,0x23,0x36,0xfe,0xa1,0x85,0x1f,0x38};

    vector<uint8_t>resulting_plaintext;
    chacha20_aead_decrypt(resulting_plaintext, aad2, key2, nonce2, ciphertext2, received_tag2);


    cout<<"PLAINTEXT: \n";
    for(auto x : resulting_plaintext){
        printf("%c", static_cast<char>(x));
    }
    cout<<'\n';

    return 0;
}



