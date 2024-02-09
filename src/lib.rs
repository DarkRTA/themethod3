// mogg v16 is dead
//
// ```
//[package]
//name = "toasters"
//version = "0.1.0"
//edition = "2021"
//
//[dependencies]
//aes = "0.8.3"
//```

use std::io::Cursor;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;

use aes::cipher::generic_array::GenericArray;
use aes::cipher::BlockDecrypt;
use aes::cipher::BlockEncrypt;
use aes::cipher::KeyInit;
use aes::Aes128;

pub fn decrypt_mogg(mogg_data: &mut [u8]) {
    let ctr_key_0b = match mogg_data[0] {
        10 => return,
        11 => CTR_KEY_0B,
        12 | 13 => gen_key(&HV_KEY_0C, mogg_data, 12),
        14 => gen_key(&HV_KEY_0E, mogg_data, 14),
        15 => gen_key(&HV_KEY_0F, mogg_data, 15),
        16 => gen_key(&HV_KEY_10, mogg_data, 16),
        _ => unreachable!(),
    };

    let ogg_offset =
        i32::from_le_bytes(mogg_data[4..4 + 4].try_into().unwrap()) as usize;
    let hmx_header_size =
        i32::from_le_bytes(mogg_data[16..16 + 4].try_into().unwrap()) as usize;

    let nonce_offset = 20 + hmx_header_size * 8;
    let mut nonce = [0u8; 16];
    nonce.copy_from_slice(&mogg_data[nonce_offset..nonce_offset + 16]);
    let mut nonce_reversed = nonce;
    nonce_reversed.reverse();

    do_crypt(&ctr_key_0b, mogg_data, &nonce, ogg_offset);

    // check for HMXA
    if mogg_data[ogg_offset] == 0x48 {
        hmxa_to_ogg(mogg_data, ogg_offset, hmx_header_size)
    }
    // check if not OggS
    if mogg_data[ogg_offset] != 0x4f {
        mogg_data[0] = 10;
        eprintln!("WARNING: DECRYPT FAILED")
    }

    mogg_data[0] = 10;
}

const CTR_KEY_0B: [u8; 16] = [
    0x37, 0xb2, 0xe2, 0xb9, 0x1c, 0x74, 0xfa, 0x9e, 0x38, 0x81, 0x08, 0xea,
    0x36, 0x23, 0xdb, 0xe4,
];

const HV_KEY_0C: [u8; 16] = [
    0x01, 0x22, 0x00, 0x38, 0xd2, 0x01, 0x78, 0x8b, 0xdd, 0xcd, 0xd0, 0xf0,
    0xfe, 0x3e, 0x24, 0x7f,
];
const HV_KEY_0E: [u8; 16] = [
    0x51, 0x73, 0xad, 0xe5, 0xb3, 0x99, 0xb8, 0x61, 0x58, 0x1a, 0xf9, 0xb8,
    0x1e, 0xa7, 0xbe, 0xbf,
];
const HV_KEY_0F: [u8; 16] = [
    0xc6, 0x22, 0x94, 0x30, 0xd8, 0x3c, 0x84, 0x14, 0x08, 0x73, 0x7c, 0xf2,
    0x23, 0xf6, 0xeb, 0x5a,
];
const HV_KEY_10: [u8; 16] = [
    0x02, 0x1a, 0x83, 0xf3, 0x97, 0xe9, 0xd4, 0xb8, 0x06, 0x74, 0x14, 0x6b,
    0x30, 0x4c, 0x00, 0x91,
];

const HIDDEN_KEYS: [[u8; 32]; 12] = [
    [
        0x7f, 0x95, 0x5b, 0x9d, 0x94, 0xba, 0x12, 0xf1, 0xd7, 0x5a, 0x67, 0xd9,
        0x16, 0x45, 0x28, 0xdd, 0x61, 0x55, 0x55, 0xaf, 0x23, 0x91, 0xd6, 0x0a,
        0x3a, 0x42, 0x81, 0x18, 0xb4, 0xf7, 0xf3, 0x04,
    ],
    [
        0x78, 0x96, 0x5d, 0x92, 0x92, 0xb0, 0x47, 0xac, 0x8f, 0x5b, 0x6d, 0xdc,
        0x1c, 0x41, 0x7e, 0xda, 0x6a, 0x55, 0x53, 0xaf, 0x20, 0xc8, 0xdc, 0x0a,
        0x66, 0x43, 0xdd, 0x1c, 0xb2, 0xa5, 0xa4, 0x0c,
    ],
    [
        0x7e, 0x92, 0x5c, 0x93, 0x90, 0xed, 0x4a, 0xad, 0x8b, 0x07, 0x36, 0xd3,
        0x10, 0x41, 0x78, 0x8f, 0x60, 0x08, 0x55, 0xa8, 0x26, 0xcf, 0xd0, 0x0f,
        0x65, 0x11, 0x84, 0x45, 0xb1, 0xa0, 0xfa, 0x57,
    ],
    [
        0x79, 0x97, 0x0b, 0x90, 0x92, 0xb0, 0x44, 0xad, 0x8a, 0x0e, 0x60, 0xd9,
        0x14, 0x11, 0x7e, 0x8d, 0x35, 0x5d, 0x5c, 0xfb, 0x21, 0x9c, 0xd3, 0x0e,
        0x32, 0x40, 0xd1, 0x48, 0xb8, 0xa7, 0xa1, 0x0d,
    ],
    [
        0x28, 0xc3, 0x5d, 0x97, 0xc1, 0xec, 0x42, 0xf1, 0xdc, 0x5d, 0x37, 0xda,
        0x14, 0x47, 0x79, 0x8a, 0x32, 0x5c, 0x54, 0xf2, 0x72, 0x9d, 0xd3, 0x0d,
        0x67, 0x4c, 0xd6, 0x49, 0xb4, 0xa2, 0xf3, 0x50,
    ],
    [
        0x28, 0x96, 0x5e, 0x95, 0xc5, 0xe9, 0x45, 0xad, 0x8a, 0x5d, 0x64, 0x8e,
        0x17, 0x40, 0x2e, 0x87, 0x36, 0x58, 0x06, 0xfd, 0x75, 0x90, 0xd0, 0x5f,
        0x3a, 0x40, 0xd4, 0x4c, 0xb0, 0xf7, 0xa7, 0x04,
    ],
    [
        0x2c, 0x96, 0x01, 0x96, 0x9b, 0xbc, 0x15, 0xa6, 0xde, 0x0e, 0x65, 0x8d,
        0x17, 0x47, 0x2f, 0xdd, 0x63, 0x54, 0x55, 0xaf, 0x76, 0xca, 0x84, 0x5f,
        0x62, 0x44, 0x80, 0x4a, 0xb3, 0xf4, 0xf4, 0x0c,
    ],
    [
        0x7e, 0xc4, 0x0e, 0xc6, 0x9a, 0xeb, 0x43, 0xa0, 0xdb, 0x0a, 0x64, 0xdf,
        0x1c, 0x42, 0x24, 0x89, 0x63, 0x5c, 0x55, 0xf3, 0x71, 0x90, 0xdc, 0x5d,
        0x60, 0x40, 0xd1, 0x4d, 0xb2, 0xa3, 0xa7, 0x0d,
    ],
    [
        0x2c, 0x9a, 0x0b, 0x90, 0x9a, 0xbe, 0x47, 0xa7, 0x88, 0x5a, 0x6d, 0xdf,
        0x13, 0x1d, 0x2e, 0x8b, 0x60, 0x5e, 0x55, 0xf2, 0x74, 0x9c, 0xd7, 0x0e,
        0x60, 0x40, 0x80, 0x1c, 0xb7, 0xa1, 0xf4, 0x02,
    ],
    [
        0x28, 0x96, 0x5b, 0x95, 0xc1, 0xe9, 0x40, 0xa3, 0x8f, 0x0c, 0x32, 0xdf,
        0x43, 0x1d, 0x24, 0x8d, 0x61, 0x09, 0x54, 0xab, 0x27, 0x9a, 0xd3, 0x58,
        0x60, 0x16, 0x84, 0x4f, 0xb3, 0xa4, 0xf3, 0x0d,
    ],
    [
        0x25, 0x93, 0x08, 0xc0, 0x9a, 0xbd, 0x10, 0xa2, 0xd6, 0x09, 0x60, 0x8f,
        0x11, 0x1d, 0x7a, 0x8f, 0x63, 0x0b, 0x5d, 0xf2, 0x21, 0xec, 0xd7, 0x08,
        0x62, 0x40, 0x84, 0x49, 0xb0, 0xad, 0xf2, 0x07,
    ],
    [
        0x29, 0xc3, 0x0c, 0x96, 0x96, 0xeb, 0x10, 0xa0, 0xda, 0x59, 0x32, 0xd3,
        0x17, 0x41, 0x25, 0xdc, 0x63, 0x08, 0x04, 0xae, 0x77, 0xcb, 0x84, 0x5a,
        0x60, 0x4d, 0xdd, 0x45, 0xb5, 0xf4, 0xa0, 0x05,
    ],
];

fn ascii_digit_to_hex(h: u8) -> u8 {
    if !(0x61..=0x66).contains(&h) {
        if !(0x41..=0x46).contains(&h) {
            h - 0x30
        } else {
            h - 0x37
        }
    } else {
        h.wrapping_add(0xa9)
    }
}

fn do_crypt(
    key: &[u8; 16],
    mogg_data: &mut [u8],
    file_nonce: &[u8; 16],
    ogg_offset: usize,
) {
    let aes = Aes128::new(key.into());
    // avoid clobbering the nonce for rn
    let mut nonce = file_nonce.to_owned();
    let mut block_mask = [0u8; 16];
    aes.encrypt_block_b2b(
        GenericArray::from_slice(&nonce),
        GenericArray::from_mut_slice(&mut block_mask),
    );
    let mut block_offset = 0;
    for byte in mogg_data.iter_mut().skip(ogg_offset) {
        if block_offset == 16 {
            for j in &mut nonce {
                *j = j.wrapping_add(1);
                if *j != 0 {
                    break;
                }
            }
            aes.encrypt_block_b2b(
                GenericArray::from_slice(&nonce),
                GenericArray::from_mut_slice(&mut block_mask),
            );
            block_offset = 0;
        }

        *byte ^= block_mask[block_offset];
        block_offset += 1;
    }
}

fn get_masher() -> [u8; 32] {
    let mut m_masher_word: i32;
    let mut masher_word: i32 = 0xeb;
    let mut masher = [0i32; 8];

    for (idx, byte) in masher.iter_mut().enumerate() {
        m_masher_word = 0;
        if idx == 0 {
            m_masher_word = 0xeb;
        }
        if m_masher_word != 0 {
            masher_word = m_masher_word;
        }
        masher_word =
            masher_word.wrapping_mul(0x19660e).wrapping_add(0x3c6ef35f);
        *byte = masher_word;
    }

    let mut out = Vec::new();

    for i in masher {
        out.append(&mut i.to_le_bytes().into())
    }

    out.try_into().unwrap()
}

fn read_u32_le<T: Read>(stream: &mut T) -> u32 {
    let mut buf = [0u8; 4];
    stream.read_exact(&mut buf).unwrap();
    u32::from_le_bytes(buf)
}

fn read_u64_le<T: Read>(stream: &mut T) -> u64 {
    let mut buf = [0u8; 8];
    stream.read_exact(&mut buf).unwrap();
    u64::from_le_bytes(buf)
}

fn gen_key(hv_key: &[u8; 16], mogg_data: &[u8], version: u32) -> [u8; 16] {
    let mut mogg = Cursor::new(mogg_data);
    let mut key_mask_ps3_as_read = [0u8; 16];
    let mut key_mask_360_as_read = [0u8; 16];

    let masher = get_masher();
    println!("masher: {masher:X?}");

    mogg.seek(SeekFrom::Start(16)).unwrap();
    let mut buf = [0u8; 4];
    mogg.read_exact(&mut buf).unwrap();
    let hmx_header_size = u32::from_le_bytes(buf) as u64;

    mogg.seek(SeekFrom::Start(20 + hmx_header_size * 8 + 16 + 16))
        .unwrap();
    mogg.read_exact(&mut key_mask_ps3_as_read).unwrap();

    mogg.seek(SeekFrom::Start(20 + hmx_header_size * 8 + 16 + 32))
        .unwrap();
    mogg.read_exact(&mut key_mask_360_as_read).unwrap();

    let key_mask_ps3 = key_mask_ps3_as_read;

    let aes_360 = Aes128::new(hv_key.into());
    let mut key_mask_360 = [0u8; 16];
    match version {
        12..=16 => {
            aes_360.decrypt_block_b2b(
                GenericArray::from_slice(&key_mask_360_as_read),
                GenericArray::from_mut_slice(&mut key_mask_360),
            );
        }
        _ => unreachable!(),
    }

    println!("keyMaskPS3: {key_mask_ps3:X?}");
    println!("keyMask360: {key_mask_360:X?}");

    mogg.seek(SeekFrom::Start(20 + hmx_header_size * 8 + 16))
        .unwrap();
    let magic_a = read_u32_le(&mut mogg);

    mogg.seek(SeekFrom::Start(20 + hmx_header_size * 8 + 16 + 8))
        .unwrap();
    let magic_b = read_u32_le(&mut mogg);

    mogg.seek(SeekFrom::Start(20 + hmx_header_size * 8 + 16 + 48))
        .unwrap();
    let key_index_as_read = read_u64_le(&mut mogg);
    let key_index_ps3 = key_index_as_read % 6;
    let key_index_360 = key_index_as_read % 6 + 6;

    println!("keyIndexPS3: {key_index_ps3:X?}");
    println!("keyIndex360: {key_index_360:X?}");

    let selected_key_ps3;
    let selected_key_360;
    match version {
        12..=16 => {
            selected_key_ps3 = HIDDEN_KEYS[key_index_ps3 as usize];
            selected_key_360 = HIDDEN_KEYS[key_index_360 as usize];
        }
        _ => unreachable!(),
    }

    println!("selectedKeyPS3: {selected_key_ps3:X?}");
    println!("selectedKey360: {selected_key_360:X?}");

    let revealed_key_ps3 = reveal_key(selected_key_ps3, masher);
    let revealed_key_360 = reveal_key(selected_key_360, masher);

    println!("revealedKeyPS3 hex: {revealed_key_ps3:X?}");
    println!("revealedKey360 hex: {revealed_key_360:X?}");

    let bytes_from_hex_string_ps3 = hex_string_to_bytes(revealed_key_ps3);
    let bytes_from_hex_string_360 = hex_string_to_bytes(revealed_key_360);

    println!("revealedKeyPS3 char: {bytes_from_hex_string_ps3:X?}");
    println!("revealedKey360 char: {bytes_from_hex_string_360:X?}");

    let grind_array_result_ps3 =
        grind_array(magic_a, magic_b, bytes_from_hex_string_ps3, version);
    let grind_array_result_360 =
        grind_array(magic_a, magic_b, bytes_from_hex_string_360, version);

    println!("grind_array_resut_PS3 char: {grind_array_result_ps3:X?}");
    println!("grind_array_resut_360 char: {grind_array_result_360:X?}");

    let mut ps3_key = [0u8; 16];
    for i in 0..16 {
        ps3_key[i] = grind_array_result_ps3[i] ^ key_mask_ps3[i];
    }

    let mut x360_key = [0u8; 16];
    for i in 0..16 {
        x360_key[i] = grind_array_result_360[i] ^ key_mask_360[i];
    }

    if ps3_key != x360_key {
        eprintln!("warning: ps3 key does not match 360 key");
    }

    println!("ps3_key: {ps3_key:X?}");
    println!("360_key: {x360_key:X?}");
    x360_key
}

fn reveal_key(key: [u8; 32], masher: [u8; 32]) -> [u8; 32] {
    let mut key = key;
    for _ in 0..14 {
        supershuffle(&mut key);
    }

    key.iter()
        .zip(masher)
        .map(|(x, y)| *x ^ y)
        .collect::<Vec<u8>>()
        .try_into()
        .unwrap()
}

fn supershuffle(key: &mut [u8; 32]) {
    shuffle1(key);
    shuffle2(key);
    shuffle3(key);
    shuffle4(key);
    shuffle5(key);
    shuffle6(key);
}

fn shuffle1(key: &mut [u8; 32]) {
    for i in 0..8 {
        let offset = roll(i << 2);
        key.swap(offset, (i * 4) + 2);
        let offset = roll((i * 4) + 3);
        key.swap(offset, (i * 4) + 1);
    }
}

fn shuffle2(key: &mut [u8; 32]) {
    for i in 0..8 {
        key.swap(((7 - i) * 4) + 1, (i * 4) + 2);
        key.swap((7 - i) * 4, (i * 4) + 3);
    }
}

fn shuffle3(key: &mut [u8; 32]) {
    for i in 0..8 {
        let offset = roll(((7 - i) * 4) + 1);
        key.swap(offset, (i * 4) + 2);
        key.swap((7 - i) * 4, (i * 4) + 3);
    }
}

fn shuffle4(key: &mut [u8; 32]) {
    for i in 0..8 {
        key.swap(((7 - i) * 4) + 1, (i * 4) + 2);
        let offset = roll((7 - i) * 4);
        key.swap(offset, (i * 4) + 3);
    }
}

fn shuffle5(key: &mut [u8; 32]) {
    for i in 0..8 {
        let offset = roll((i * 4) + 2);
        key.swap(((7 - i) * 4) + 1, offset);
        key.swap((7 - i) * 4, (i * 4) + 3);
    }
}

fn shuffle6(key: &mut [u8; 32]) {
    for i in 0..8 {
        key.swap(((7 - i) * 4) + 1, (i * 4) + 2);
        let offset = roll((i * 4) + 3);
        key.swap((7 - i) * 4, offset);
    }
}

fn roll(x: usize) -> usize {
    (x + 0x13) % 0x20
}

fn hex_string_to_bytes(s: [u8; 32]) -> [u8; 16] {
    let mut arr = [0u8; 16];
    for i in 0..16 {
        arr[i] = ascii_digit_to_hex(s[i * 2]) << 4
            | ascii_digit_to_hex(s[i * 2 + 1]);
    }
    arr
}

fn lcg(x: u32) -> u32 {
    x.wrapping_mul(0x19660d).wrapping_add(0x3c6ef35f)
}

fn grind_array(
    mut magic_a: u32,
    mut magic_b: u32,
    mut key: [u8; 16],
    version: u32,
) -> [u8; 16] {
    let mut _i: i32;
    let mut num: u32;
    let mut array = [0u8; 64];
    let mut array1 = [0u8; 64];
    let mut num1: u32 = magic_a;
    let num2: u32 = magic_b;
    let mut array2 = [0i32; 256];

    for item in &mut array2 {
        *item = (magic_a as u8 >> 3) as i32;
        magic_a = lcg(magic_a)
    }

    if magic_b == 0 {
        magic_b = 0x303f;
    }

    #[allow(clippy::needless_range_loop)]
    for i in 0..0x20 {
        loop {
            magic_b = lcg(magic_b);
            num = magic_b >> 2 & 0x1f;
            if array[num as usize] == 0 {
                break;
            }
        }
        array1[i] = num as u8;
        array[num as usize] = 1;
    }
    let mut array3 = array2;
    let mut array4 = [0i32; 256];
    magic_a = num2;

    for item in &mut array4 {
        *item = (magic_a as u8 >> 2 & 0x3f) as i32;
        magic_a = lcg(magic_a)
    }

    if version > 13 {
        #[allow(clippy::needless_range_loop)]
        for i in 32..64 {
            loop {
                num1 = lcg(num1);
                num = (num1 >> 2 & 0x1f) + 0x20;
                if array[num as usize] == 0 {
                    break;
                }
            }
            array1[i] = num as u8;
            array[num as usize] = 1;
        }
        array3 = array4;
    }
    for j in 0..16 {
        let mut num3 = key[j];
        for k in (0..16).step_by(2) {
            num3 = o_funcs(
                num3,
                key[k + 1],
                array1[array3[key[k] as usize] as usize],
            );
        }
        key[j] = num3;
    }
    key
}

fn rotr(x: i32, n: u32) -> i32 {
    u8::rotate_right(x as u8, n) as i32
}

fn rotl(x: i32, n: u32) -> i32 {
    u8::rotate_left(x as u8, n) as i32
}

fn not(x: i32) -> i32 {
    if x == 0 {
        1
    } else {
        0
    }
}

fn o_funcs(a1: u8, a2: u8, op: u8) -> u8 {
    let a1 = a1 as i32;
    let a2 = a2 as i32;
    (match op {
        0 => a2 + rotr(a1, not(a2) as u32),
        1 => a2 + rotr(a1, 3),
        2 => a2 + rotl(a1, 1),
        3 => a2 ^ (a1 >> (a2 & 7 & 31) | (a1 << (-a2 & 7 & 31))),
        4 => a2 ^ rotl(a1, 4),
        5 => a2 + (a2 ^ rotr(a1, 3)),
        6 => a2 + rotl(a1, 2),
        7 => a2 + not(a1),
        8 => a2 ^ rotr(a1, not(a2) as u32),
        9 => a2 ^ (a2 + rotl(a1, 3)),
        10 => a2 + rotl(a1, 3),
        11 => a2 + rotl(a1, 4),
        12 => a1 ^ a2,
        13 => a2 ^ not(a1),
        14 => a2 ^ (a2 + rotr(a1, 3)),
        15 => a2 ^ rotl(a1, 3),
        16 => a2 ^ rotl(a1, 2),
        17 => a2 + (a2 ^ rotl(a1, 3)),
        18 => a2 + (a1 ^ a2),
        19 => a1 + a2,
        20 => a2 ^ rotr(a1, 3),
        21 => a2 ^ (a1 + a2),
        22 => rotr(a1, not(a2) as u32),
        23 => a2 + rotr(a1, 1),
        24 => a1 >> (a2 & 7 & 31) | a1 << (-a2 & 7 & 31),
        25 => {
            if a1 == 0 {
                if a2 == 0 {
                    128
                } else {
                    1
                }
            } else {
                0
            }
        }
        26 => a2 + rotr(a1, 2),
        27 => a2 ^ rotr(a1, 1),
        28 => o_funcs(!a1 as u8, a2 as u8, 24) as i32, // lmao
        29 => a2 ^ rotr(a1, 2),
        30 => a2 + (a1 >> (a2 & 7 & 31) | (a1 << (-a2 & 7 & 31))),
        31 => a2 ^ rotl(a1, 1),
        32 => ((a1 << 8 | 170 | a1 ^ 255) >> 4) ^ a2,
        33 => (a1 ^ 255 | a1 << 8) >> 3 ^ a2,
        34 => (a1 << 8 ^ 65280 | a1) >> 2 ^ a2,
        35 => (a1 ^ 92 | a1 << 8) >> 5 ^ a2,
        36 => (a1 << 8 | 101 | a1 ^ 60) >> 2 ^ a2,
        37 => (a1 ^ 54 | a1 << 8) >> 2 ^ a2,
        38 => (a1 ^ 54 | a1 << 8) >> 4 ^ a2,
        39 => (a1 ^ 92 | a1 << 8 | 54) >> 1 ^ a2,
        40 => (a1 ^ 255 | a1 << 8) >> 5 ^ a2,
        41 => (!a1 << 8 | a1) >> 6 ^ a2,
        42 => (a1 ^ 92 | a1 << 8) >> 3 ^ a2,
        43 => (a1 ^ 60 | 101 | a1 << 8) >> 5 ^ a2,
        44 => (a1 ^ 54 | a1 << 8) >> 1 ^ a2,
        45 => (a1 ^ 101 | a1 << 8 | 60) >> 6 ^ a2,
        46 => (a1 ^ 92 | a1 << 8) >> 2 ^ a2,
        47 => (a2 ^ 170 | a2 << 8 | 255) >> 3 ^ a1,
        48 => (a1 ^ 99 | a1 << 8 | 92) >> 6 ^ a2,
        49 => (a1 ^ 92 | a1 << 8 | 54) >> 7 ^ a2,
        50 => (a1 ^ 92 | a1 << 8) >> 6 ^ a2,
        51 => (a1 << 8 ^ 65280 | a1) >> 3 ^ a2,
        52 => (a1 ^ 255 | a1 << 8) >> 6 ^ a2,
        53 => (a1 << 8 ^ 65280 | a1) >> 5 ^ a2,
        54 => (a1 ^ 60 | 101 | a1 << 8) >> 4 ^ a2,
        55 => (a1 ^ 99 | a1 << 8 | 92) >> 3 ^ a2,
        56 => (a1 ^ 99 | a1 << 8 | 92) >> 5 ^ a2,
        57 => (a1 ^ 175 | a1 << 8 | 250) >> 5 ^ a2,
        58 => (a1 ^ 92 | a1 << 8 | 54) >> 5 ^ a2,
        59 => (a1 ^ 92 | a1 << 8 | 54) >> 3 ^ a2,
        60 => (a1 ^ 54 | a1 << 8) >> 3 ^ a2,
        61 => (a1 ^ 99 | a1 << 8 | 92) >> 4 ^ a2,
        62 => (a1 ^ 255 | a1 << 8 | 175) >> 6 ^ a2,
        63 => (a1 ^ 255 | a1 << 8) >> 2 ^ a2,
        _ => unreachable!(),
    }) as u8
}

fn hmxa_to_ogg(mogg_data: &mut [u8], start: usize, num_entries: usize) {
    let magic_a = u32::from_le_bytes(
        mogg_data[20 + num_entries * 8 + 16..][..4]
            .try_into()
            .unwrap(),
    );
    let magic_b = u32::from_le_bytes(
        mogg_data[20 + num_entries * 8 + 16 + 8..][..4]
            .try_into()
            .unwrap(),
    );
    let magic_hash_a = lcg(lcg(magic_a ^ 0x5c5c5c5c));
    let magic_hash_b = lcg(magic_b ^ 0x36363636);

    mogg_data[start..][..4].copy_from_slice(&[0x4f, 0x67, 0x67, 0x53]);

    let slice_a = &mut mogg_data[start + 12..][..4];
    let val_a = u32::from_be_bytes(slice_a.try_into().unwrap());
    slice_a.copy_from_slice(&u32::to_be_bytes(val_a ^ magic_hash_a));

    let slice_b = &mut mogg_data[start + 20..][..4];
    let val_b = u32::from_be_bytes(slice_b.try_into().unwrap());
    slice_b.copy_from_slice(&u32::to_be_bytes(val_b ^ magic_hash_b));
}
