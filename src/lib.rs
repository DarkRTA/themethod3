mod keys;

use std::error::Error;
use std::io::Cursor;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;

use aes::cipher::generic_array::GenericArray;
use aes::cipher::BlockDecrypt;
use aes::cipher::BlockEncrypt;
use aes::cipher::KeyInit;
use aes::Aes128;
use log::debug;
use log::error;
use log::trace;
use log::warn;

pub mod capi {
    #[no_mangle]
    pub unsafe extern "C" fn decrypt_mogg(data: *mut u8, len: usize) -> bool {
        let buf = std::slice::from_raw_parts_mut(data, len);

        match super::decrypt_mogg(buf) {
            Ok(vec) => {
                buf.copy_from_slice(&vec);
                true
            }
            Err(_) => false,
        }
    }
}

pub fn decrypt_mogg(mogg_data: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut mogg_data = mogg_data.to_vec();
    let version = mogg_data[0];

    debug!("version: {}", version);

    match version {
        11 => debug!("actual_key: {}", hex::encode(keys::CTR_KEY_0B)),
        12 | 13 => debug!("HvKey: 12/13, {}", hex::encode(keys::HV_KEY_0C)),
        14 => debug!("HvKey: 14, {}", hex::encode(keys::HV_KEY_0E)),
        15 => debug!("HvKey: 15, {}", hex::encode(keys::HV_KEY_0F)),
        16 => debug!("HvKey: 16, {}", hex::encode(keys::HV_KEY_10)),
        17 => debug!("HvKey: 17, {}", hex::encode(keys::HV_KEY_11)),
        _ => (),
    };

    let ctr_key_0b = match mogg_data[0] {
        10 => return Ok(mogg_data),
        11 => keys::CTR_KEY_0B,
        12 | 13 => gen_key(&keys::HV_KEY_0C, &mut mogg_data, 12)?,
        14 => gen_key(&keys::HV_KEY_0E, &mut mogg_data, 14)?,
        15 => gen_key(&keys::HV_KEY_0F, &mut mogg_data, 15)?,
        16 => gen_key(&keys::HV_KEY_10, &mut mogg_data, 16)?,
        17 => gen_key(&keys::HV_KEY_11, &mut mogg_data, 17)?,
        _ => return Err("invalid version".into()),
    };

    let ogg_offset = i32::from_le_bytes(
        mogg_data.get(4..4 + 4).ok_or("invalid index")?.try_into()?,
    ) as usize;
    let hmx_header_size = i32::from_le_bytes(
        mogg_data
            .get(16..16 + 4)
            .ok_or("invalid index")?
            .try_into()?,
    ) as usize;

    let nonce_offset = 20 + hmx_header_size * 8;
    let mut nonce = [0u8; 16];
    nonce.copy_from_slice(
        &mogg_data
            .get(nonce_offset..nonce_offset + 16)
            .ok_or("invalid index")?,
    );
    debug!("nonce: {}", hex::encode(nonce));
    let mut nonce_reversed = nonce;
    nonce_reversed.reverse();

    do_crypt(&ctr_key_0b, &mut mogg_data, &nonce, ogg_offset);

    // check for HMXA
    if mogg_data
        .get(ogg_offset..ogg_offset + 4)
        .ok_or("invalid index")?
        == [0x48, 0x4D, 0x58, 0x41]
    {
        hmxa_to_ogg(&mut mogg_data, ogg_offset, hmx_header_size)
    }

    mogg_data[0] = 10;

    // check if not OggS
    if mogg_data
        .get(ogg_offset..ogg_offset + 4)
        .ok_or("invalid index")?
        != [0x4f, 0x67, 0x67, 0x53]
    {
        error!("failed to decrypt mogg");
        Err("failed to decrypt mogg".into())
    } else {
        Ok(mogg_data)
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

    for (idx, word) in masher.iter_mut().enumerate() {
        m_masher_word = 0;
        if idx == 0 {
            m_masher_word = 0xeb;
        }
        if m_masher_word != 0 {
            masher_word = m_masher_word;
        }
        masher_word =
            masher_word.wrapping_mul(0x19660e).wrapping_add(0x3c6ef35f);
        *word = masher_word;
    }

    let mut out = Vec::new();

    for i in masher {
        out.append(&mut i.to_le_bytes().into())
    }

    out.try_into().unwrap()
}

fn read_u32_le<T: Read>(stream: &mut T) -> Result<u32, Box<dyn Error>> {
    let mut buf = [0u8; 4];
    stream.read_exact(&mut buf)?;
    Ok(u32::from_le_bytes(buf))
}

fn read_u64_le<T: Read>(stream: &mut T) -> Result<u64, Box<dyn Error>> {
    let mut buf = [0u8; 8];
    stream.read_exact(&mut buf)?;
    Ok(u64::from_le_bytes(buf))
}

fn gen_key(
    hv_key: &[u8; 16],
    mogg_data: &mut [u8],
    version: u32,
) -> Result<[u8; 16], Box<dyn Error>> {
    debug!("generating ps3 key");
    let ps3 = gen_key_inner(hv_key, mogg_data, version, true)?;
    debug!("generating xbox 360 key");
    let x360 = gen_key_inner(hv_key, mogg_data, version, false)?;

    if ps3 != x360 {
        warn!("PS3 key does not match Xbox 360 key");
    }
    Ok(x360)
}

fn gen_key_inner(
    hv_key: &[u8; 16],
    mogg_data: &[u8],
    version: u32,
    ps3_path: bool,
) -> Result<[u8; 16], Box<dyn Error>> {
    let mut mogg = Cursor::new(mogg_data);
    let mut key_mask_as_read = [0u8; 16];

    let masher = get_masher();
    debug!("masher: {}", hex::encode(masher));

    mogg.seek(SeekFrom::Start(16))?;
    let mut buf = [0u8; 4];
    mogg.read_exact(&mut buf)?;
    let hmx_header_size = u32::from_le_bytes(buf) as u64;

    if ps3_path {
        mogg.seek(SeekFrom::Start(20 + hmx_header_size * 8 + 16 + 16))?;
    } else {
        mogg.seek(SeekFrom::Start(20 + hmx_header_size * 8 + 16 + 32))?;
    }

    mogg.read_exact(&mut key_mask_as_read)?;

    debug!("key mask as read: {}", hex::encode(key_mask_as_read));

    let mut key_mask = [0u8; 16];

    if ps3_path {
        key_mask = key_mask_as_read
    } else {
        let aes_360 = Aes128::new(hv_key.into());
        match version {
            12..=17 => {
                aes_360.decrypt_block_b2b(
                    GenericArray::from_slice(&key_mask_as_read),
                    GenericArray::from_mut_slice(&mut key_mask),
                );
            }
            _ => unreachable!(),
        }
    }

    debug!("key mask: {}", hex::encode(key_mask));

    mogg.seek(SeekFrom::Start(20 + hmx_header_size * 8 + 16))?;
    let magic_a = read_u32_le(&mut mogg)?;

    mogg.seek(SeekFrom::Start(20 + hmx_header_size * 8 + 16 + 8))?;
    let magic_b = read_u32_le(&mut mogg)?;

    let mut use_new_hidden_keys = 0;

    mogg.seek(SeekFrom::Start(20 + hmx_header_size * 8 + 16 + 48))?;
    if version == 17 {
        use_new_hidden_keys = read_u64_le(&mut mogg)?;
        let v17_game = match use_new_hidden_keys {
            1 => "arby 4",
            4 => "mix drop",
            6 => "virtua just dance",
            8 => "audi car",
            10 => "blown fuse",
            _ => unimplemented!(),
        };
        debug!("use_new_hidden_keys: {use_new_hidden_keys} ({v17_game})");
    }

    let key_index_as_read = read_u64_le(&mut mogg)?;

    let key_index = if ps3_path {
        key_index_as_read % 6
    } else {
        key_index_as_read % 6 + 6
    };

    debug!("key index: {key_index}");

    let selected_key = match version {
        12..=16 => keys::HIDDEN_KEYS[key_index as usize],
        17 => match use_new_hidden_keys {
            1 => keys::HIDDEN_KEYS_17_1[key_index as usize],
            4 => keys::HIDDEN_KEYS_17_4[key_index as usize],
            6 => keys::HIDDEN_KEYS_17_6[key_index as usize],
            8 => keys::HIDDEN_KEYS_17_8[key_index as usize],
            10 => keys::HIDDEN_KEYS_17_10[key_index as usize],
            _ => unimplemented!(),
        },
        _ => unreachable!(),
    };

    debug!("selectedKey: {}", hex::encode(selected_key));

    let revealed_key = reveal_key(selected_key, masher);

    debug!("revealedKey: {}", hex::encode(revealed_key));

    let bytes_from_hex_string = hex_string_to_bytes(revealed_key);

    debug!("revealedKey char: {}", hex::encode(bytes_from_hex_string));

    let grind_array_result =
        grind_array(magic_a, magic_b, bytes_from_hex_string, version);

    debug!("grind_array_result: {}", hex::encode(grind_array_result));

    let mut key = [0u8; 16];
    for i in 0..16 {
        key[i] = grind_array_result[i] ^ key_mask[i];
    }

    debug!("key: {}", hex::encode(key));
    Ok(key)
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

fn ascii_digit_to_hex(h: u8) -> u8 {
    if !(0x61..=0x66).contains(&h) {
        if !(0x41..=0x46).contains(&h) {
            h.wrapping_sub(0x30)
        } else {
            h.wrapping_sub(0x37)
        }
    } else {
        h.wrapping_sub(87)
    }
}

fn hex_string_to_bytes(s: [u8; 32]) -> [u8; 16] {
    let mut arr = [0u8; 16];

    for i in 0..16 {
        let lo = ascii_digit_to_hex(s[i * 2 + 1]) as i32;
        let hi = ascii_digit_to_hex(s[i * 2]) as i32;
        arr[i] = (lo + hi * 16) as u8
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
    let ret = match op {
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
    };

    trace!("o_func: a1 {a1:2X}, a2: {a2:2X}, ret: {ret:2X}, op{op}");
    ret as u8
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
    debug!("magic_a: {magic_a:08x}");
    debug!("magic_b: {magic_b:08x}");

    let magic_hash_a = lcg(lcg(magic_a ^ 0x5c5c5c5c));
    let magic_hash_b = lcg(magic_b ^ 0x36363636);

    debug!("magic_hash_a: {magic_hash_a:08x}");
    debug!("magic_hash_b: {magic_hash_b:08x}");

    mogg_data[start..][..4].copy_from_slice(&[0x4f, 0x67, 0x67, 0x53]);

    let slice_a = &mut mogg_data[start + 12..][..4];
    let val_a = u32::from_be_bytes(slice_a.try_into().unwrap());
    slice_a.copy_from_slice(&u32::to_be_bytes(val_a ^ magic_hash_a));

    let slice_b = &mut mogg_data[start + 20..][..4];
    let val_b = u32::from_be_bytes(slice_b.try_into().unwrap());
    slice_b.copy_from_slice(&u32::to_be_bytes(val_b ^ magic_hash_b));
}
