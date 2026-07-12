use std::cmp::{max, min};

use blake2::{
    Blake2bVar,
    digest::{Update, VariableOutput},
};

const GOLDEN_GAMMA: u64 = 0x9e37_79b9_7f4a_7c15;
const DOMAIN_MUL: u64 = 0xd6e8_feb8_6659_fd93;
const NAMESPACE_ADD: u64 = 0xa076_1d64_78bd_642f;
const COEF_A: u64 = 0xe703_7ed1_a0b4_28db;
const ADD_A: u64 = 0x8f39_07f7_b2b8_0c35;
const COEF_B: u64 = 0x5899_65cc_7537_4cc3;
const ADD_B: u64 = 0x33a2_13ec_50ff_e2e9;
const MAX_EXTRA_PADDING: usize = 0x02da;

const HANDSHAKE_DOMAIN: u32 = 0x7053;
const MIX_HANDSHAKE_DOMAIN: u32 = 0x51a7;
const CHUNK_INITIAL_DOMAIN: u32 = 0xf17c;

const NS_PROFILE: u64 = 0xb46c_2e7d_9a15_38f1;
const NS_PREFIX: u64 = 0x5d92_17c0_83e6_4ab9;
const NS_MOTIF: u64 = 0xa71f_0c54_d839_6e2b;
const NS_SALT: u64 = 0x3e8a_91b5_2740_f6cd;
const NS_MIX: u64 = 0xc9f4_260b_7d1e_835a;
const NS_CHUNK: u64 = 0x62d0_b5e1_9c4a_783f;
const NS_WRITE: u64 = 0x917b_3c48_e6a2_05d4;

const LABEL_PADDING: u32 = 0;
const LABEL_BIT_PERCENT: u32 = 1;
const LABEL_MOTIF: u32 = 2;
const LABEL_MIX_OFFSET: u32 = 3;
const LABEL_SALT: u32 = 3;
const LABEL_PROFILE_ID: u32 = 5;
const LABEL_GENERATOR: u32 = 6;
const LABEL_PAD_MIN: u32 = 7;
const LABEL_PAD_MAX: u32 = 8;
const LABEL_PAD_COUNT: u32 = 9;
const LABEL_PAD_INTERVAL: u32 = 10;
const LABEL_SMALL_LIMIT: u32 = 11;
const LABEL_BIT_MIN: u32 = 12;
const LABEL_BIT_MAX: u32 = 13;
const LABEL_PREFIX_MIN: u32 = 14;
const LABEL_PREFIX_MAX: u32 = 15;
const LABEL_MIX_MODE: u32 = 16;
const LABEL_MIX_ROUNDS: u32 = 17;
const LABEL_MIX_STRIDE: u32 = 18;
const LABEL_MIX_OFFSET_BASE: u32 = 19;
const LABEL_MIX_BLOCK: u32 = 20;
const LABEL_CHUNK_POLICY: u32 = 21;
const LABEL_CHUNK_INITIAL: u32 = 22;
const LABEL_CHUNK_FIRST_CAP: u32 = 22;
const LABEL_CHUNK_MAX: u32 = 23;
const LABEL_CHUNK_STEP: u32 = 24;
const LABEL_CHUNK_JITTER: u32 = 25;
const LABEL_CHUNK_BUCKET: u32 = 26;
const LABEL_IDLE_RESET: u32 = 27;
const LABEL_WRITE_POLICY: u32 = 28;
const LABEL_WRITE_FIRST: u32 = 29;
const LABEL_WRITE_BUCKET: u32 = 30;
const LABEL_WRITE_SEQ: u32 = 31;
const LABEL_WRITE_JITTER: u32 = 32;
const LABEL_RECORD_PREFIX: u32 = 33;
const LABEL_PAYLOAD_PAD: u32 = 34;
const LABEL_WRITE_TARGET: u32 = 35;
const LABEL_WRITE_JITTER_VALUE: u32 = 36;
const LABEL_WRITE_NEXT: u32 = 37;
const LABEL_CHUNK_SIZE: u32 = 38;
const LABEL_CHUNK_JITTER_VALUE: u32 = 39;

const PROFILE_SEED: [u8; 24] = [
    0x8d, 0x41, 0xa7, 0x13, 0x5c, 0xe2, 0x09, 0xbb, 0x70, 0x2f, 0xd6, 0x94, 0x33,
    0x18, 0xc0, 0x6e, 0x4a, 0x91, 0x25, 0xfd, 0xb8, 0x03, 0x77, 0xac,
];

const BIT_ROTATE_TABLE: [u8; 128] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x01, 0x02,
    0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x03, 0x05, 0x09, 0x11, 0x21, 0x41, 0x81,
    0x06, 0x0a, 0x12, 0x22, 0x42, 0x82, 0x0c, 0x18, 0x24, 0x07, 0x0b, 0x13, 0x23,
    0x43, 0x83, 0x0d, 0x19, 0x31, 0x61, 0xc1, 0x0e, 0x1c, 0x38, 0x70, 0xe0, 0x0f,
    0x17, 0x27, 0x47, 0x87, 0x1b, 0x33, 0x63, 0xc3, 0x1d, 0x39, 0x71, 0xe1, 0x3c,
    0x78, 0xf0, 0xf8, 0xf4, 0xec, 0xdc, 0xbc, 0x7c, 0xf2, 0xe6, 0xce, 0x9e, 0x3e,
    0xf1, 0xe3, 0xc7, 0x8f, 0x1f, 0xfc, 0xfa, 0xf6, 0xee, 0xde, 0xbe, 0x7e, 0xf9,
    0xf5, 0xed, 0xdd, 0xbd, 0x7d, 0xf3, 0xe7, 0xdb, 0xfe, 0xfd, 0xfb, 0xf7, 0xef,
    0xdf, 0xbf, 0x7f, 0xfe, 0xfd, 0xfb, 0xf7, 0xef, 0xdf, 0xbf, 0x7f,
];

#[derive(Clone, Copy)]
struct Namespaces {
    profile: u64,
    prefix: u64,
    motif: u64,
    salt: u64,
    mix: u64,
    chunk: u64,
    write: u64,
}

impl Namespaces {
    fn new(secret: &[u8; 32]) -> Self {
        Self {
            profile: derive_namespace(secret, LABEL_PROFILE_ID, NS_PROFILE),
            prefix: derive_namespace(secret, LABEL_PADDING, NS_PREFIX),
            motif: derive_namespace(secret, LABEL_MOTIF, NS_MOTIF),
            salt: derive_namespace(secret, LABEL_SALT, NS_SALT),
            mix: derive_namespace(secret, LABEL_MIX_MODE, NS_MIX),
            chunk: derive_namespace(secret, LABEL_CHUNK_POLICY, NS_CHUNK),
            write: derive_namespace(secret, LABEL_WRITE_POLICY, NS_WRITE),
        }
    }

    fn namespace(self, label: u32) -> u64 {
        match label {
            LABEL_PADDING | LABEL_BIT_PERCENT | LABEL_PREFIX_MIN
            | LABEL_PREFIX_MAX | LABEL_RECORD_PREFIX | LABEL_PAYLOAD_PAD => {
                self.prefix
            }
            LABEL_MOTIF => self.motif,
            LABEL_MIX_OFFSET
            | LABEL_MIX_MODE
            | LABEL_MIX_ROUNDS
            | LABEL_MIX_STRIDE
            | LABEL_MIX_OFFSET_BASE
            | LABEL_MIX_BLOCK => self.mix,
            LABEL_CHUNK_POLICY
            | LABEL_CHUNK_INITIAL
            | LABEL_CHUNK_MAX
            | LABEL_CHUNK_STEP
            | LABEL_CHUNK_JITTER
            | LABEL_CHUNK_BUCKET
            | LABEL_CHUNK_SIZE
            | LABEL_CHUNK_JITTER_VALUE => self.chunk,
            LABEL_WRITE_POLICY
            | LABEL_WRITE_FIRST
            | LABEL_WRITE_BUCKET
            | LABEL_WRITE_SEQ
            | LABEL_WRITE_JITTER
            | LABEL_WRITE_TARGET
            | LABEL_WRITE_JITTER_VALUE
            | LABEL_WRITE_NEXT => self.write,
            _ => self.profile,
        }
    }

    fn prf(self, label: u32, a: u32, b: u32) -> u32 {
        prf32(self.namespace(label), label, a as u64, b as u64)
    }

    fn static_prf(self, label: u32, domain: u32) -> u32 {
        prf32(self.namespace(label), label, 0, domain as u64)
    }

    fn fill(self, label: u32, sequence: u32, output: &mut [u8]) {
        let mut seed = self.namespace(label)
            ^ (sequence as u64)
                .wrapping_mul(DOMAIN_MUL)
                .wrapping_add(0xb57d_e1f3_f82c_b33f)
            ^ (label as u64).wrapping_mul(0xa24b_aed4_963e_e407)
            ^ (output.len() as u64)
                .wrapping_mul(0x1656_67b1_9e37_79f9)
                .wrapping_add(0x0d4c_d3e7_b14a_36d7);
        let mut offset = 0;
        while offset < output.len() {
            seed = seed.wrapping_add(GOLDEN_GAMMA);
            let block = splitmix64(seed).to_le_bytes();
            let count = min(block.len(), output.len() - offset);
            output[offset..offset + count].copy_from_slice(&block[..count]);
            offset += count;
        }
    }
}

#[derive(Clone)]
pub struct Profile {
    namespaces: Namespaces,
    generator: u32,
    pad_min: usize,
    pad_max: usize,
    pad_count: u32,
    pad_interval: u32,
    small_limit: usize,
    bit_min: u32,
    bit_max: u32,
    prefix_min: usize,
    prefix_max: usize,
    mix_mode: u32,
    mix_rounds: u32,
    mix_stride: usize,
    mix_offset: usize,
    mix_block: usize,
    chunk_policy: u32,
    pub chunk_initial: usize,
    pub first_record_cap: usize,
    pub chunk_max: usize,
    chunk_step: usize,
    chunk_jitter: usize,
    pub idle_reset_secs: i64,
    write_policy: u32,
    write_first: u32,
    chunk_buckets: [usize; 8],
    write_buckets: [usize; 8],
    write_sequence: [usize; 8],
    write_jitter: usize,
    write_jitter_percent: usize,
    generator_weights: [usize; 6],
    pub salt_block_len: usize,
    handshake_mix_stride: usize,
    handshake_mix_rounds: u32,
}

impl Profile {
    pub fn new(psk: &[u8]) -> Self {
        let mut input = Vec::with_capacity(PROFILE_SEED.len() + psk.len());
        input.extend_from_slice(&PROFILE_SEED);
        input.extend_from_slice(psk);
        let mut secret = [0u8; 32];
        let mut digest = Blake2bVar::new(32).expect("valid digest size");
        digest.update(&input);
        digest
            .finalize_variable(&mut secret)
            .expect("valid digest output");
        let namespaces = Namespaces::new(&secret);

        let pad_min = pick(namespaces.static_prf(LABEL_PAD_MIN, 0), 0x18, 0xa0);
        let pad_max = min(
            pad_min + pick(namespaces.static_prf(LABEL_PAD_MAX, 0), 0xa0, 0x3c0),
            MAX_EXTRA_PADDING,
        );
        let hs_min = pick(
            namespaces.static_prf(LABEL_PREFIX_MIN, HANDSHAKE_DOMAIN),
            0x10,
            0x60,
        );
        let hs_max = min(
            hs_min
                + pick(
                    namespaces.static_prf(LABEL_PREFIX_MAX, HANDSHAKE_DOMAIN),
                    0x10,
                    0xa0,
                ),
            0x80,
        );
        let salt_block_len = 16
            + pick(
                namespaces.static_prf(LABEL_RECORD_PREFIX, HANDSHAKE_DOMAIN),
                min(hs_min, hs_max),
                hs_max,
            );
        let prefix_min =
            pick(namespaces.static_prf(LABEL_PREFIX_MIN, 0), 0x08, 0x50);
        let prefix_max = min(
            prefix_min
                + pick(namespaces.static_prf(LABEL_PREFIX_MAX, 0), 0x10, 0xa0),
            0x80,
        );
        let chunk_initial =
            pick(namespaces.static_prf(LABEL_CHUNK_INITIAL, 0), 0x200, 0x05b4)
                .clamp(0x60, 0x05b4);
        let first_record_cap = max(
            0x100,
            min(
                pick(
                    namespaces
                        .static_prf(LABEL_CHUNK_FIRST_CAP, CHUNK_INITIAL_DOMAIN),
                    0x100,
                    0x300,
                ),
                min(chunk_initial, 0x300),
            ),
        );
        let chunk_max = max(
            pick(namespaces.static_prf(LABEL_CHUNK_MAX, 0), 0x2000, 0x3fff),
            chunk_initial,
        );

        let mut profile = Self {
            namespaces,
            generator: namespaces.static_prf(LABEL_GENERATOR, 0) & 3,
            pad_min,
            pad_max,
            pad_count: pick_u32(namespaces.static_prf(LABEL_PAD_COUNT, 0), 2, 8),
            pad_interval: pick_u32(
                namespaces.static_prf(LABEL_PAD_INTERVAL, 0),
                2,
                0x0b,
            ),
            small_limit: pick(
                namespaces.static_prf(LABEL_SMALL_LIMIT, 0),
                0x60,
                0x300,
            ),
            bit_min: pick_u32(namespaces.static_prf(LABEL_BIT_MIN, 0), 0x18, 0x29),
            bit_max: pick_u32(namespaces.static_prf(LABEL_BIT_MAX, 0), 0x3a, 0x4c),
            prefix_min: min(prefix_min, prefix_max),
            prefix_max,
            mix_mode: namespaces.static_prf(LABEL_MIX_MODE, 0) % 3,
            mix_rounds: pick_u32(namespaces.static_prf(LABEL_MIX_ROUNDS, 0), 1, 3),
            mix_stride: pick(namespaces.static_prf(LABEL_MIX_STRIDE, 0), 2, 13),
            mix_offset: pick(namespaces.static_prf(LABEL_MIX_OFFSET_BASE, 0), 0, 15),
            mix_block: pick(namespaces.static_prf(LABEL_MIX_BLOCK, 0), 8, 0x40),
            chunk_policy: namespaces.static_prf(LABEL_CHUNK_POLICY, 0) % 3,
            chunk_initial,
            first_record_cap,
            chunk_max,
            chunk_step: min(
                pick(namespaces.static_prf(LABEL_CHUNK_STEP, 0), 0x400, 0x1000),
                0x0b68,
            ),
            chunk_jitter: min(
                pick(namespaces.static_prf(LABEL_CHUNK_JITTER, 0), 0x10, 0xc0),
                0x0b6,
            ),
            idle_reset_secs: pick(
                namespaces.static_prf(LABEL_IDLE_RESET, 0),
                0x0c,
                0x5a,
            ) as i64,
            write_policy: namespaces.static_prf(LABEL_WRITE_POLICY, 0) % 3,
            write_first: pick_u32(namespaces.static_prf(LABEL_WRITE_FIRST, 0), 4, 8),
            chunk_buckets: [0; 8],
            write_buckets: [0; 8],
            write_sequence: [0; 8],
            write_jitter: pick(
                namespaces.static_prf(LABEL_WRITE_JITTER, 0),
                0x08,
                0x60,
            ),
            write_jitter_percent: pick(
                namespaces.static_prf(LABEL_WRITE_POLICY, 0x504c),
                8,
                0x30,
            ),
            generator_weights: [
                pick(namespaces.static_prf(LABEL_GENERATOR, 1), 0x18, 0x80),
                pick(namespaces.static_prf(LABEL_GENERATOR, 2), 0x10, 0x60),
                pick(namespaces.static_prf(LABEL_GENERATOR, 3), 0x10, 0x60),
                pick(namespaces.static_prf(LABEL_GENERATOR, 4), 0, 9),
                pick(namespaces.static_prf(LABEL_GENERATOR, 5), 1, 8),
                pick(namespaces.static_prf(LABEL_GENERATOR, 6), 7, 0x17),
            ],
            salt_block_len,
            handshake_mix_stride: pick(
                namespaces.static_prf(LABEL_MIX_STRIDE, MIX_HANDSHAKE_DOMAIN),
                0x11,
                0xfb,
            ),
            handshake_mix_rounds: pick_u32(
                namespaces.static_prf(LABEL_MIX_ROUNDS, MIX_HANDSHAKE_DOMAIN),
                1,
                4,
            ),
        };
        for index in 0..8 {
            profile.chunk_buckets[index] = pick(
                namespaces.static_prf(LABEL_CHUNK_BUCKET, index as u32),
                0x1000,
                chunk_max,
            );
            profile.write_buckets[index] = pick(
                namespaces.static_prf(LABEL_WRITE_BUCKET, index as u32),
                0x140,
                0x05b4,
            );
            profile.write_sequence[index] = pick(
                namespaces.static_prf(LABEL_WRITE_SEQ, index as u32),
                0x168,
                0x05b4,
            );
        }
        profile
    }

    pub fn prefix_len(&self, sequence: u32) -> usize {
        pick(
            self.namespaces.prf(LABEL_RECORD_PREFIX, sequence, 0),
            self.prefix_min,
            self.prefix_max,
        )
    }

    pub fn payload_limit(&self, sequence: u32, mut chunk_size: usize) -> usize {
        if chunk_size == 0 {
            chunk_size = self.chunk_initial;
        }
        match self.chunk_policy {
            1 => {
                let index = self.namespaces.prf(
                    LABEL_CHUNK_SIZE,
                    sequence,
                    chunk_size as u32,
                ) as usize
                    % self.chunk_buckets.len();
                chunk_size = self.chunk_buckets[index];
            }
            2 => {
                let raw = self.namespaces.prf(
                    LABEL_CHUNK_JITTER_VALUE,
                    sequence,
                    chunk_size as u32,
                ) as usize;
                chunk_size = chunk_size
                    .saturating_add(raw % (self.chunk_jitter * 2 + 1))
                    .saturating_sub(self.chunk_jitter);
            }
            _ => {}
        }
        max(0x40, min(chunk_size, self.chunk_max))
    }

    pub fn next_chunk_size(&self, chunk_size: usize) -> usize {
        if chunk_size == 0 {
            self.chunk_initial
        } else {
            min(chunk_size + self.chunk_step, self.chunk_max)
        }
    }

    pub fn padding_len(
        &self,
        sequence: u32,
        payload_len: usize,
        prefix_len: usize,
        salt_prefix_len: usize,
        salt_block_len: usize,
    ) -> usize {
        let mut padding = 0;
        if sequence < self.pad_count
            || (payload_len > 0 && payload_len <= self.small_limit)
            || (self.pad_interval > 0 && sequence.is_multiple_of(self.pad_interval))
        {
            padding = pick(
                self.namespaces
                    .prf(LABEL_PAYLOAD_PAD, sequence, payload_len as u32),
                self.pad_min,
                self.pad_max,
            );
        }
        let frame_len = salt_block_len
            + prefix_len
            + 23
            + padding
            + payload_len
            + usize::from(payload_len > 0) * 16;
        let target = self.write_target(sequence, frame_len);
        if target > frame_len {
            padding += min(target - frame_len, MAX_EXTRA_PADDING);
        }
        if salt_block_len > 0 {
            let overhead = salt_prefix_len + prefix_len + padding;
            let input = payload_len + if payload_len == 0 { 0x27 } else { 0x37 };
            let threshold = max((input * 25).div_ceil(75), 0xc0);
            if overhead < threshold {
                padding = min(
                    threshold.saturating_sub(salt_prefix_len + prefix_len),
                    self.pad_max + MAX_EXTRA_PADDING,
                );
            }
        }
        min(padding, u16::MAX as usize)
    }

    fn write_target(&self, sequence: u32, frame_len: usize) -> usize {
        if frame_len > 0x05b3 {
            return min(frame_len, u16::MAX as usize);
        }
        let mut target = if sequence < self.write_first {
            self.write_sequence[sequence as usize]
        } else {
            let index =
                self.namespaces
                    .prf(LABEL_WRITE_TARGET, sequence, frame_len as u32)
                    as usize
                    % self.write_buckets.len();
            self.write_buckets[index]
        };
        if self.write_policy == 2 {
            let raw =
                self.namespaces.prf(LABEL_WRITE_JITTER_VALUE, sequence, 0) as usize;
            target = target
                .saturating_add(raw % (self.write_jitter * 2 + 1))
                .saturating_sub(self.write_jitter);
            target = max(target, 1);
        }
        let spread = min(
            MAX_EXTRA_PADDING,
            frame_len * self.write_jitter_percent / 100,
        );
        if self
            .namespaces
            .prf(LABEL_WRITE_TARGET, sequence, spread as u32)
            & 1
            == 0
        {
            target = min(target + spread, u16::MAX as usize);
        } else {
            target = target.saturating_sub(spread >> 1);
        }
        while frame_len > target {
            let index =
                self.namespaces
                    .prf(LABEL_WRITE_NEXT, sequence, target as u32)
                    as usize
                    % self.write_buckets.len();
            let next = self.write_buckets[index];
            target = if next <= target {
                min(target + self.pad_max, u16::MAX as usize)
            } else {
                next
            };
            if target == u16::MAX as usize {
                break;
            }
        }
        target
    }

    pub fn fill_padding(&self, sequence: u32, output: &mut [u8]) {
        self.namespaces.fill(LABEL_PADDING, sequence, output);
        let [g1, g2, g3, g4, g5, g6] = self.generator_weights;
        match self.generator {
            0 => {
                let bits = pick_u32(
                    self.namespaces.prf(LABEL_BIT_PERCENT, sequence, 0),
                    self.bit_min,
                    self.bit_max,
                ) as usize;
                let scaled = bits * 8;
                let rotation = if scaled <= 0x31 {
                    1
                } else if scaled <= 0x02ed {
                    (scaled + 0x32) / 100
                } else {
                    7
                };
                for (index, value) in output.iter_mut().enumerate() {
                    let original = *value;
                    let raw = original.wrapping_add(index as u8);
                    let table = BIT_ROTATE_TABLE
                        [max(rotation, 1) * 16 + ((raw ^ original) & 0x0f) as usize];
                    *value = table.rotate_left(((raw ^ (original >> 4)) & 7) as u32);
                }
            }
            1 => {
                for (index, value) in output.iter_mut().enumerate() {
                    let original = *value;
                    let bucket = original as usize % (g1 + g2 + g3);
                    *value = if bucket < g1 {
                        pick(original.wrapping_add(index as u8) as u32, 0x20, 0x7e)
                            as u8
                    } else if bucket < g1 + g2 {
                        pick((original ^ index as u8) as u32, 0x80, 0xbf) as u8
                    } else {
                        pick(
                            original.wrapping_add((index * 7) as u8) as u32,
                            0xc0,
                            0xff,
                        ) as u8
                    };
                }
            }
            2 => {
                for (index, value) in output.iter_mut().enumerate() {
                    let low = ((*value & 0x0f) as usize + g4 + (index & 1)) % 10;
                    let high = (*value as usize + ((index & 3) << 4) + 0x30) & 0xf0;
                    *value = (high | low) as u8;
                }
            }
            3 => {
                let mut motif = [0u8; 32];
                self.namespaces.fill(LABEL_MOTIF, sequence, &mut motif);
                let motif_len = max(g5 * 4, 4);
                let period = max(g6, 5);
                for (index, value) in output.iter_mut().enumerate() {
                    let block_offset = index % period;
                    if block_offset < period - 3 {
                        *value = ((g5 + 3) * index) as u8 ^ motif[index % motif_len];
                    } else if block_offset < period - 1 {
                        *value = 0x30 | (*value % 10);
                    }
                }
            }
            _ => unreachable!(),
        }
    }

    pub fn mix_payload(&self, sequence: u32, padding: &mut [u8], body: &mut [u8]) {
        let count = min(padding.len(), body.len());
        for round in 0..self.mix_rounds {
            match self.mix_mode {
                0 => {
                    let stride = max(self.mix_stride + (round as usize % 3), 1);
                    for index in (self.mix_offset % stride..count).step_by(stride) {
                        std::mem::swap(&mut padding[index], &mut body[index]);
                    }
                }
                1 => {
                    let start = (round as usize & 1) * self.mix_block;
                    for offset in (start..count).step_by(self.mix_block * 2) {
                        if offset + self.mix_block > count {
                            break;
                        }
                        for index in offset..offset + self.mix_block {
                            std::mem::swap(&mut padding[index], &mut body[index]);
                        }
                    }
                }
                2 => {
                    let stride = max(self.mix_stride + (round as usize % 3), 1);
                    let offset =
                        (self.namespaces.prf(LABEL_MIX_OFFSET, sequence, round)
                            as usize
                            + self.mix_offset)
                            % stride;
                    for index in (offset..count).step_by(stride) {
                        std::mem::swap(&mut padding[index], &mut body[index]);
                    }
                }
                _ => unreachable!(),
            }
        }
    }

    pub fn extract_salt(&self, block: &[u8]) -> [u8; 16] {
        let permutation =
            shuffle(self.namespaces.salt, self.handshake_mix_rounds, block.len());
        let mut salt = [0u8; 16];
        for index in 0..salt.len() {
            salt[index] = salt_mask(
                self.namespaces.salt,
                self.handshake_mix_stride,
                index as u32,
            ) ^ block[permutation[index]];
        }
        salt
    }

    pub fn write_salt(&self, salt: &[u8; 16], block: &mut [u8]) {
        let permutation =
            shuffle(self.namespaces.salt, self.handshake_mix_rounds, block.len());
        for index in 0..salt.len() {
            block[permutation[index]] = salt_mask(
                self.namespaces.salt,
                self.handshake_mix_stride,
                index as u32,
            ) ^ salt[index];
        }
    }
}

fn derive_namespace(secret: &[u8; 32], label: u32, seed: u64) -> u64 {
    let word =
        |offset| u64::from_le_bytes(secret[offset..offset + 8].try_into().unwrap());
    splitmix64(
        (label as u64).wrapping_mul(DOMAIN_MUL)
            ^ seed.wrapping_add(NAMESPACE_ADD)
            ^ word(0)
            ^ word(8).wrapping_add(GOLDEN_GAMMA)
            ^ word(16).rotate_left(17)
            ^ word(24).rotate_right(11),
    )
}

fn splitmix64(mut value: u64) -> u64 {
    value ^= value >> 30;
    value = value.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value ^= value >> 27;
    value = value.wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

fn prf32(namespace: u64, label: u32, a: u64, b: u64) -> u32 {
    let value = namespace
        ^ b.wrapping_mul(COEF_B).wrapping_add(ADD_B)
        ^ (label as u64).wrapping_mul(GOLDEN_GAMMA)
        ^ a.wrapping_mul(COEF_A).wrapping_add(ADD_A);
    let mixed = splitmix64(value);
    (mixed ^ (mixed >> 32)) as u32
}

fn pick(raw: u32, low: usize, high: usize) -> usize {
    low + raw as usize % (high - low + 1)
}

fn pick_u32(raw: u32, low: u32, high: u32) -> u32 {
    low + raw % (high - low + 1)
}

fn shuffle(namespace: u64, rounds: u32, length: usize) -> Vec<usize> {
    let mut output = (0..length).collect::<Vec<_>>();
    for round in 0..max(rounds, 1) {
        for index in 0..length {
            let left = (index as u64).wrapping_mul(COEF_B).wrapping_add(ADD_B);
            let middle = namespace ^ 0xdaa6_6d2c_7ddf_743f;
            let right = ((MIX_HANDSHAKE_DOMAIN + round) as u64)
                .wrapping_mul(COEF_A)
                .wrapping_add(ADD_A);
            let mixed = splitmix64(left ^ middle ^ right);
            let raw = (mixed ^ (mixed >> 32)) as u32 as usize;
            let target = index + raw % (length - index);
            output.swap(index, target);
        }
    }
    output
}

fn salt_mask(namespace: u64, stride: usize, index: u32) -> u8 {
    (index as u8).wrapping_mul(stride as u8)
        ^ prf32(
            namespace,
            LABEL_MOTIF,
            MIX_HANDSHAKE_DOMAIN as u64,
            index as u64,
        ) as u8
}

#[cfg(test)]
mod tests {
    use super::Profile;

    #[test]
    fn derives_reference_profile() {
        let profile = Profile::new(b"!dubuxOpopop880@@");
        assert_eq!(profile.generator, 2);
        assert_eq!((profile.pad_min, profile.pad_max), (69, 730));
        assert_eq!((profile.pad_count, profile.pad_interval), (4, 4));
        assert_eq!((profile.prefix_min, profile.prefix_max), (61, 86));
        assert_eq!((profile.mix_mode, profile.mix_rounds), (1, 1));
        assert_eq!((profile.chunk_initial, profile.chunk_max), (1026, 11630));
        assert_eq!(profile.first_record_cap, 531);
        assert_eq!(profile.salt_block_len, 106);
        assert_eq!(profile.handshake_mix_stride, 174);
        assert_eq!(profile.handshake_mix_rounds, 4);
        assert_eq!(
            profile.chunk_buckets,
            [6386, 7265, 4501, 8084, 9937, 10197, 4179, 6716]
        );
    }

    #[test]
    fn extracts_reference_salt_block() {
        let profile = Profile::new(b"!dubuxOpopop880@@");
        let encoded = "a751d0230a44511324c6c764f8a380b7f718d890c878094b2739c9928993a98380aba7f0379363d2c9c2025428583872f47928b1a369b2b5ace8eb0105b149897798b969042892d5c2909846ded0d4f2725134703083f70288b1bc4717f3418882d0118aa5b357561962";
        let block = (0..encoded.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&encoded[index..index + 2], 16).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(profile.extract_salt(&block), [0u8; 16]);
    }
}
