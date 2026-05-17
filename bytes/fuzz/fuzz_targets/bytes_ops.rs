#![no_main]

use bytes::{Buf, BufMut, Bytes, BytesMut};
use libfuzzer_sys::{arbitrary, fuzz_target};

const MAX_INITIAL: usize = 4096;
const MAX_APPEND: usize = 256;
const MAX_ACTIVE: usize = 8192;
const MAX_FROZEN: usize = 16;
const MAX_OPS: usize = 128;

#[derive(arbitrary::Arbitrary, Debug)]
struct Case {
    initial: Vec<u8>,
    ops: Vec<Op>,
}

#[derive(arbitrary::Arbitrary, Debug)]
enum Op {
    PutSlice(Vec<u8>),
    PutU8(u8),
    SplitTo(u16),
    SplitOff(u16),
    Freeze,
    CloneFrozen(u8),
    SliceFrozen(u8, u16, u16),
    AdvanceFrozen(u8, u16),
    CopyToBytes(u8, u16),
    Read,
}

fuzz_target!(|case: Case| {
    run_case(case);
});

fn run_case(case: Case) {
    let initial_len = case.initial.len().min(MAX_INITIAL);
    let mut active = BytesMut::from(&case.initial[..initial_len]);
    let mut frozen = Vec::new();
    let mut checksum = 0_u64;

    observe(active.as_ref(), &mut checksum);

    for op in case.ops.into_iter().take(MAX_OPS) {
        match op {
            Op::PutSlice(bytes) => {
                if active.len() < MAX_ACTIVE {
                    let available = MAX_ACTIVE - active.len();
                    let len = bytes.len().min(MAX_APPEND).min(available);
                    active.put_slice(&bytes[..len]);
                    observe(&active[..], &mut checksum);
                }
            }
            Op::PutU8(byte) => {
                if active.len() < MAX_ACTIVE {
                    active.put_u8(byte);
                    checksum = checksum.wrapping_add(u64::from(byte));
                }
            }
            Op::SplitTo(raw_at) => {
                if !active.is_empty() {
                    let at = bounded_index(raw_at, active.len());
                    let part = active.split_to(at);
                    push_frozen(part.freeze(), &mut frozen, &mut checksum);
                }
            }
            Op::SplitOff(raw_at) => {
                if !active.is_empty() {
                    let at = bounded_index(raw_at, active.len());
                    let part = active.split_off(at);
                    push_frozen(part.freeze(), &mut frozen, &mut checksum);
                }
            }
            Op::Freeze => {
                if !active.is_empty() {
                    let part = active.split();
                    push_frozen(part.freeze(), &mut frozen, &mut checksum);
                }
            }
            Op::CloneFrozen(raw_slot) => {
                if let Some(slot) = frozen_slot(raw_slot, frozen.len()) {
                    let cloned = frozen[slot].clone();
                    push_frozen(cloned, &mut frozen, &mut checksum);
                }
            }
            Op::SliceFrozen(raw_slot, raw_start, raw_len) => {
                if let Some(slot) = frozen_slot(raw_slot, frozen.len()) {
                    let bytes = &frozen[slot];
                    if !bytes.is_empty() {
                        let start = bounded_index(raw_start, bytes.len());
                        let len = usize::from(raw_len) % (bytes.len() - start + 1);
                        let sliced = bytes.slice(start..start + len);
                        push_frozen(sliced, &mut frozen, &mut checksum);
                    }
                }
            }
            Op::AdvanceFrozen(raw_slot, raw_count) => {
                if let Some(slot) = frozen_slot(raw_slot, frozen.len()) {
                    let remaining = frozen[slot].remaining();
                    if remaining > 0 {
                        let count = usize::from(raw_count) % (remaining + 1);
                        frozen[slot].advance(count);
                        observe(frozen[slot].as_ref(), &mut checksum);
                    }
                }
            }
            Op::CopyToBytes(raw_slot, raw_count) => {
                if let Some(slot) = frozen_slot(raw_slot, frozen.len()) {
                    let mut reader = frozen[slot].clone();
                    let remaining = reader.remaining();
                    if remaining > 0 {
                        let count = usize::from(raw_count) % (remaining + 1);
                        let copied = reader.copy_to_bytes(count);
                        push_frozen(copied, &mut frozen, &mut checksum);
                    }
                }
            }
            Op::Read => {
                observe(&active[..], &mut checksum);
                for bytes in &frozen {
                    observe(bytes.as_ref(), &mut checksum);
                }
            }
        }
    }

    std::hint::black_box(checksum);
}

fn bounded_index(raw: u16, len: usize) -> usize {
    usize::from(raw) % (len + 1)
}

fn frozen_slot(raw: u8, len: usize) -> Option<usize> {
    if len == 0 {
        None
    } else {
        Some(usize::from(raw) % len)
    }
}

fn push_frozen(bytes: Bytes, frozen: &mut Vec<Bytes>, checksum: &mut u64) {
    observe(bytes.as_ref(), checksum);
    if frozen.len() == MAX_FROZEN {
        let dropped = frozen.remove(0);
        observe(dropped.as_ref(), checksum);
    }
    frozen.push(bytes);
}

fn observe(bytes: &[u8], checksum: &mut u64) {
    *checksum = checksum.wrapping_add(bytes.len() as u64);
    if let Some((&first, rest)) = bytes.split_first() {
        *checksum = checksum.rotate_left(5) ^ u64::from(first);
        if let Some(&last) = rest.last() {
            *checksum = checksum.rotate_left(7) ^ u64::from(last);
        }
    }
}
