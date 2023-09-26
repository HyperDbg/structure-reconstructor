use std::env;
use std::num::ParseIntError;
use zydis::*;

#[rustfmt::skip]
static CODE: &'static [u8] = &[
    0x51, 0x8D, 0x45, 0xFF, 0x50, 0xFF, 0x75, 0x0C, 0xFF, 0x75, 0x08,
    0xFF, 0x15, 0xA0, 0xA5, 0x48, 0x76, 0x85, 0xC0, 0x0F, 0x88, 0xFC,
    0xDA, 0x02, 0x00,
];

fn zydis_len_disasm(code: &[u8]) -> zydis::Result<u8> {
    let fmt = Formatter::intel();
    let dec = Decoder::new64();

    // 0 is the address for our code.
    for insn_info in dec.decode_all::<VisibleOperands>(code, 0) {
        let (ip, _raw_bytes, insn) = insn_info?;
        let len = insn.length;
        return Ok(len);
    }
    Ok(0)
}

fn zydis_disasm() -> zydis::Result<()> {
    let fmt = Formatter::intel();
    let dec = Decoder::new64();

    // 0 is the address for our code.
    for insn_info in dec.decode_all::<VisibleOperands>(CODE, 0) {
        let (ip, _raw_bytes, insn) = insn_info?;

        println!(
            "Sina address {}",
            zydis_len_disasm(_raw_bytes).expect("err, unable to decode the buffer")
        );

        // We use Some(ip) here since we want absolute addressing based on the given
        // instruction pointer. If we wanted relative addressing, we'd use `None` instead.
        println!("0x{:016X} {}", ip, fmt.format(Some(ip), &insn)?);
    }

    Ok(())
}

fn parse_hex_to_u32(hex_str: &str) -> std::result::Result<u32, ParseIntError> {
    u32::from_str_radix(hex_str.trim_start_matches("0x"), 16)
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() != 7 {
        eprintln!(
            "Usage: {} --start <start_address_hex> --end <end_address_hex> --size <size_hex>",
            args[0]
        );
        std::process::exit(1);
    }

    let mut start_address = String::new();
    let mut end_address = String::new();
    let mut size_hex = String::new();

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--start" => {
                start_address = args[i + 1].clone();
                i += 2;
            }
            "--end" => {
                end_address = args[i + 1].clone();
                i += 2;
            }
            "--size" => {
                size_hex = args[i + 1].clone();
                i += 2;
            }
            _ => {
                eprintln!("Invalid argument: {}", args[i]);
                std::process::exit(1);
            }
        }
    }

    zydis_disasm().expect("err, unable to decode instructions");

    match parse_hex_to_u32(&size_hex) {
        Ok(size) => {
            let formatted_string = format!("{} {} {}\n", start_address, end_address, size);
            print!("{}", formatted_string);
        }
        Err(e) => {
            eprintln!("Error parsing --size argument: {}", e);
            std::process::exit(1);
        }
    }
}
