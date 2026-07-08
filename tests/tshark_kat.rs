//! Spec known-answer validation against the Wireshark (tshark) ITU-T Q.763 ISUP
//! dissector, the independent oracle for this codec.
//!
//! For each message the codec builds it, wraps it as the SIF of an MTP3 MSU with
//! Service Indicator 5 (ISUP) via `Message::to_msu(...).encode(Variant::Itu)`,
//! writes the bytes into a LINKTYPE_MTP3 (141) pcap with `text2pcap -l 141`, and
//! dissects with `tshark -V`. It then asserts tshark reports the right ISUP
//! message type and the decoded parameter fields, and that the dissection is free
//! of `Malformed` / expert `Error`. This checks the wire layout against a
//! third-party dissector, not a round-trip.
//!
//! The test **skips** (passes) when `text2pcap` / `tshark` are not on PATH, so it
//! runs the real validation wherever the tools exist and stays green elsewhere.

use std::io::Write;
use std::path::PathBuf;
use std::process::Command;

use itu_isup::{
    calling_party_category, event_information, transmission_medium_requirement, CauseIndicators,
    Message, Number, Parameter, RangeAndStatus,
};
use mtp3::{NetworkIndicator, PointCode, Variant};

/// Locate a tool on PATH (or at a couple of well-known absolute paths).
fn find_tool(name: &str) -> Option<PathBuf> {
    if let Ok(path) = std::env::var("PATH") {
        for dir in std::env::split_paths(&path) {
            let candidate = dir.join(name);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    for prefix in ["/usr/bin", "/usr/local/bin", "/opt/homebrew/bin"] {
        let candidate = PathBuf::from(prefix).join(name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

/// Wrap an ISUP message as an ITU MTP3 MSU and return the on-wire bytes.
fn msu_bytes(message: &Message) -> Vec<u8> {
    let opc = PointCode::from_value(4107, Variant::Itu).unwrap();
    let dpc = PointCode::from_value(8209, Variant::Itu).unwrap();
    // SLS derived from the CIC low bits, the usual ISUP load-sharing key.
    let sls = (message.cic & 0x0F) as u8;
    message
        .to_msu(opc, dpc, NetworkIndicator::National, sls)
        .unwrap()
        .encode(Variant::Itu)
}

/// Dissect one MSU with tshark and return the full `-V` text.
fn dissect(text2pcap: &PathBuf, tshark: &PathBuf, msu: &[u8]) -> String {
    let dir = std::env::temp_dir();
    let stamp = format!(
        "{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let txt = dir.join(format!("itu-isup-kat-{stamp}.txt"));
    let pcap = dir.join(format!("itu-isup-kat-{stamp}.pcap"));

    // text2pcap hexdump: one offset column then the space-separated octets.
    let mut line = String::from("000000");
    for b in msu {
        line.push_str(&format!(" {b:02x}"));
    }
    line.push('\n');
    std::fs::File::create(&txt)
        .unwrap()
        .write_all(line.as_bytes())
        .unwrap();

    let t2p = Command::new(text2pcap)
        .args(["-q", "-l", "141"])
        .arg(&txt)
        .arg(&pcap)
        .output()
        .expect("run text2pcap");
    assert!(
        t2p.status.success(),
        "text2pcap failed: {}",
        String::from_utf8_lossy(&t2p.stderr)
    );

    let out = Command::new(tshark)
        .args(["-r"])
        .arg(&pcap)
        .args(["-V", "-o", "mtp3.standard:ITU"])
        .output()
        .expect("run tshark");
    assert!(
        out.status.success(),
        "tshark failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let _ = std::fs::remove_file(&txt);
    let _ = std::fs::remove_file(&pcap);
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// Assert the dissection names the ISUP message type and shows no error.
fn assert_clean(text: &str, must_contain: &[&str]) {
    assert!(
        text.contains("ISDN User Part"),
        "tshark did not reach the ISUP dissector:\n{text}"
    );
    assert!(
        !text.contains("Malformed"),
        "tshark reported a malformed packet:\n{text}"
    );
    assert!(
        !text.contains("Expert Info (Error"),
        "tshark reported an expert error:\n{text}"
    );
    for needle in must_contain {
        assert!(
            text.contains(needle),
            "tshark output missing {needle:?}:\n{text}"
        );
    }
}

#[test]
fn dissects_clean_against_wireshark() {
    let (Some(text2pcap), Some(tshark)) = (find_tool("text2pcap"), find_tool("tshark")) else {
        eprintln!("SKIP: text2pcap / tshark not found on PATH, skipping tshark KAT");
        return;
    };

    // ── IAM with called + optional calling party ────────────────────────────
    let called = Number::called(4, 1, false, "15551234567");
    let calling = Number::calling(4, 1, false, 0, 3, "15559876543");
    let iam = Message::iam(
        1,
        0x00,
        0x2000,
        calling_party_category::ORDINARY,
        transmission_medium_requirement::SPEECH,
        &called,
    )
    .unwrap()
    .with_optional(Parameter::calling_party_number(&calling).unwrap());
    let text = dissect(&text2pcap, &tshark, &msu_bytes(&iam));
    assert_clean(
        &text,
        &[
            "Initial address",
            "Called Party Number",
            "15551234567",
            "Calling Party Number",
            "15559876543",
            "Nature of Connection Indicators",
        ],
    );

    // ── ACM ─────────────────────────────────────────────────────────────────
    let acm = Message::acm(1, 0x1010);
    let text = dissect(&text2pcap, &tshark, &msu_bytes(&acm));
    assert_clean(&text, &["Address complete", "Backward Call Indicators"]);

    // ── ANM ─────────────────────────────────────────────────────────────────
    let anm = Message::anm(1);
    let text = dissect(&text2pcap, &tshark, &msu_bytes(&anm));
    assert_clean(&text, &["Answer"]);

    // ── CPG ─────────────────────────────────────────────────────────────────
    let cpg = Message::cpg(1, event_information::ALERTING);
    let text = dissect(&text2pcap, &tshark, &msu_bytes(&cpg));
    assert_clean(&text, &["Call progress", "Event information"]);

    // ── REL with Cause (normal call clearing, 16) ───────────────────────────
    let rel = Message::release(1, &CauseIndicators::new(1, 16));
    let text = dissect(&text2pcap, &tshark, &msu_bytes(&rel));
    assert_clean(
        &text,
        &["Release", "Cause indicator", "Normal call clearing"],
    );

    // ── RLC ─────────────────────────────────────────────────────────────────
    let rlc = Message::release_complete(1);
    let text = dissect(&text2pcap, &tshark, &msu_bytes(&rlc));
    assert_clean(&text, &["Release complete"]);

    // ── BLO / UBL / RSC ─────────────────────────────────────────────────────
    for (msg, name) in [
        (Message::blocking(3), "Blocking"),
        (Message::unblocking(3), "Unblocking"),
        (Message::reset_circuit(3), "Reset Circuit"),
    ] {
        let text = dissect(&text2pcap, &tshark, &msu_bytes(&msg));
        assert_clean(&text, &[name]);
    }

    // ── GRS (range only) ────────────────────────────────────────────────────
    let grs = Message::circuit_group_reset(1, &RangeAndStatus::range_only(4));
    let text = dissect(&text2pcap, &tshark, &msu_bytes(&grs));
    assert_clean(&text, &["Circuit group reset", "Range"]);

    // ── CGB (supervision + range and status) ────────────────────────────────
    let cgb = Message::circuit_group_blocking(1, 0x00, &RangeAndStatus::with_status(3, vec![0x0F]));
    let text = dissect(&text2pcap, &tshark, &msu_bytes(&cgb));
    assert_clean(
        &text,
        &[
            "Circuit group blocking",
            "Circuit group supervision message type",
            "Range",
        ],
    );

    // ── INF / INR ───────────────────────────────────────────────────────────
    let inr = Message::information_request(1, 0x0001);
    let text = dissect(&text2pcap, &tshark, &msu_bytes(&inr));
    assert_clean(&text, &["Information request"]);
}
