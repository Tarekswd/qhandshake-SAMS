//! Known-answer test: expected values come from tools/kat.py, an independent stdlib-Python
//! implementation of the same key schedule (differential test).

use qhandshake::crypto::*;

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[test]
fn key_schedule_matches_independent_python_implementation() {
    let shared: Vec<u8> = (1..=64).collect();
    let th_hello = hash(b"hello");
    let th_fin = hash(b"fin");
    let hs = handshake_secrets(&shared, &th_hello);
    let (c_ap, s_ap) = application_secrets(&hs.handshake_secret, &th_fin);
    assert_eq!(
        hex(&hs.handshake_secret),
        "09722e51c7da65a254d0992aefe840c109ae47552dd64fcafcd631336b9e8405"
    );
    assert_eq!(
        hex(&hs.client_hs),
        "22c2bda8fa19b42a1ab4b11517570a94aed0c332c8972dd3dc4d15c68c70dc3c"
    );
    assert_eq!(
        hex(&hs.server_hs),
        "3ae58aeca6fe1563348b8e4b0a21f188f8a1c11fb407401ec7e13038d152520d"
    );
    assert_eq!(
        hex(&*c_ap),
        "ed52ef67309ecd58eea07c02c84ade2c776f6d9dc88ab0f86157f26be1db5d45"
    );
    assert_eq!(
        hex(&*s_ap),
        "d7af392e37096c81c13f829367b7d27cddd2421ef05e51463e9c27c48728251c"
    );
    assert_eq!(
        hex(&finished_mac(&hs.server_hs, &th_fin)),
        "51b8f46d18ea0227d9f6c2d522fbbb58b4ad0f9cfcf62723e3fe5cfbd0d27d25"
    );
}
