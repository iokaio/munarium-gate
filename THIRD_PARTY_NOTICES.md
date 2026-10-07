# Third-party notices

Stage 1 dependencies are pinned by Cargo.toml and Cargo.lock. Warden verification/transport exports are retained with their licenses and source locks in vendor/. This inventory was generated from locked Cargo metadata on 6 October
2026. Preserve upstream license/notice files when redistributing crates or binaries;
this inventory does not replace their terms or claim a vulnerability audit.

The proposed JSON vectors/schemas come unchanged from the public Apache-2.0 platform hub;
contracts/stage1/vendor-lock.json records their revision and hashes.

The separately downloaded OPA 1.21.1 evaluator is Apache-2.0, from
[open-policy-agent/opa](https://github.com/open-policy-agent/opa). Its exact binary pin and
reproducible-build limitation are in [Stage 1](docs/stage1.md). It is not redistributed.
Python is operator-supplied under its PSF license; the worker requires no third-party Python packages.

| Package | Version | Declared license | Upstream |
|---|---|---|---|
| ahash | 0.8.12 | MIT OR Apache-2.0 | [source](https://github.com/tkaitchuck/ahash) |
| aho-corasick | 1.1.5 | Unlicense OR MIT | [source](https://github.com/BurntSushi/aho-corasick) |
| atomic-waker | 1.1.2 | Apache-2.0 OR MIT | [source](https://github.com/smol-rs/atomic-waker) |
| autocfg | 1.5.1 | Apache-2.0 OR MIT | [source](https://github.com/cuviper/autocfg) |
| axum | 0.8.9 | MIT | [source](https://github.com/tokio-rs/axum) |
| axum-core | 0.5.6 | MIT | [source](https://github.com/tokio-rs/axum) |
| base64 | 0.22.1 | MIT OR Apache-2.0 | [source](https://github.com/marshallpierce/rust-base64) |
| base64 | 0.23.1 | MIT OR Apache-2.0 | [source](https://github.com/marshallpierce/rust-base64) |
| base64ct | 1.8.3 | Apache-2.0 OR MIT | [source](https://github.com/RustCrypto/formats) |
| bit-set | 0.8.0 | Apache-2.0 OR MIT | [source](https://github.com/contain-rs/bit-set) |
| bit-vec | 0.8.0 | Apache-2.0 OR MIT | [source](https://github.com/contain-rs/bit-vec) |
| bitflags | 2.13.2 | MIT OR Apache-2.0 | [source](https://github.com/bitflags/bitflags) |
| block-buffer | 0.10.4 | MIT OR Apache-2.0 | [source](https://github.com/RustCrypto/utils) |
| borrow-or-share | 0.2.4 | MIT-0 | [source](https://github.com/yescallop/borrow-or-share) |
| bumpalo | 3.20.3 | MIT OR Apache-2.0 | [source](https://github.com/fitzgen/bumpalo) |
| bytecount | 0.6.9 | Apache-2.0/MIT | [source](https://github.com/llogiq/bytecount) |
| bytes | 1.12.1 | MIT | [source](https://github.com/tokio-rs/bytes) |
| cc | 1.6.0 | MIT OR Apache-2.0 | [source](https://github.com/rust-lang/cc-rs) |
| cfg-if | 1.0.5 | MIT OR Apache-2.0 | [source](https://github.com/rust-lang/cfg-if) |
| cfg_aliases | 0.2.2 | MIT | [source](https://github.com/katharostech/cfg_aliases) |
| chacha20 | 0.10.2 | MIT OR Apache-2.0 | [source](https://github.com/RustCrypto/stream-ciphers) |
| const-oid | 0.9.6 | Apache-2.0 OR MIT | [source](https://github.com/RustCrypto/formats/tree/master/const-oid) |
| cpufeatures | 0.2.17 | MIT OR Apache-2.0 | [source](https://github.com/RustCrypto/utils) |
| cpufeatures | 0.3.1 | MIT OR Apache-2.0 | [source](https://github.com/RustCrypto/utils) |
| crypto-common | 0.1.7 | MIT OR Apache-2.0 | [source](https://github.com/RustCrypto/traits) |
| curve25519-dalek | 4.1.3 | BSD-3-Clause | [source](https://github.com/dalek-cryptography/curve25519-dalek/tree/main/curve25519-dalek) |
| curve25519-dalek-derive | 0.1.1 | MIT/Apache-2.0 | [source](https://github.com/dalek-cryptography/curve25519-dalek) |
| der | 0.7.10 | Apache-2.0 OR MIT | [source](https://github.com/RustCrypto/formats/tree/master/der) |
| digest | 0.10.7 | MIT OR Apache-2.0 | [source](https://github.com/RustCrypto/traits) |
| displaydoc | 0.2.7 | MIT OR Apache-2.0 | [source](https://github.com/yaahc/displaydoc) |
| ed25519 | 2.2.3 | Apache-2.0 OR MIT | [source](https://github.com/RustCrypto/signatures/tree/master/ed25519) |
| ed25519-dalek | 2.2.0 | BSD-3-Clause | [source](https://github.com/dalek-cryptography/curve25519-dalek/tree/main/ed25519-dalek) |
| email_address | 0.2.9 | MIT | [source](https://github.com/johnstonskj/rust-email_address.git) |
| errno | 0.3.14 | MIT OR Apache-2.0 | [source](https://github.com/lambda-fairy/rust-errno) |
| fallible-iterator | 0.3.0 | MIT/Apache-2.0 | [source](https://github.com/sfackler/rust-fallible-iterator) |
| fallible-streaming-iterator | 0.1.9 | MIT/Apache-2.0 | [source](https://github.com/sfackler/fallible-streaming-iterator) |
| fancy-regex | 0.14.0 | MIT | [source](https://github.com/fancy-regex/fancy-regex) |
| fastrand | 2.5.0 | Apache-2.0 OR MIT | [source](https://github.com/smol-rs/fastrand) |
| fiat-crypto | 0.2.9 | MIT OR Apache-2.0 OR BSD-1-Clause | [source](https://github.com/mit-plv/fiat-crypto) |
| find-msvc-tools | 0.1.14 | MIT OR Apache-2.0 | [source](https://github.com/rust-lang/cc-rs) |
| fluent-uri | 0.3.2 | MIT | [source](https://github.com/yescallop/fluent-uri-rs) |
| foldhash | 0.1.5 | Zlib | [source](https://github.com/orlp/foldhash) |
| form_urlencoded | 1.2.2 | MIT OR Apache-2.0 | [source](https://github.com/servo/rust-url) |
| fraction | 0.15.4 | MIT OR Apache-2.0 | [source](https://github.com/dnsl48/fraction.git) |
| futures-channel | 0.3.34 | MIT OR Apache-2.0 | [source](https://github.com/rust-lang/futures-rs) |
| futures-core | 0.3.34 | MIT OR Apache-2.0 | [source](https://github.com/rust-lang/futures-rs) |
| futures-task | 0.3.34 | MIT OR Apache-2.0 | [source](https://github.com/rust-lang/futures-rs) |
| futures-util | 0.3.34 | MIT OR Apache-2.0 | [source](https://github.com/rust-lang/futures-rs) |
| generic-array | 0.14.7 | MIT | [source](https://github.com/fizyk20/generic-array.git) |
| getrandom | 0.2.17 | MIT OR Apache-2.0 | [source](https://github.com/rust-random/getrandom) |
| getrandom | 0.3.4 | MIT OR Apache-2.0 | [source](https://github.com/rust-random/getrandom) |
| getrandom | 0.4.3 | MIT OR Apache-2.0 | [source](https://github.com/rust-random/getrandom) |
| hashbrown | 0.15.5 | MIT OR Apache-2.0 | [source](https://github.com/rust-lang/hashbrown) |
| hashlink | 0.10.0 | MIT OR Apache-2.0 | [source](https://github.com/kyren/hashlink) |
| http | 1.5.0 | MIT OR Apache-2.0 | [source](https://github.com/hyperium/http) |
| http-body | 1.1.0 | MIT | [source](https://github.com/hyperium/http-body) |
| http-body-util | 0.1.5 | MIT | [source](https://github.com/hyperium/http-body) |
| httparse | 1.10.1 | MIT OR Apache-2.0 | [source](https://github.com/seanmonstar/httparse) |
| httpdate | 1.0.3 | MIT OR Apache-2.0 | [source](https://github.com/pyfisch/httpdate) |
| hyper | 1.12.0 | MIT | [source](https://github.com/hyperium/hyper) |
| hyper-rustls | 0.27.10 | Apache-2.0 OR ISC OR MIT | [source](https://github.com/rustls/hyper-rustls) |
| hyper-util | 0.1.21 | MIT | [source](https://github.com/hyperium/hyper-util) |
| icu_collections | 2.3.0 | Unicode-3.0 | [source](https://github.com/unicode-org/icu4x) |
| icu_locale_core | 2.3.0 | Unicode-3.0 | [source](https://github.com/unicode-org/icu4x) |
| icu_normalizer | 2.3.0 | Unicode-3.0 | [source](https://github.com/unicode-org/icu4x) |
| icu_normalizer_data | 2.3.0 | Unicode-3.0 | [source](https://github.com/unicode-org/icu4x) |
| icu_properties | 2.3.0 | Unicode-3.0 | [source](https://github.com/unicode-org/icu4x) |
| icu_properties_data | 2.3.0 | Unicode-3.0 | [source](https://github.com/unicode-org/icu4x) |
| icu_provider | 2.3.1 | Unicode-3.0 | [source](https://github.com/unicode-org/icu4x) |
| idna | 1.1.0 | MIT OR Apache-2.0 | [source](https://github.com/servo/rust-url/) |
| idna_adapter | 1.2.2 | Apache-2.0 OR MIT | [source](https://github.com/hsivonen/idna_adapter) |
| ipnet | 2.12.2 | MIT OR Apache-2.0 | [source](https://github.com/krisprice/ipnet) |
| itoa | 1.0.18 | MIT OR Apache-2.0 | [source](https://github.com/dtolnay/itoa) |
| js-sys | 0.3.106 | MIT OR Apache-2.0 | [source](https://github.com/wasm-bindgen/wasm-bindgen/tree/master/crates/js-sys) |
| jsonschema | 0.26.2 | MIT | [source](https://github.com/Stranger6667/jsonschema) |
| lazy_static | 1.5.1 | MIT OR Apache-2.0 | [source](https://github.com/rust-lang-nursery/lazy-static.rs) |
| libc | 0.2.190 | MIT OR Apache-2.0 | [source](https://github.com/rust-lang/libc) |
| libsqlite3-sys | 0.35.0 | MIT | [source](https://github.com/rusqlite/rusqlite) |
| linux-raw-sys | 0.12.1 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT | [source](https://github.com/sunfishcode/linux-raw-sys) |
| litemap | 0.8.3 | Unicode-3.0 | [source](https://github.com/unicode-org/icu4x) |
| log | 0.4.34 | MIT OR Apache-2.0 | [source](https://github.com/rust-lang/log) |
| lru-slab | 0.1.3 | MIT OR Apache-2.0 OR Zlib | [source](https://github.com/Ralith/lru-slab) |
| matchit | 0.8.4 | MIT AND BSD-3-Clause | [source](https://github.com/ibraheemdev/matchit) |
| memchr | 2.8.3 | Unlicense OR MIT | [source](https://github.com/BurntSushi/memchr) |
| mime | 0.3.17 | MIT OR Apache-2.0 | [source](https://github.com/hyperium/mime) |
| mio | 1.2.4 | MIT | [source](https://github.com/tokio-rs/mio) |
| num | 0.4.3 | MIT OR Apache-2.0 | [source](https://github.com/rust-num/num) |
| num-bigint | 0.4.8 | MIT OR Apache-2.0 | [source](https://github.com/rust-num/num-bigint) |
| num-cmp | 0.1.0 | MIT/Apache-2.0 | [source](https://github.com/lifthrasiir/num-cmp) |
| num-complex | 0.4.6 | MIT OR Apache-2.0 | [source](https://github.com/rust-num/num-complex) |
| num-integer | 0.1.47 | MIT OR Apache-2.0 | [source](https://github.com/rust-num/num-integer) |
| num-iter | 0.1.46 | MIT OR Apache-2.0 | [source](https://github.com/rust-num/num-iter) |
| num-rational | 0.4.2 | MIT OR Apache-2.0 | [source](https://github.com/rust-num/num-rational) |
| num-traits | 0.2.19 | MIT OR Apache-2.0 | [source](https://github.com/rust-num/num-traits) |
| once_cell | 1.21.4 | MIT OR Apache-2.0 | [source](https://github.com/matklad/once_cell) |
| outref | 0.5.2 | MIT | [source](https://github.com/Nugine/outref) |
| percent-encoding | 2.3.2 | MIT OR Apache-2.0 | [source](https://github.com/servo/rust-url/) |
| pin-project-lite | 0.2.17 | Apache-2.0 OR MIT | [source](https://github.com/taiki-e/pin-project-lite) |
| pkcs8 | 0.10.2 | Apache-2.0 OR MIT | [source](https://github.com/RustCrypto/formats/tree/master/pkcs8) |
| pkg-config | 0.3.34 | MIT OR Apache-2.0 | [source](https://github.com/rust-lang/pkg-config-rs) |
| potential_utf | 0.1.6 | Unicode-3.0 | [source](https://github.com/unicode-org/icu4x) |
| proc-macro2 | 1.0.107 | MIT OR Apache-2.0 | [source](https://github.com/dtolnay/proc-macro2) |
| quinn | 0.11.12 | MIT OR Apache-2.0 | [source](https://github.com/quinn-rs/quinn) |
| quinn-proto | 0.11.19 | MIT OR Apache-2.0 | [source](https://github.com/quinn-rs/quinn) |
| quinn-udp | 0.5.16 | MIT OR Apache-2.0 | [source](https://github.com/quinn-rs/quinn) |
| quote | 1.0.47 | MIT OR Apache-2.0 | [source](https://github.com/dtolnay/quote) |
| r-efi | 5.3.0 | MIT OR Apache-2.0 OR LGPL-2.1-or-later | [source](https://github.com/r-efi/r-efi) |
| r-efi | 6.0.0 | MIT OR Apache-2.0 OR LGPL-2.1-or-later | [source](https://github.com/r-efi/r-efi) |
| rand | 0.10.3 | MIT OR Apache-2.0 | [source](https://github.com/rust-random/rand) |
| rand_core | 0.10.1 | MIT OR Apache-2.0 | [source](https://github.com/rust-random/rand_core) |
| rand_core | 0.6.4 | MIT OR Apache-2.0 | [source](https://github.com/rust-random/rand) |
| rand_pcg | 0.10.2 | MIT OR Apache-2.0 | [source](https://github.com/rust-random/rngs) |
| ref-cast | 1.0.26 | MIT OR Apache-2.0 | [source](https://github.com/dtolnay/ref-cast) |
| ref-cast-impl | 1.0.26 | MIT OR Apache-2.0 | [source](https://github.com/dtolnay/ref-cast) |
| referencing | 0.26.2 | MIT | [source](https://github.com/Stranger6667/jsonschema) |
| regex-automata | 0.4.18 | MIT OR Apache-2.0 | [source](https://github.com/rust-lang/regex) |
| regex-syntax | 0.8.11 | MIT OR Apache-2.0 | [source](https://github.com/rust-lang/regex) |
| reqwest | 0.12.28 | MIT OR Apache-2.0 | [source](https://github.com/seanmonstar/reqwest) |
| ring | 0.17.14 | Apache-2.0 AND ISC | [source](https://github.com/briansmith/ring) |
| rusqlite | 0.37.0 | MIT | [source](https://github.com/rusqlite/rusqlite) |
| rustc-hash | 2.1.3 | Apache-2.0 OR MIT | [source](https://github.com/rust-lang/rustc-hash) |
| rustc_version | 0.4.1 | MIT OR Apache-2.0 | [source](https://github.com/djc/rustc-version-rs) |
| rustix | 1.1.5 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT | [source](https://github.com/bytecodealliance/rustix) |
| rustls | 0.23.45 | Apache-2.0 OR ISC OR MIT | [source](https://github.com/rustls/rustls) |
| rustls-pemfile | 2.2.0 | Apache-2.0 OR ISC OR MIT | [source](https://github.com/rustls/pemfile) |
| rustls-pki-types | 1.15.1 | MIT OR Apache-2.0 | [source](https://github.com/rustls/pki-types) |
| rustls-webpki | 0.103.15 | ISC | [source](https://github.com/rustls/webpki) |
| rustversion | 1.0.23 | MIT OR Apache-2.0 | [source](https://github.com/dtolnay/rustversion) |
| ryu | 1.0.23 | Apache-2.0 OR BSL-1.0 | [source](https://github.com/dtolnay/ryu) |
| semver | 1.0.28 | MIT OR Apache-2.0 | [source](https://github.com/dtolnay/semver) |
| serde | 1.0.228 | MIT OR Apache-2.0 | [source](https://github.com/serde-rs/serde) |
| serde_core | 1.0.228 | MIT OR Apache-2.0 | [source](https://github.com/serde-rs/serde) |
| serde_derive | 1.0.228 | MIT OR Apache-2.0 | [source](https://github.com/serde-rs/serde) |
| serde_json | 1.0.149 | MIT OR Apache-2.0 | [source](https://github.com/serde-rs/json) |
| serde_path_to_error | 0.1.20 | MIT OR Apache-2.0 | [source](https://github.com/dtolnay/path-to-error) |
| serde_urlencoded | 0.7.1 | MIT/Apache-2.0 | [source](https://github.com/nox/serde_urlencoded) |
| sha2 | 0.10.9 | MIT OR Apache-2.0 | [source](https://github.com/RustCrypto/hashes) |
| shlex | 2.0.1 | MIT OR Apache-2.0 | [source](https://github.com/comex/rust-shlex) |
| signal-hook-registry | 1.4.8 | MIT OR Apache-2.0 | [source](https://github.com/vorner/signal-hook) |
| signature | 2.2.0 | Apache-2.0 OR MIT | [source](https://github.com/RustCrypto/traits/tree/master/signature) |
| slab | 0.4.12 | MIT | [source](https://github.com/tokio-rs/slab) |
| smallvec | 1.16.2 | MIT OR Apache-2.0 | [source](https://github.com/servo/rust-smallvec) |
| socket2 | 0.6.5 | MIT OR Apache-2.0 | [source](https://github.com/rust-lang/socket2) |
| spki | 0.7.3 | Apache-2.0 OR MIT | [source](https://github.com/RustCrypto/formats/tree/master/spki) |
| stable_deref_trait | 1.2.1 | MIT OR Apache-2.0 | [source](https://github.com/storyyeller/stable_deref_trait) |
| subtle | 2.6.1 | BSD-3-Clause | [source](https://github.com/dalek-cryptography/subtle) |
| syn | 2.0.119 | MIT OR Apache-2.0 | [source](https://github.com/dtolnay/syn) |
| syn | 3.0.6 | MIT OR Apache-2.0 | [source](https://github.com/dtolnay/syn) |
| sync_wrapper | 1.0.2 | Apache-2.0 | [source](https://github.com/Actyx/sync_wrapper) |
| synstructure | 0.14.0 | MIT | [source](https://github.com/mystor/synstructure) |
| tempfile | 3.27.0 | MIT OR Apache-2.0 | [source](https://github.com/Stebalien/tempfile) |
| thiserror | 2.0.21 | MIT OR Apache-2.0 | [source](https://github.com/dtolnay/thiserror) |
| thiserror-impl | 2.0.21 | MIT OR Apache-2.0 | [source](https://github.com/dtolnay/thiserror) |
| tinystr | 0.8.4 | Unicode-3.0 | [source](https://github.com/unicode-org/icu4x) |
| tinyvec | 1.13.3 | Zlib OR Apache-2.0 OR MIT | [source](https://github.com/Lokathor/tinyvec) |
| tokio | 1.53.1 | MIT | [source](https://github.com/tokio-rs/tokio) |
| tokio-macros | 2.7.2 | MIT | [source](https://github.com/tokio-rs/tokio) |
| tokio-rustls | 0.26.4 | MIT OR Apache-2.0 | [source](https://github.com/rustls/tokio-rustls) |
| tower | 0.5.3 | MIT | [source](https://github.com/tower-rs/tower) |
| tower-http | 0.6.11 | MIT | [source](https://github.com/tower-rs/tower-http) |
| tower-layer | 0.3.3 | MIT | [source](https://github.com/tower-rs/tower) |
| tower-service | 0.3.3 | MIT | [source](https://github.com/tower-rs/tower) |
| tracing | 0.1.44 | MIT | [source](https://github.com/tokio-rs/tracing) |
| tracing-core | 0.1.36 | MIT | [source](https://github.com/tokio-rs/tracing) |
| try-lock | 0.2.5 | MIT | [source](https://github.com/seanmonstar/try-lock) |
| typenum | 1.20.1 | MIT OR Apache-2.0 | [source](https://github.com/paholg/typenum) |
| unicode-ident | 1.0.26 | (MIT OR Apache-2.0) AND Unicode-3.0 | [source](https://github.com/dtolnay/unicode-ident) |
| untrusted | 0.9.0 | ISC | [source](https://github.com/briansmith/untrusted) |
| url | 2.5.8 | MIT OR Apache-2.0 | [source](https://github.com/servo/rust-url) |
| utf8_iter | 1.0.4 | Apache-2.0 OR MIT | [source](https://github.com/hsivonen/utf8_iter) |
| uuid | 1.26.0 | Apache-2.0 OR MIT | [source](https://github.com/uuid-rs/uuid) |
| uuid-simd | 0.8.0 | MIT | [source](https://github.com/Nugine/simd) |
| vcpkg | 0.2.15 | MIT/Apache-2.0 | [source](https://github.com/mcgoo/vcpkg-rs) |
| version_check | 0.9.5 | MIT/Apache-2.0 | [source](https://github.com/SergioBenitez/version_check) |
| vsimd | 0.8.0 | MIT | [source](https://github.com/Nugine/simd) |
| want | 0.3.2 | MIT | [source](https://github.com/seanmonstar/want) |
| wasi | 0.11.1+wasi-snapshot-preview1 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT | [source](https://github.com/bytecodealliance/wasi) |
| wasip2 | 1.0.4+wasi-0.2.12 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT | [source](https://github.com/bytecodealliance/wasi-rs) |
| wasm-bindgen | 0.2.129 | MIT OR Apache-2.0 | [source](https://github.com/wasm-bindgen/wasm-bindgen) |
| wasm-bindgen-futures | 0.4.79 | MIT OR Apache-2.0 | [source](https://github.com/wasm-bindgen/wasm-bindgen/tree/master/crates/futures) |
| wasm-bindgen-macro | 0.2.129 | MIT OR Apache-2.0 | [source](https://github.com/wasm-bindgen/wasm-bindgen/tree/master/crates/macro) |
| wasm-bindgen-macro-support | 0.2.129 | MIT OR Apache-2.0 | [source](https://github.com/wasm-bindgen/wasm-bindgen/tree/main/crates/macro-support) |
| wasm-bindgen-shared | 0.2.129 | MIT OR Apache-2.0 | [source](https://github.com/wasm-bindgen/wasm-bindgen/tree/master/crates/shared) |
| web-sys | 0.3.106 | MIT OR Apache-2.0 | [source](https://github.com/wasm-bindgen/wasm-bindgen/tree/master/crates/web-sys) |
| web-time | 1.1.0 | MIT OR Apache-2.0 | [source](https://github.com/daxpedda/web-time) |
| webpki-roots | 1.0.9 | CDLA-Permissive-2.0 | [source](https://github.com/rustls/webpki-roots) |
| windows-link | 0.2.1 | MIT OR Apache-2.0 | [source](https://github.com/microsoft/windows-rs) |
| windows-sys | 0.52.0 | MIT OR Apache-2.0 | [source](https://github.com/microsoft/windows-rs) |
| windows-sys | 0.61.2 | MIT OR Apache-2.0 | [source](https://github.com/microsoft/windows-rs) |
| windows-targets | 0.52.6 | MIT OR Apache-2.0 | [source](https://github.com/microsoft/windows-rs) |
| windows_aarch64_gnullvm | 0.52.6 | MIT OR Apache-2.0 | [source](https://github.com/microsoft/windows-rs) |
| windows_aarch64_msvc | 0.52.6 | MIT OR Apache-2.0 | [source](https://github.com/microsoft/windows-rs) |
| windows_i686_gnu | 0.52.6 | MIT OR Apache-2.0 | [source](https://github.com/microsoft/windows-rs) |
| windows_i686_gnullvm | 0.52.6 | MIT OR Apache-2.0 | [source](https://github.com/microsoft/windows-rs) |
| windows_i686_msvc | 0.52.6 | MIT OR Apache-2.0 | [source](https://github.com/microsoft/windows-rs) |
| windows_x86_64_gnu | 0.52.6 | MIT OR Apache-2.0 | [source](https://github.com/microsoft/windows-rs) |
| windows_x86_64_gnullvm | 0.52.6 | MIT OR Apache-2.0 | [source](https://github.com/microsoft/windows-rs) |
| windows_x86_64_msvc | 0.52.6 | MIT OR Apache-2.0 | [source](https://github.com/microsoft/windows-rs) |
| wit-bindgen | 0.57.1 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT | [source](https://github.com/bytecodealliance/wit-bindgen) |
| writeable | 0.6.4 | Unicode-3.0 | [source](https://github.com/unicode-org/icu4x) |
| yoke | 0.8.3 | Unicode-3.0 | [source](https://github.com/unicode-org/icu4x) |
| yoke-derive | 0.8.4 | Unicode-3.0 | [source](https://github.com/unicode-org/icu4x) |
| zerocopy | 0.8.56 | BSD-2-Clause OR Apache-2.0 OR MIT | [source](https://github.com/google/zerocopy) |
| zerocopy-derive | 0.8.56 | BSD-2-Clause OR Apache-2.0 OR MIT | [source](https://github.com/google/zerocopy) |
| zerofrom | 0.1.8 | Unicode-3.0 | [source](https://github.com/unicode-org/icu4x) |
| zerofrom-derive | 0.1.8 | Unicode-3.0 | [source](https://github.com/unicode-org/icu4x) |
| zeroize | 1.9.0 | Apache-2.0 OR MIT | [source](https://github.com/RustCrypto/utils) |
| zerotrie | 0.2.5 | Unicode-3.0 | [source](https://github.com/unicode-org/icu4x) |
| zerovec | 0.11.8 | Unicode-3.0 | [source](https://github.com/unicode-org/icu4x) |
| zerovec-derive | 0.11.6 | Unicode-3.0 | [source](https://github.com/unicode-org/icu4x) |
| zmij | 1.0.23 | MIT | [source](https://github.com/dtolnay/zmij) |
