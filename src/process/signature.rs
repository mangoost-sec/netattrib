//! Authenticode verification of executable images (WinVerifyTrust), System Informer style.
//!
//! Most Windows binaries carry no embedded signature: they are listed, by hash, in a signed
//! security catalog. A file without an embedded signature is therefore looked up in the
//! catalogs before it is called unsigned; the signer of a catalog-signed file is the catalog's
//! ("Microsoft Windows"). Packaged (MSIX / Store) apps sign the package instead of each file,
//! so an image under `WindowsApps` takes the signature status of its package.
//!
//! Verification never touches the network: revocation is not checked, and certificates or CRLs
//! not already cached are not fetched (netattrib must not add traffic of its own).

use std::fs::File;
use std::os::windows::io::AsRawHandle;
use std::path::Path;

use windows_sys::core::GUID;
use windows_sys::Win32::Foundation::{
    CERT_E_CHAINING, CERT_E_EXPIRED, CERT_E_REVOKED, CERT_E_UNTRUSTEDROOT,
    CERT_E_UNTRUSTEDTESTROOT, CRYPT_E_SECURITY_SETTINGS, HANDLE, HWND, INVALID_HANDLE_VALUE,
    TRUST_E_BAD_DIGEST, TRUST_E_EXPLICIT_DISTRUST, TRUST_E_NOSIGNATURE, TRUST_E_PROVIDER_UNKNOWN,
    TRUST_E_SUBJECT_FORM_UNKNOWN, TRUST_E_SUBJECT_NOT_TRUSTED,
};
use windows_sys::Win32::Security::Cryptography::Catalog::{
    CryptCATAdminAcquireContext2, CryptCATAdminCalcHashFromFileHandle2,
    CryptCATAdminEnumCatalogFromHash, CryptCATAdminReleaseCatalogContext,
    CryptCATAdminReleaseContext, CryptCATCatalogInfoFromContext, CATALOG_INFO,
};
use windows_sys::Win32::Security::Cryptography::{
    CertGetNameStringW, CERT_NAME_SIMPLE_DISPLAY_TYPE,
};
use windows_sys::Win32::Security::WinTrust::{
    WTHelperGetProvSignerFromChain, WTHelperProvDataFromStateData, WinVerifyTrust,
    WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_CATALOG_INFO, WINTRUST_DATA, WINTRUST_DATA_0,
    WINTRUST_FILE_INFO, WTD_CACHE_ONLY_URL_RETRIEVAL, WTD_CHOICE_CATALOG, WTD_CHOICE_FILE,
    WTD_REVOCATION_CHECK_NONE, WTD_REVOKE_NONE, WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY,
    WTD_UICONTEXT_EXECUTE, WTD_UI_NONE,
};
use windows_sys::Win32::Storage::Packaging::Appx::{
    GetStagedPackageOrigin, PackageOrigin, PackageOrigin_DeveloperSigned,
    PackageOrigin_DeveloperUnsigned, PackageOrigin_Inbox, PackageOrigin_LineOfBusiness,
    PackageOrigin_Store, PackageOrigin_Unknown, PackageOrigin_Unsigned,
};

use crate::util::{from_wide, wide};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Signature {
    /// A valid signature chaining to a trusted root.
    Signed { signer: String, via: Via },
    /// No embedded signature, catalog entry or signed package.
    Unsigned,
    /// A signature that does not verify: the file was modified, the certificate is revoked,
    /// expired (and the signature not timestamped), or does not chain to a trusted root.
    Invalid {
        reason: &'static str,
        signer: Option<String>,
    },
}

/// Where a valid signature was found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Via {
    /// Embedded in the file.
    File,
    /// A security catalog listing the file's hash.
    Catalog,
    /// The signed MSIX / AppX package the file belongs to.
    Package,
}

impl Signature {
    /// Unsigned or invalid: the processes worth a second look when they talk to the internet.
    pub fn is_untrusted(&self) -> bool {
        !matches!(self, Signature::Signed { .. })
    }

    /// `signed` / `unsigned` / `invalid` (exports).
    pub fn status(&self) -> &'static str {
        match self {
            Signature::Signed { .. } => "signed",
            Signature::Unsigned => "unsigned",
            Signature::Invalid { .. } => "invalid",
        }
    }

    pub fn signer(&self) -> Option<&str> {
        match self {
            Signature::Signed { signer, .. } => Some(signer),
            Signature::Invalid { signer, .. } => signer.as_deref(),
            Signature::Unsigned => None,
        }
    }
}

/// Verifies `path`; `None` when the file cannot be opened (gone, or access denied).
pub fn verify(path: &str) -> Option<Signature> {
    let file = File::open(path).ok()?;
    let h = file.as_raw_handle() as HANDLE;
    let wpath = wide(path);
    let embedded = check_embedded(&wpath, h);
    if !matches!(
        embedded.result,
        TRUST_E_NOSIGNATURE | TRUST_E_SUBJECT_FORM_UNKNOWN | TRUST_E_PROVIDER_UNKNOWN
    ) {
        return Some(classify(embedded, Via::File));
    }
    // SHA-256 catalogs first (Windows 8 and later), then the older SHA-1 ones.
    for alg in ["SHA256", "SHA1"] {
        if let Some(outcome) = check_catalog(&wpath, h, alg) {
            return Some(classify(outcome, Via::Catalog));
        }
    }
    Some(check_package(path).unwrap_or(Signature::Unsigned))
}

struct Outcome {
    result: i32,
    signer: Option<String>,
}

fn classify(o: Outcome, via: Via) -> Signature {
    let reason = match o.result {
        0 => {
            return Signature::Signed {
                signer: o.signer.unwrap_or_else(|| "unknown signer".into()),
                via,
            }
        }
        TRUST_E_NOSIGNATURE | TRUST_E_SUBJECT_FORM_UNKNOWN | TRUST_E_PROVIDER_UNKNOWN => {
            return Signature::Unsigned
        }
        TRUST_E_BAD_DIGEST => "the file was modified after it was signed",
        CERT_E_REVOKED => "the signing certificate was revoked",
        CERT_E_EXPIRED => "the signing certificate expired and the signature has no timestamp",
        CERT_E_UNTRUSTEDROOT => "the certificate chain ends in an untrusted root",
        CERT_E_UNTRUSTEDTESTROOT => "signed with a test certificate",
        CERT_E_CHAINING => "the certificate chain is incomplete",
        TRUST_E_EXPLICIT_DISTRUST => "the signer is explicitly distrusted",
        CRYPT_E_SECURITY_SETTINGS => "the signature is blocked by local security policy",
        TRUST_E_SUBJECT_NOT_TRUSTED => "the subject is not trusted",
        _ => "the signature does not verify",
    };
    Signature::Invalid {
        reason,
        signer: o.signer,
    }
}

/// An image inside an installed MSIX / AppX package (`...\WindowsApps\<full name>\...`).
/// `AppxSignature.p7x` signs the package's block map, which hashes every file. Windows checked
/// it when it staged the package and only the system can write under `WindowsApps`, so the
/// staged origin says whether the file is signed. `None`: not a staged package.
fn check_package(path: &str) -> Option<Signature> {
    const DIR: &str = r"\windowsapps\";
    // ASCII lower-casing keeps byte offsets, so `at` indexes `path` too.
    let at = path.to_ascii_lowercase().find(DIR)? + DIR.len();
    let full_name = path[at..].split('\\').next().filter(|n| !n.is_empty())?;
    let mut origin: PackageOrigin = PackageOrigin_Unknown;
    if unsafe { GetStagedPackageOrigin(wide(full_name).as_ptr(), &mut origin) } != 0 {
        return None;
    }
    let signed = [
        PackageOrigin_Inbox,
        PackageOrigin_Store,
        PackageOrigin_LineOfBusiness,
        PackageOrigin_DeveloperSigned,
    ];
    if signed.contains(&origin) {
        let manifest = Path::new(&path[..at])
            .join(full_name)
            .join("AppxManifest.xml");
        let signer = std::fs::read_to_string(manifest)
            .ok()
            .and_then(|m| package_publisher(&m))
            .unwrap_or_else(|| "package publisher".into());
        Some(Signature::Signed {
            signer,
            via: Via::Package,
        })
    } else if [PackageOrigin_Unsigned, PackageOrigin_DeveloperUnsigned].contains(&origin) {
        Some(Signature::Unsigned)
    } else {
        None
    }
}

/// The manifest's `<PublisherDisplayName>` (Store apps' certificate subject is a GUID), else the
/// CN of the `<Identity Publisher="...">` distinguished name. Both are covered by the package
/// signature.
fn package_publisher(manifest: &str) -> Option<String> {
    let between = |s: &str, open: &str, close: &str| -> Option<String> {
        let start = s.find(open)? + open.len();
        let len = s[start..].find(close)?;
        Some(xml_unescape(s[start..start + len].trim()))
    };
    if let Some(name) = between(
        manifest,
        "<PublisherDisplayName>",
        "</PublisherDisplayName>",
    ) {
        if !name.is_empty() && !name.starts_with("ms-resource:") {
            return Some(name);
        }
    }
    let identity = &manifest[manifest.find("<Identity")?..];
    let dn = between(identity, "Publisher=\"", "\"")?;
    let cn = dn
        .strip_prefix("CN=")
        .or_else(|| dn.split(", CN=").nth(1))?;
    let cn = match cn.strip_prefix('"') {
        Some(quoted) => quoted.split('"').next()?,
        None => cn.split(',').next()?,
    };
    Some(cn.trim().to_string()).filter(|c| !c.is_empty())
}

fn xml_unescape(s: &str) -> String {
    s.replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
}

fn check_embedded(path: &[u16], h: HANDLE) -> Outcome {
    let mut file = WINTRUST_FILE_INFO {
        cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: path.as_ptr(),
        hFile: h,
        pgKnownSubject: std::ptr::null_mut(),
    };
    run_policy(WTD_CHOICE_FILE, WINTRUST_DATA_0 { pFile: &mut file })
}

/// `None` when no catalog of this hash algorithm lists the file.
fn check_catalog(path: &[u16], h: HANDLE, alg: &str) -> Option<Outcome> {
    let alg = wide(alg);
    let mut admin: isize = 0;
    let ok = unsafe {
        CryptCATAdminAcquireContext2(
            &mut admin,
            std::ptr::null(),
            alg.as_ptr(),
            std::ptr::null(),
            0,
        )
    };
    if ok == 0 {
        return None;
    }
    struct Admin(isize);
    impl Drop for Admin {
        fn drop(&mut self) {
            unsafe { CryptCATAdminReleaseContext(self.0, 0) };
        }
    }
    let admin = Admin(admin);

    let mut hash = [0u8; 64];
    let mut len = hash.len() as u32;
    if unsafe { CryptCATAdminCalcHashFromFileHandle2(admin.0, h, &mut len, hash.as_mut_ptr(), 0) }
        == 0
    {
        return None;
    }
    let hash = &mut hash[..len as usize];
    let cat = unsafe {
        CryptCATAdminEnumCatalogFromHash(admin.0, hash.as_ptr(), len, 0, std::ptr::null_mut())
    };
    if cat == 0 {
        return None;
    }
    let mut info = CATALOG_INFO {
        cbStruct: std::mem::size_of::<CATALOG_INFO>() as u32,
        wszCatalogFile: [0; 260],
    };
    let have_info = unsafe { CryptCATCatalogInfoFromContext(cat, &mut info, 0) } != 0;
    let outcome = have_info.then(|| {
        // Catalog members are tagged with the upper-case hex of their hash.
        let tag = wide(
            &hash
                .iter()
                .map(|b| format!("{:02X}", b))
                .collect::<String>(),
        );
        let mut member = WINTRUST_CATALOG_INFO {
            cbStruct: std::mem::size_of::<WINTRUST_CATALOG_INFO>() as u32,
            dwCatalogVersion: 0,
            pcwszCatalogFilePath: info.wszCatalogFile.as_ptr(),
            pcwszMemberTag: tag.as_ptr(),
            pcwszMemberFilePath: path.as_ptr(),
            hMemberFile: h,
            pbCalculatedFileHash: hash.as_mut_ptr(),
            cbCalculatedFileHash: len,
            pcCatalogContext: std::ptr::null_mut(),
            hCatAdmin: admin.0,
        };
        run_policy(
            WTD_CHOICE_CATALOG,
            WINTRUST_DATA_0 {
                pCatalog: &mut member,
            },
        )
    });
    unsafe { CryptCATAdminReleaseCatalogContext(admin.0, cat, 0) };
    outcome
}

/// Runs the Authenticode policy on one subject and reads the signer before releasing the
/// verification state.
fn run_policy(choice: u32, subject: WINTRUST_DATA_0) -> Outcome {
    let mut data = WINTRUST_DATA {
        cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
        pPolicyCallbackData: std::ptr::null_mut(),
        pSIPClientData: std::ptr::null_mut(),
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_NONE,
        dwUnionChoice: choice,
        Anonymous: subject,
        dwStateAction: WTD_STATEACTION_VERIFY,
        hWVTStateData: std::ptr::null_mut(),
        pwszURLReference: std::ptr::null_mut(),
        dwProvFlags: WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_REVOCATION_CHECK_NONE,
        dwUIContext: WTD_UICONTEXT_EXECUTE,
        pSignatureSettings: std::ptr::null_mut(),
    };
    let mut action: GUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    // INVALID_HANDLE_VALUE: there is no interactive user to ask.
    let no_ui = INVALID_HANDLE_VALUE as HWND;
    let result = unsafe { WinVerifyTrust(no_ui, &mut action, &mut data as *mut _ as *mut _) };
    let signer = signer_name(data.hWVTStateData);
    data.dwStateAction = WTD_STATEACTION_CLOSE;
    unsafe { WinVerifyTrust(no_ui, &mut action, &mut data as *mut _ as *mut _) };
    Outcome { result, signer }
}

/// Simple display name (CN) of the leaf certificate of the first signer.
fn signer_name(state: HANDLE) -> Option<String> {
    if state.is_null() {
        return None;
    }
    unsafe {
        let prov = WTHelperProvDataFromStateData(state);
        if prov.is_null() {
            return None;
        }
        let sgnr = WTHelperGetProvSignerFromChain(prov, 0, 0, 0);
        if sgnr.is_null() || (*sgnr).csCertChain == 0 || (*sgnr).pasCertChain.is_null() {
            return None;
        }
        let cert = (*(*sgnr).pasCertChain).pCert;
        if cert.is_null() {
            return None;
        }
        let mut buf = [0u16; 256];
        let n = CertGetNameStringW(
            cert,
            CERT_NAME_SIMPLE_DISPLAY_TYPE,
            0,
            std::ptr::null(),
            buf.as_mut_ptr(),
            buf.len() as u32,
        );
        // n counts the terminating NUL; 1 means an empty name.
        (n > 1).then(|| from_wide(&buf[..n as usize]))
    }
}

#[cfg(test)]
mod bench {
    /// What the GUI's background check costs: every distinct image of the running processes,
    /// verified once each (the enrichment worker caches per path).
    #[test]
    #[ignore]
    fn cost_of_verifying_running_images() {
        use crate::process::query;
        let mut paths: Vec<String> = query::snapshot()
            .unwrap()
            .iter()
            .filter_map(|e| query::image_path(e.pid, query::open_limited(e.pid).as_ref()))
            .collect();
        paths.sort_by_key(|p| p.to_lowercase());
        paths.dedup_by_key(|p| p.to_lowercase());
        let t = std::time::Instant::now();
        let mut counts = std::collections::BTreeMap::new();
        for p in &paths {
            let sig = super::verify(p);
            if sig.as_ref().is_some_and(|s| s.is_untrusted()) {
                println!("  {:?}: {}", sig.as_ref().unwrap(), p);
            }
            let kind = match sig {
                Some(super::Signature::Signed { via, .. }) => match via {
                    super::Via::File => "signed (embedded)",
                    super::Via::Catalog => "signed (catalog)",
                    super::Via::Package => "signed (package)",
                },
                Some(super::Signature::Unsigned) => "unsigned",
                Some(super::Signature::Invalid { .. }) => "invalid",
                None => "unreadable",
            };
            *counts.entry(kind).or_insert(0) += 1;
        }
        let total = t.elapsed();
        println!(
            "{} images in {:?} ({:?}/image): {:?}",
            paths.len(),
            total,
            total / paths.len().max(1) as u32,
            counts
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn system32(name: &str) -> String {
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
        format!(r"{}\System32\{}", root, name)
    }

    #[test]
    fn catalog_signed_windows_binary() {
        // Inbox binaries are signed through the system catalogs.
        let sig = verify(&system32("cmd.exe")).expect("readable");
        match &sig {
            Signature::Signed { signer, .. } => assert!(signer.contains("Microsoft"), "{signer}"),
            other => panic!("cmd.exe: {other:?}"),
        }
        assert!(!sig.is_untrusted());
        assert_eq!(sig.status(), "signed");
    }

    #[test]
    fn unsigned_and_missing_files() {
        // The test binary cargo just linked carries no signature and is in no catalog.
        let me = std::env::current_exe().unwrap();
        let sig = verify(&me.to_string_lossy()).expect("readable");
        assert_eq!(sig, Signature::Unsigned);
        assert!(sig.is_untrusted() && sig.signer().is_none());
        assert_eq!(verify(r"C:\definitely\not\here.exe"), None);
    }

    /// An embedded-signed binary verifies; the same file with one byte changed does not.
    #[test]
    fn tampered_copy_is_invalid() {
        let candidates = [
            r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
            r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
            r"C:\Program Files\Windows Defender\MpCmdRun.exe",
        ];
        let Some((path, signer)) = candidates.iter().find_map(|p| match verify(p) {
            Some(Signature::Signed {
                signer,
                via: Via::File,
            }) => Some((*p, signer)),
            _ => None,
        }) else {
            eprintln!("no embedded-signed candidate on this machine; skipped");
            return;
        };
        let mut bytes = std::fs::read(path).unwrap();
        // A quarter in: inside the code, well clear of the headers and the signature blob at
        // the end of the file.
        let at = bytes.len() / 4;
        bytes[at] ^= 0xff;
        let dir = std::env::temp_dir().join(format!("netattrib-sigtest-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let copy = dir.join("tampered.exe");
        std::fs::write(&copy, &bytes).unwrap();
        let sig = verify(&copy.to_string_lossy());
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(
            sig,
            Some(Signature::Invalid {
                reason: "the file was modified after it was signed",
                signer: Some(signer),
            })
        );
    }

    #[test]
    fn package_publisher_from_manifest() {
        // A Store app: the certificate subject is a GUID, the display name is the company.
        let store = r#"<Package><Identity Name="9426MICRO-STARINTERNATION.MSIGameBar"
            Publisher="CN=A225F3B5-240D-4EE9-BCF4-697A07F5E93E" Version="3.0.36.0" />
            <Properties><PublisherDisplayName>MICRO-STAR INTERNATIONAL CO., LTD</PublisherDisplayName>
            </Properties></Package>"#;
        assert_eq!(
            package_publisher(store).as_deref(),
            Some("MICRO-STAR INTERNATIONAL CO., LTD")
        );
        // A localized display name falls back to the subject's CN, quoted or not.
        let localized = r#"<Identity Name="X" Publisher="CN=&quot;Contoso, Ltd.&quot;, O=Contoso"/>
            <PublisherDisplayName>ms-resource:PublisherName</PublisherDisplayName>"#;
        assert_eq!(
            package_publisher(localized).as_deref(),
            Some("Contoso, Ltd.")
        );
        let plain = r#"<Identity Name="Microsoft.WidgetsPlatformRuntime"
            Publisher="CN=Microsoft Corporation, O=Microsoft Corporation, C=US" />"#;
        assert_eq!(
            package_publisher(plain).as_deref(),
            Some("Microsoft Corporation")
        );
        assert_eq!(package_publisher("<Package/>"), None);
        // Not inside a package: no opinion.
        assert_eq!(check_package(r"C:\Program Files\App\app.exe"), None);
    }

    /// Images of running packaged apps (Widgets, Store apps) carry no signature of their own
    /// but are signed through their package.
    #[test]
    fn packaged_app_images_are_signed_by_their_package() {
        use crate::process::query;
        let packaged = query::snapshot()
            .unwrap()
            .iter()
            .filter_map(|e| query::image_path(e.pid, query::open_limited(e.pid).as_ref()))
            .find(|p| p.to_ascii_lowercase().contains(r"\windowsapps\"));
        let Some(path) = packaged else {
            eprintln!("no packaged app running; skipped");
            return;
        };
        match verify(&path) {
            Some(Signature::Signed { .. }) => {}
            other => panic!("{path}: {other:?}"),
        }
    }
}
