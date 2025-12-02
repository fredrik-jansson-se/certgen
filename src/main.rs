use clap::Parser;

#[derive(Debug, Parser)]
struct Opts {
    #[clap(subcommand)]
    cmd: Cmd,
}

#[derive(Debug, clap::Subcommand)]
enum Cmd {
    SelfSignedCA(#[clap(flatten)] SelfSignedCA),
    SignedCert(#[clap(flatten)] SignedCert),
}

#[derive(Debug, clap::Parser)]
struct SelfSignedCA {
    name: String,
    #[clap(long("san"), required = true)]
    subject_alt_names: Vec<String>,
    #[clap(long)]
    ttl: humantime::Duration,
}

#[derive(Debug, clap::Parser)]
struct SignedCert {
    #[clap(long, required = true)]
    ca: std::path::PathBuf,
    #[clap(long, required = true)]
    ca_key: std::path::PathBuf,
    name: String,
    #[clap(long("san"), required = true)]
    subject_alt_names: Vec<String>,
    #[clap(long)]
    ttl: humantime::Duration,

    #[clap(long, default_value_t = false)]
    is_ca: bool,
}

fn main() -> anyhow::Result<()> {
    let opts = Opts::parse();

    match opts.cmd {
        Cmd::SelfSignedCA(sa) => self_signed_ca(sa),
        Cmd::SignedCert(sa) => signed_cert(sa),
    }
}

fn self_signed_ca(opts: SelfSignedCA) -> anyhow::Result<()> {
    let mut cp = rcgen::CertificateParams::new(opts.subject_alt_names)?;

    cp.not_before = time::OffsetDateTime::now_utc();
    cp.not_after = time::OffsetDateTime::now_utc() + *opts.ttl;
    cp.use_authority_key_identifier_extension = true;
    cp.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);

    let mut dn = rcgen::DistinguishedName::new();
    dn.push(rcgen::DnType::CommonName, &opts.name);

    cp.distinguished_name = dn;
    
    cp.key_usages.push(rcgen::KeyUsagePurpose::CrlSign);
    cp.key_usages.push(rcgen::KeyUsagePurpose::DigitalSignature);
    cp.key_usages.push(rcgen::KeyUsagePurpose::KeyCertSign);

    let signing_key = rcgen::KeyPair::generate()?;

    let certificate = cp.self_signed(&signing_key)?;

    std::fs::write(format!("{}.pem", opts.name), certificate.pem())?;
    std::fs::write(format!("{}.key", opts.name), signing_key.serialize_pem())?;

    Ok(())
}

fn signed_cert(opts: SignedCert) -> anyhow::Result<()> {
    // Load CA
    let ca_key = rcgen::KeyPair::from_pem(&std::fs::read_to_string(&opts.ca_key)?)?;
    let ca = rcgen::Issuer::from_ca_cert_pem(&std::fs::read_to_string(&opts.ca)?, &ca_key)?;

    let mut cp = rcgen::CertificateParams::new(opts.subject_alt_names)?;

    cp.not_before = time::OffsetDateTime::now_utc();
    cp.not_after = time::OffsetDateTime::now_utc() + *opts.ttl;
    cp.use_authority_key_identifier_extension = true;

    let mut dn = rcgen::DistinguishedName::new();
    dn.push(rcgen::DnType::CommonName, &opts.name);

    cp.distinguished_name = dn;

    if opts.is_ca {
        cp.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        cp.key_usages.push(rcgen::KeyUsagePurpose::CrlSign);
        cp.key_usages.push(rcgen::KeyUsagePurpose::KeyCertSign);
    }
    cp.key_usages.push(rcgen::KeyUsagePurpose::DigitalSignature);

    let key = rcgen::KeyPair::generate()?;

    let certificate = cp.signed_by(&key, &ca)?;

    std::fs::write(format!("{}.pem", opts.name), certificate.pem())?;
    std::fs::write(format!("{}.key", opts.name), key.serialize_pem())?;

    Ok(())
}
