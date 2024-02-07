use clap::Parser;
use trust_dns_resolver::{
    config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts}, error::ResolveError, IntoName, Name, Resolver
};
use trust_dns_proto::{rr::RecordType::NSEC, error::ProtoError};
use std::{error::Error, net::SocketAddr, process::ExitCode};
use thiserror::Error;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about=None)]
struct Args {
    #[arg(short, long)]
    nameserver: Option<String>,
    #[arg(short, long)]
    udp: bool,
    domain: String,
}

struct NSECWalker<'r> {
    resolver: &'r Resolver,
    domain: Name,
    current: Name,
}

#[derive(Debug, Error)]
#[error("NSec")]
enum NSecError {
    ResolveError(#[from] ResolveError),
    NoNSEC,
}

impl <'r> NSECWalker<'r> {
    fn new(resolver: &'r Resolver, domain: &str) -> Result<Self,ProtoError> {
        let domain = domain.into_name()?;
        Ok(Self { resolver, current: domain.clone(), domain })
    }

    fn next_lookup(&mut self) -> Result<Option<Name>, NSecError> {

        let rr = self.resolver
        .lookup(self.current.clone(), NSEC)?
        .into_iter()
        .next()
        .ok_or(NSecError::NoNSEC)?;

        let next: Name = rr.as_dnssec()
            .and_then(|ds| ds.as_nsec())
            .ok_or(NSecError::NoNSEC)?
            .next_domain_name()
            .clone();

        // Parent domain in next name means end of zone
        if next == self.domain { return Ok(None) }

        self.current = next.clone();
        Ok(Some(next))      
    }

}

impl <'r> Iterator for NSECWalker<'r> {
    type Item = Result<Name, NSecError>;

    fn next(&mut self) -> Option<Self::Item> {
        self.next_lookup().transpose()
    }
}

fn main() -> Result<ExitCode, Box<dyn Error>> {

    let args = Args::parse();
    let domain = args.domain;

    let config = match args.nameserver {
        
        Some(ns) => {
            let addr: SocketAddr = ns.parse()?;
            let proto = if args.udp { Protocol::Udp } else {Protocol::Tcp };
            let mut config = ResolverConfig::new();
            config.add_name_server(NameServerConfig::new(addr, proto));
            config
        },
        None => ResolverConfig::default(),
    };

    let mut opts = ResolverOpts::default();
    opts.recursion_desired = false;

    let resolver = Resolver::new(config, opts)?;

    let walker = NSECWalker::new(&resolver, &domain)?;

    let mut found = false;

    for name in walker {
        let name = name?;
        found = true;
        println!("{name}");
    }
    
    if found {
        Ok(ExitCode::SUCCESS)
    } else {
        eprintln!("No NSEC records found for {domain}");
        Ok(ExitCode::FAILURE)
    }
    
}
