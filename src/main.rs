use clap::Parser;
use trust_dns_resolver::{
    Resolver,
    config::{ResolverConfig,ResolverOpts},
    error::{ResolveError, ResolveErrorKind}, Name, IntoName,
};
use trust_dns_proto::{rr::RecordType::NSEC, error::ProtoError};
use std::{error::Error};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about=None)]
struct Args {
    domain: String
}

fn no_records_found(e: &ResolveError) -> bool {
    match e.kind() {
        ResolveErrorKind::NoRecordsFound{..} => true,
        _                                    => false,
    }
}

struct NSECWalker<'r> {
    resolver: &'r Resolver,
    domain: Name,
    current: Name,
}

impl <'r> NSECWalker<'r> {
    fn new(resolver: &'r Resolver, domain: &str) -> Result<Self,ProtoError> {
        let domain = domain.into_name()?;
        Ok(Self { resolver, current: domain.clone(), domain })
    }
}

impl <'r> Iterator for NSECWalker<'r> {
    type Item = Name;

    fn next(&mut self) -> Option<Self::Item> {
        let next: Name = self.resolver
            .lookup(self.current.clone(), NSEC)
            .ok()?
            .into_iter()
            .next()?
            .as_dnssec()?
            .as_nsec()?
            .next_domain_name()
            .clone();

        // Parent domain in next name means end of zone
        if next == self.domain { return None }

        self.current = next.clone();
        Some(next)
    }
}

fn main() -> Result<(), Box<dyn Error>> {

    let args = Args::parse();
    let domain = args.domain;

    let resolver = Resolver::new(ResolverConfig::default(), ResolverOpts::default())?;
    let walker = NSECWalker::new(&resolver, &domain)?;

    for name in walker {
        eprintln!("Found {name}");
    }

    /* 
    loop {

        todo!();

    }
    */
    
    Ok(())
    
}
