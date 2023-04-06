use clap::Parser;
use trust_dns_resolver::{
    Resolver,
    config::{ResolverConfig,ResolverOpts}, Name, IntoName,
};
use trust_dns_proto::{rr::RecordType::NSEC, error::ProtoError};
use std::{error::Error, process::ExitCode};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about=None)]
struct Args {
    domain: String
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

fn main() -> Result<ExitCode, Box<dyn Error>> {

    let args = Args::parse();
    let domain = args.domain;

    let resolver = Resolver::new(ResolverConfig::default(), ResolverOpts::default())?;
    let walker = NSECWalker::new(&resolver, &domain)?;

    let mut found = false;

    for name in walker {
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
