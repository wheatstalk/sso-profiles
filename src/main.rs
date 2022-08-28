use anyhow::anyhow;
use clap::Parser;
use sso_profiles::*;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Your SSO Start URL
    #[clap(value_parser)]
    start_url: String,

    /// The region in which you've deployed AWS SSO
    #[clap(long, value_parser, default_value_t = String::from("us-east-1"))]
    sso_region: String,

    /// Populate any discovered profiles into your AWS config file
    #[clap(long)]
    populate: bool,

    /// An optional prefix for generated SSO profile names
    #[clap(long, value_parser)]
    prefix: Option<String>,

    /// Remove old profiles matching the optional prefix
    #[clap(long)]
    clean: bool,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let args = Args::parse();

    let merger = AwsConfigMerger {
        prefix: args.prefix.clone().unwrap_or_else(|| String::from("")),
        clean: args.clean,
    };

    let mut ini = configparser::ini::Ini::new();

    if args.populate {
        // Try to locate the AWS config file
        let aws_config_path = get_aws_config_path().ok_or_else(|| anyhow!("Cannot resolve AWS config file path"))?;

        // Load the AWS Config file
        if aws_config_path.exists() {
            match ini.load(&aws_config_path) {
                Ok(res) => res,
                Err(err) => return Err(anyhow!("{}", err)),
            };
        }

        let sso_profiles = list_sso_profiles(&args).await?;

        merger.merge(&sso_profiles, &mut ini)?;
        
        ini.write(&aws_config_path)?;
    } else {
        let sso_profiles = list_sso_profiles(&args).await?;
        
        merger.merge(&sso_profiles, &mut ini)?;
        
        println!("{}", ini.writes());
    }

    Ok(())
}

async fn list_sso_profiles(args: &Args) -> Result<Vec<SSOProfile>, anyhow::Error> {
    let lister = SSOProfilesLister::new(&args.start_url, &args.sso_region);
    let sso_profiles = lister.list().await?;

    Ok(sso_profiles)
}

fn get_aws_config_path() -> Option<std::path::PathBuf> {
    if let Some(mut path) = home::home_dir() {
        path.push(".aws");
        path.push("config");
        Some(path)
    } else {
        None
    }
}