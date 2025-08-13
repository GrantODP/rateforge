use std::process::exit;

use clap::Parser;
use rtfg_core::{
    control::{CgroupName, Policy, Rate, RateController, TokenBucketController},
    platform::get_pids_by_name,
};
use tokio::signal;

#[derive(Debug, Parser)]
#[command(name = "rateforge")]
#[command(version = "1.0")]
pub struct Commands {
    #[arg(short, long, value_name = "Process Name")]
    name: String,

    ///Kilobytes per second
    #[arg(short, long)]
    download: Option<Rate>,

    ///Kilobytes per second
    #[arg(short, long)]
    upload: Option<Rate>,
}

async fn handle_controller(control: &mut dyn RateController, policy: Policy) {
    match control.apply_policy(policy) {
        Ok(_) => (),
        Err(err) => {
            eprintln!("Could not add policy: {}", err);
            exit(1)
        }
    }
    println!("limiting. Ctrl-c to quit.");
    signal::ctrl_c().await;
    match control.close() {
        Ok(_) => (),
        Err(err) => {
            eprintln!("Failed cleaning resources: {}", err);
            exit(1)
        }
    }
}

#[tokio::main]
async fn main() {
    let args = Commands::parse();

    let policy = Policy::new(args.download, args.upload);
    let mut cgname = CgroupName::new(args.name.as_str()).unwrap();
    let procs = get_pids_by_name(args.name.as_str());

    if let Some(procs) = procs {
        for proc in procs {
            println!("{:?}", proc);
            cgname.add_task(proc.into()).unwrap();
        }
    } else {
        eprintln!("No process by the name {}", args.name);
        exit(1)
    }

    let mut controller = TokenBucketController::new(cgname);

    match controller.as_mut() {
        Ok(control) => handle_controller(control, policy).await,
        Err(err) => {
            eprintln!("Program failed initializing: {}", err);
            exit(1)
        }
    }
}
