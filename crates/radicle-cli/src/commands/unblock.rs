mod args;

use crate::terminal as term;

use term::args::BlockTarget;

pub use args::Args;

pub fn run(args: Args, ctx: impl term::Context) -> anyhow::Result<()> {
    let profile = ctx.profile()?;

    let updated = match args.target {
        BlockTarget::Node(nid) => profile.policies_mut()?.unblock_nid(&nid)?,
        // A repository's block goes only while no node runs: without it, a
        // permissive default seeds the repository, past the node's gate.
        BlockTarget::Repo(rid) => profile.unblock_repo(&rid)?,
    };

    if updated {
        term::success!("The 'block' policy for {} is removed", args.target);
    } else {
        term::info!("No 'block' policy exists for {}", args.target)
    }
    Ok(())
}
