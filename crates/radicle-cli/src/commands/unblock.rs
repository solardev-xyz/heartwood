mod args;

use crate::terminal as term;

use term::args::BlockTarget;

pub use args::Args;

pub fn run(args: Args, ctx: impl term::Context) -> anyhow::Result<()> {
    let profile = ctx.profile()?;

    let updated = match args.target {
        BlockTarget::Node(nid) => profile.policies_mut()?.unblock_nid(&nid)?,
        // Without its block, a permissive default seeds the repository: it
        // goes through the node, which checks its repository gate, or
        // directly while no node runs.
        BlockTarget::Repo(rid) => {
            let mut node = radicle::Node::new(profile.socket_from_env());
            profile.unblock_repo(rid, &mut node)?
        }
    };

    if updated {
        term::success!("The 'block' policy for {} is removed", args.target);
    } else {
        term::info!("No 'block' policy exists for {}", args.target)
    }
    Ok(())
}
