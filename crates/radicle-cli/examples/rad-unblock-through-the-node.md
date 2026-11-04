Under a permissive default seeding policy, a repository removed from storage
is left with a 'block' policy, so that the default doesn't seed it again on
its own:

```
$ rad inspect rad:z42hL2jL4XNk6K8oHQaSWfMgCL7ji --policy
Repository rad:z42hL2jL4XNk6K8oHQaSWfMgCL7ji is not being seeded
```

A seed doesn't lift a block. With the node running, `rad unblock` removes it
through the node, which refuses while the repository is being repaired or is
quarantined:

```
$ rad unblock rad:z42hL2jL4XNk6K8oHQaSWfMgCL7ji
✓ The 'block' policy for rad:z42hL2jL4XNk6K8oHQaSWfMgCL7ji is removed
```

The default policy applies to it again, and it can be cloned:

```
$ rad inspect rad:z42hL2jL4XNk6K8oHQaSWfMgCL7ji --policy
Repository rad:z42hL2jL4XNk6K8oHQaSWfMgCL7ji is being seeded with scope `all`
```

```
$ rad clone rad:z42hL2jL4XNk6K8oHQaSWfMgCL7ji
✓ Seeding policy updated for rad:z42hL2jL4XNk6K8oHQaSWfMgCL7ji with scope 'all'
Fetching rad:z42hL2jL4XNk6K8oHQaSWfMgCL7ji from the network, found [..] potential seed(s).
✓ Target met: [..] seed(s)
✓ Creating checkout in ./heartwood..
✓ Remote alice@z6MknSLrJoTcukLrE435hVNQT4JUhbvWLX4kUzqkEStBU8Vi added
✓ Remote-tracking branch alice@z6MknSLrJoTcukLrE435hVNQT4JUhbvWLX4kUzqkEStBU8Vi/master created for z6MknSLrJoTcukLrE435hVNQT4JUhbvWLX4kUzqkEStBU8Vi
✓ Repository successfully cloned under [..]/heartwood/
╭────────────────────────────────────╮
│ heartwood                          │
│ Radicle Heartwood Protocol & Stack │
│ 0 issues · 0 patches               │
╰────────────────────────────────────╯
Run `cd ./heartwood` to go to the repository directory.
```
