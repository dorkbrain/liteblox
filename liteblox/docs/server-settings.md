# Server settings and ACLs

Each node's `options { … }` (recursion, forwarders, DNSSEC, who may query it) is edited on its **Server settings** page, reached from the node's page. Named address lists shared by every node are under **Settings → ACLs**. LiteBlox writes both into the node's generated files (`options.conf`, `top.conf`, `acls.conf`) and checks every change on the node before and after applying it.

Readonly accounts can view the settings; changing them needs an admin.

## The fields

Leave a field empty, or a choice on "not set", for BIND's own default. That's how a freshly set-up node starts, so it behaves exactly like the stock Debian configuration. Lists take one item per line: addresses, networks, ACL names, `key NAME`; a `!` in front excludes.

| Field | BIND option | Notes |
|---|---|---|
| **Recursion** | `recursion` | **no** makes the node authoritative only: it answers for its own zones and nothing else |
| **Who may recurse** | `allow-recursion` | BIND's default is `localnets; localhost;`. [Forwarding-only zones](/help/zones#forwarding-only-zones) follow this too. |
| **Forwarders** | `forwarders` | an IP address per line, optionally followed by `port N`; empty resolves from the root servers |
| **If they don't answer** | `forward` | **fail (only)**, or **look it up the normal way (first)** |
| **Validation** | `dnssec-validation` | `auto` uses the built-in root key |
| **Don't validate** | `validate-except` | domains not to validate, such as a private domain you forward elsewhere |
| **Answer queries from** | `allow-query` | LiteBlox warns before a change that would shut out its own address |
| **Listen on IPv4 / IPv6** | `listen-on`, `listen-on-v6` | |

**Extra statements** hold anything without a field, written as they are: **Inside options** (for example `minimal-responses yes;`) and **Top level** (`logging`, `statistics-channels`…). LiteBlox's own `top.conf` adds BIND's statistics channel on `127.0.0.1:8053`, where the agent reads the query counts for the [Dashboard](/help/dashboard#services). If **Top level** has a `statistics-channels` statement of its own, LiteBlox adds none and yours is used as written; keep `inet 127.0.0.1 port 8053` in it, or the Dashboard's query graph for that node stays empty. The node's `named-checkconf` checks them, and the agent refuses `include`, file paths and statements that load code. Options found in a server's own configuration when it was [taken over](/help/existing-servers) land here when they have no field.

## Changing them

1. Change the fields. **Start from** another node and **Copy settings** fills the form in from that node; **Also apply to** applies the same settings to other nodes in one go.
2. **Review changes** shows, for each node, the diff of its generated files, its own `named-checkconf` verdict, and any **lockout** findings:
    - **blocks**: `allow-query` would refuse LiteBlox's own address, or `listen-on` would drop the address LiteBlox reaches the node's DNS on. LiteBlox couldn't check the node afterwards, so it refuses unless you tick **Apply anyway**.
    - **warns**: LiteBlox can't tell (for example a list with `localnets`).
3. **Apply** runs a job, one node at a time (secondaries first, the primary last). Each node is backed up, gets its new files (`rndc reconfig`), and is checked: every zone it serves still answers, and recursion still works if it did before. If a node fails, **every node the change touched is rolled back** and the settings stay as they were.

The **Nodes** page says *settings differ* when taken-over nodes don't all have the same settings, and lists the groups. Open one node's settings, **Copy settings** from the other, and apply.

From the command line, `liteblox node settings NAME` prints a node's options as LiteBlox writes them.

## ACLs

**Settings → ACLs** holds named address-match lists, written into `acls.conf` on every node LiteBlox has taken over. Use a name anywhere a list goes: a node's **Answer queries from**, **Who may recurse** or **Listen on**, or a zone's **Allow transfers to** and **Answer queries from**.

- **Name**: letters, digits, `-` and `_`; not one of BIND's built-in names (`any`, `none`, `localhost`, `localnets`)
- **Matches**: one per line: addresses, networks, other ACL names, `key NAME`; a `!` in front excludes. A list can't include itself, directly or through another list.

**Add and apply to nodes** and **Save and apply** apply the change to each node in turn, with the same checks and rollback as server settings. The list shows what uses each ACL; one that's in use can't be deleted.

ACLs and TSIG keys found in a server's configuration when it's [taken over](/help/existing-servers) become LiteBlox's, so every node gets them.
