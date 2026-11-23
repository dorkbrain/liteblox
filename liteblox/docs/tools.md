# Tools

The **Tools** menu in the top bar holds two small network calculators. Each opens in a new tab, so it can sit beside the page you're working on. Any logged-in account can use them, read-only ones too; they don't read or change anything in LiteBlox.

## Subnet Reference

A table of every IPv4 prefix from **/0** to **/32**:

| Column | Shows |
|---|---|
| **CIDR** | the prefix length |
| **Mask** | the same as a dotted netmask, such as `255.255.255.0` for a /24 |
| **Usable hosts** | the addresses a host can have: all of them less the network and broadcast addresses |
| **Next Net** | where the next network of the same size starts |

The common sizes (/8, /16 and /24) are highlighted.

### Next Net

Next Net is written over an address `a.b.c.d` on the network's boundary, adding to the octet that holds the prefix's last bit:

- a /24 steps the third octet by 1: `a.b.c+1.d`, so after `192.168.1.0/24` comes `192.168.2.0/24`;
- a /23 steps it by 2: `a.b.c+2.d`;
- a /26 steps the last octet by 64: `a.b.c.d+64`, so after `192.168.1.64/26` comes `192.168.1.128/26`;
- a /1 steps the first by 128: `a+128.b.c.d`.

A /0 is every address, so it has no next network (**n/a**).

### /31 and /32

A **/31** has two usable addresses, not zero: on a point-to-point link there's no need for network and broadcast addresses, so both are used (RFC 3021). A **/32** is a single host, such as a loopback or a route to one address.

## Subnet Calculator

A visual calculator for splitting a network into smaller ones.

- Enter a **network address** and its prefix length, then **Update**. An address that isn't on the network's boundary is moved down to it, with a note saying so.
- **Divide** splits a row into two halves. The coloured badges on the right show every prefix a row belongs to; click a badge to **join** that network's rows back into one.
- **Exclude subnets** takes networks separated by commas (such as `192.168.1.128/25, 192.168.1.192/26`). The calculator divides around them and shows them struck through in red; they can't be divided further.
- Click the **Range** header to switch between the full range and the usable addresses.
- **Bookmark or share this link** keeps the whole layout (network, divisions and exclusions) in the address, so opening it again shows the same table.
- **Reset** joins everything back into the one network, after asking. Changing the prefix length of the base network asks first too, since it starts over.
- **Copy Table** copies the table as plain text, with the supernet and the excluded networks at the end. Browsers only let a page write to the clipboard over HTTPS (or on `localhost`); over plain HTTP LiteBlox tries the older way, and if the browser refuses that too it shows the text in a box, selected, for you to copy.

### Credit

The Subnet Calculator is an altered version of [David C A Croft's Visual Subnet Calculator](https://github.com/davidc/subnets), Copyright (c) 2002, 2011, 2018, 2019 David C A Croft, modified for LiteBlox. It isn't the original software. Its license ships beside it as [subnetcalc-LICENSE.txt](/static/subnetcalc-LICENSE.txt).
