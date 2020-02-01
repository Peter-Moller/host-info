# EXPLANATIONS

Hi!

This text aims at trying to explain a few things that might not known to all interested users of host-info.
It is by no means an exhaustive explanation but merely an “appetiser” of sorts, aiming to direct interest rather than deep explanation.


## Geo Location:
This is an increasingly interesting topic. There are serious financial interests in knowing where potential customers are located; the Ad serving people want nothing more than to know *exactly* where you are. And those guys are closely followed (or?) by various national security organisations with the same goal. 
There is a number of web sites that can geolocate an IP address. Both Apples macOS and Microsoft Windows have API:s for that purpose.

So can one trust the information? Almost: I have only once seen a country that wasn't correct. The city and region might be so-so. But from most legal aspects (GDPR for instance) country is good enough. The case that I found where the country wasn't correct, was a series of routers (traffic deciding “junction” point on the way from client to server) where a few of them appeared to be located in USA. This was *bad* since the server was to be GDPR-compliant and if the traffic passed USA on it's way to the Service, it wouldn't be.

One needs to keep in mind that the geolocation for non-mobile IP-addresses is entered by the corporation that “owns” the IP-address. Some of them are somewhat lazy, and routers are way down on the list of things to be correct…


## CDN – Content Delivery Network:
A content delivery network (CDN) is a service that securely delivers data, videos and applications to customers globally with low latency and high transfer speeds. 
Some CDNs also offer DDoS mitigation, that is: they can “absorb” a network attack and make their customers web servers accessible even when under attack.

You can read more about CDN here: 
https://en.wikipedia.org/wiki/Content_delivery_network


## Ping times:
Ping is a computer network utility used to test the reachability of hosts on Internet. It measures the round-trip time from the originating host to a destination computer and back to the source. Not all hosts answers to this kind of traffic, though. A non-answer might thus be perfectly “ok”.
The name comes from submarine warfare.

A *very* rough division in times is:

| Ping time | Distance |
|-----------|----------|
|   ≈ 1 ms  | Local network or really close   |
|  < 10 ms  | Pretty close, i.e. same country |
| < 100 ms  | Same continent                  |
| > 300 ms  | Other side of the planet        |

High ping times is, combined with server load, the reason CDN:s exist at all. If you access a web server on another continent and not only that site, but all included CSS-files, ads and so on takes between 100 och 300 ms, those times, that in themselves are pretty short, will add to unbearable waiting times. So you might *think* you access a web site in another country, or another continent, but in reality you are really talking to a CDN that may be located in your own country or even region. So when I sit in Sweden and read www.macworld.com, that is located in San Fransisco in California, USA, I am *really* accessing a CDN-POP (Point Of Presence) in Stockholm (Sweden) operated by the CDN “Fastly”. Pretty neat, but can also make it hard to judge where things really are…

If you are interested and somewhat technically inclined, I highly recommend the software [mtr](https://github.com/traviscross/mtr)! Tip for when you run it: press “d” twice!



Stay curious!
/Peter Möller